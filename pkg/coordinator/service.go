package coordinator

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	defaultMaxUpdateBytes      = 8 << 20
	defaultMaxUpdatesPerMinute = 60
	maxReportedSampleCount     = 10_000_000
	networkWeightsFormat       = "application/x-npy-f32"
	defaultAggregationMethod   = "median"
	requestReplayWindow        = 2 * time.Minute
	minimumNonceBytes          = 16
)

type Config struct {
	LeaseTTL            time.Duration
	MaxUpdateBytes      int
	InitialModel        *flv1.GlobalModel
	MinUpdates          int
	MaxUpdatesPerMinute int
	AggregationMethod   string
}

type pendingUpdate struct {
	NodeID      string
	UpdateID    string
	Values      []float32
	SampleCount uint64
}

type updateRateWindow struct {
	StartedAt time.Time
	Count     int
}

type Service struct {
	flv1.UnimplementedCoordinatorServiceServer

	registry            *ztsecurity.RegistrationStore
	leaseTTL            time.Duration
	maxUpdateBytes      int
	minUpdates          int
	maxUpdatesPerMinute int
	aggregationMethod   string

	modelMu sync.RWMutex
	model   *flv1.GlobalModel

	roundMu sync.Mutex
	pending map[string]pendingUpdate
	rates   map[string]updateRateWindow
	nonces  map[string]time.Time
}

func NewService(registry *ztsecurity.RegistrationStore, cfg Config) (*Service, error) {
	if registry == nil {
		return nil, errors.New("registration store is required")
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = 5 * time.Minute
	}
	if cfg.MaxUpdateBytes <= 0 {
		cfg.MaxUpdateBytes = defaultMaxUpdateBytes
	}
	if cfg.MinUpdates <= 0 {
		cfg.MinUpdates = 1
	}
	if cfg.MaxUpdatesPerMinute <= 0 {
		cfg.MaxUpdatesPerMinute = defaultMaxUpdatesPerMinute
	}
	aggregationMethod, err := normalizeAggregationMethod(cfg.AggregationMethod)
	if err != nil {
		return nil, err
	}
	if cfg.InitialModel == nil {
		cfg.InitialModel = &flv1.GlobalModel{
			ModelVersion:  "bootstrap",
			RoundId:       0,
			WeightsFormat: networkWeightsFormat,
			CreatedAtUnix: time.Now().UTC().Unix(),
		}
	}
	if payload := cfg.InitialModel.GetWeightsPayload(); len(payload) > 0 {
		if cfg.InitialModel.GetWeightsFormat() != networkWeightsFormat {
			return nil, fmt.Errorf("initial model weights_format must be %q", networkWeightsFormat)
		}
		if _, err := decodeNPYFloat32(payload); err != nil {
			return nil, fmt.Errorf("validate initial model payload: %w", err)
		}
		digest := sha256.Sum256(payload)
		if len(cfg.InitialModel.GetSha256()) > 0 && !bytes.Equal(digest[:], cfg.InitialModel.GetSha256()) {
			return nil, errors.New("initial model SHA-256 digest does not match payload")
		}
		cfg.InitialModel.Sha256 = digest[:]
	}

	return &Service{
		registry:            registry,
		leaseTTL:            cfg.LeaseTTL,
		maxUpdateBytes:      cfg.MaxUpdateBytes,
		minUpdates:          cfg.MinUpdates,
		maxUpdatesPerMinute: cfg.MaxUpdatesPerMinute,
		aggregationMethod:   aggregationMethod,
		model:               proto.Clone(cfg.InitialModel).(*flv1.GlobalModel),
		pending:             make(map[string]pendingUpdate),
		rates:               make(map[string]updateRateWindow),
		nonces:              make(map[string]time.Time),
	}, nil
}

func (s *Service) RegisterNode(ctx context.Context, req *flv1.RegisterNodeRequest) (*flv1.RegisterNodeResponse, error) {
	identity, ok := ztsecurity.AuthorizedPeerIdentity(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "authorized peer identity is missing from context")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "registration request is required")
	}
	if strings.TrimSpace(req.GetNodeId()) == "" || req.GetNodeId() != identity.NodeID {
		return nil, status.Error(codes.InvalidArgument, "node_id must match the authenticated certificate identity")
	}
	if req.GetCertificateCommonName() != identity.CommonName {
		return nil, status.Error(codes.InvalidArgument, "certificate_common_name must match the authenticated certificate")
	}
	if req.GetHardware() == nil {
		return nil, status.Error(codes.InvalidArgument, "hardware profile is required")
	}

	registrationID, err := secureIdentifier(24)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not create registration")
	}
	entry, err := s.registry.Register(identity, registrationID, s.leaseTTL)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not persist registration")
	}

	return &flv1.RegisterNodeResponse{
		Accepted:             true,
		RegistrationId:       entry.RegistrationID,
		AssignedRole:         entry.Role,
		LeaseExpiresUnix:     entry.ExpiresAt.Unix(),
		CredentialGeneration: entry.Generation,
	}, nil
}

func (s *Service) Heartbeat(ctx context.Context, req *flv1.HeartbeatRequest) (*flv1.HeartbeatResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "heartbeat request is required")
	}
	identity, err := requireIdentityAndRegistration(ctx, s.registry, req.GetNodeId(), req.GetRegistrationId())
	if err != nil {
		return nil, err
	}
	entry, err := s.registry.Refresh(identity, req.GetRegistrationId(), s.leaseTTL)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "registration is invalid or expired")
	}

	model := s.currentModel()
	return &flv1.HeartbeatResponse{
		Accepted:             true,
		ServerTimeUnix:       time.Now().UTC().Unix(),
		CurrentModelVersion:  model.GetModelVersion(),
		LeaseExpiresUnix:     entry.ExpiresAt.Unix(),
		CredentialGeneration: entry.Generation,
	}, nil
}

func (s *Service) GetGlobalModel(ctx context.Context, req *flv1.GetGlobalModelRequest) (*flv1.GlobalModel, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "global model request is required")
	}
	if _, err := requireIdentityAndRegistration(ctx, s.registry, req.GetNodeId(), req.GetRegistrationId()); err != nil {
		return nil, err
	}
	return s.currentModel(), nil
}

func (s *Service) SubmitLocalUpdate(ctx context.Context, req *flv1.SubmitLocalUpdateRequest) (*flv1.SubmitLocalUpdateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "local update request is required")
	}
	identity, err := requireIdentityAndRegistration(ctx, s.registry, req.GetNodeId(), req.GetRegistrationId())
	if err != nil {
		return nil, err
	}
	if len(req.GetWeightsPayload()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "weights payload is required")
	}
	if len(req.GetWeightsPayload()) > s.maxUpdateBytes {
		return nil, status.Errorf(codes.ResourceExhausted, "weights payload exceeds %d bytes", s.maxUpdateBytes)
	}
	if req.GetWeightsFormat() != networkWeightsFormat {
		return nil, status.Errorf(codes.InvalidArgument, "weights_format must be %q", networkWeightsFormat)
	}
	if len(req.GetUpdateSha256()) != sha256.Size {
		return nil, status.Error(codes.InvalidArgument, "update_sha256 must contain a 32-byte SHA-256 digest")
	}
	actualDigest := sha256.Sum256(req.GetWeightsPayload())
	if !bytes.Equal(actualDigest[:], req.GetUpdateSha256()) {
		return nil, status.Error(codes.InvalidArgument, "weights payload SHA-256 digest does not match update_sha256")
	}
	if err := validateMetrics(req.GetMetrics()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	values, err := decodeNPYFloat32(req.GetWeightsPayload())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid model update payload: %v", err)
	}

	now := time.Now().UTC()
	if err := validateSecurityMetadata(req.GetSecurity(), now); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	s.roundMu.Lock()
	defer s.roundMu.Unlock()

	if _, err := s.registry.Validate(identity, req.GetRegistrationId()); err != nil {
		return nil, status.Error(codes.PermissionDenied, "registration was revoked, rotated, or expired before update commit")
	}
	if !s.acceptNonceLocked(req.GetNodeId(), req.GetSecurity().GetNonce(), now) {
		return nil, status.Error(codes.AlreadyExists, "request nonce was already used")
	}
	if !s.allowUpdateLocked(req.GetNodeId(), now) {
		return nil, status.Error(codes.ResourceExhausted, "worker update rate limit exceeded")
	}

	model := s.currentModel()
	if req.GetBaseModelVersion() != model.GetModelVersion() {
		return nil, status.Errorf(codes.FailedPrecondition, "base model version %q is stale; current version is %q", req.GetBaseModelVersion(), model.GetModelVersion())
	}
	if req.GetRoundId() != model.GetRoundId() {
		return nil, status.Errorf(codes.FailedPrecondition, "update round %d does not match current round %d", req.GetRoundId(), model.GetRoundId())
	}
	if _, exists := s.pending[req.GetNodeId()]; exists {
		return nil, status.Error(codes.AlreadyExists, "worker already submitted an update for the current round")
	}

	currentValues, err := currentModelVector(model, len(values))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	updateID, err := secureIdentifier(24)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not create update identifier")
	}
	s.pending[req.GetNodeId()] = pendingUpdate{
		NodeID:      req.GetNodeId(),
		UpdateID:    updateID,
		Values:      append([]float32(nil), values...),
		SampleCount: req.GetMetrics().GetSampleCount(),
	}

	if len(s.pending) < s.minUpdates {
		return &flv1.SubmitLocalUpdateResponse{
			Accepted:            true,
			UpdateId:            updateID,
			Reason:              fmt.Sprintf("accepted; waiting for quorum (%d/%d)", len(s.pending), s.minUpdates),
			CurrentModelVersion: model.GetModelVersion(),
		}, nil
	}

	aggregated, err := aggregatePendingUpdates(s.pending, len(currentValues), s.aggregationMethod)
	if err != nil {
		delete(s.pending, req.GetNodeId())
		return nil, status.Error(codes.Internal, err.Error())
	}
	for index := range currentValues {
		currentValues[index] += aggregated[index]
		if math.IsNaN(float64(currentValues[index])) || math.IsInf(float64(currentValues[index]), 0) {
			delete(s.pending, req.GetNodeId())
			return nil, status.Error(codes.InvalidArgument, "aggregated model contains non-finite values")
		}
	}

	payload, err := encodeNPYFloat32(currentValues)
	if err != nil {
		delete(s.pending, req.GetNodeId())
		return nil, status.Error(codes.Internal, "could not encode aggregated global model")
	}
	modelDigest := sha256.Sum256(payload)
	nextRound := model.GetRoundId() + 1
	nextVersion := fmt.Sprintf("round-%d-%s", nextRound, hex.EncodeToString(modelDigest[:8]))
	nextModel := &flv1.GlobalModel{
		ModelVersion:   nextVersion,
		RoundId:        nextRound,
		WeightsPayload: payload,
		WeightsFormat:  networkWeightsFormat,
		Sha256:         modelDigest[:],
		CreatedAtUnix:  now.Unix(),
	}

	s.modelMu.Lock()
	s.model = nextModel
	s.modelMu.Unlock()
	clear(s.pending)

	return &flv1.SubmitLocalUpdateResponse{
		Accepted:            true,
		UpdateId:            updateID,
		Reason:              "accepted; round aggregated",
		CurrentModelVersion: nextVersion,
	}, nil
}

func (s *Service) allowUpdateLocked(nodeID string, now time.Time) bool {
	window := s.rates[nodeID]
	if window.StartedAt.IsZero() || now.Sub(window.StartedAt) >= time.Minute {
		s.rates[nodeID] = updateRateWindow{StartedAt: now, Count: 1}
		return true
	}
	if window.Count >= s.maxUpdatesPerMinute {
		return false
	}
	window.Count++
	s.rates[nodeID] = window
	return true
}

func (s *Service) acceptNonceLocked(nodeID string, nonce []byte, now time.Time) bool {
	cutoff := now.Add(-requestReplayWindow)
	for key, seenAt := range s.nonces {
		if seenAt.Before(cutoff) {
			delete(s.nonces, key)
		}
	}
	key := nodeID + ":" + hex.EncodeToString(nonce)
	if _, exists := s.nonces[key]; exists {
		return false
	}
	s.nonces[key] = now
	return true
}

func currentModelVector(model *flv1.GlobalModel, expectedLength int) ([]float32, error) {
	if expectedLength <= 0 {
		return nil, errors.New("model update vector must not be empty")
	}
	if len(model.GetWeightsPayload()) == 0 {
		return make([]float32, expectedLength), nil
	}
	if model.GetWeightsFormat() != networkWeightsFormat {
		return nil, fmt.Errorf("current model uses unsupported weights format %q", model.GetWeightsFormat())
	}
	values, err := decodeNPYFloat32(model.GetWeightsPayload())
	if err != nil {
		return nil, fmt.Errorf("decode current global model: %w", err)
	}
	if len(values) != expectedLength {
		return nil, fmt.Errorf("update vector length %d does not match global model length %d", expectedLength, len(values))
	}
	return values, nil
}

func normalizeAggregationMethod(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		normalized = defaultAggregationMethod
	}
	switch normalized {
	case "median", "weighted_mean":
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported aggregation method %q; expected median or weighted_mean", value)
	}
}

func aggregatePendingUpdates(updates map[string]pendingUpdate, vectorLength int, method string) ([]float32, error) {
	normalized, err := normalizeAggregationMethod(method)
	if err != nil {
		return nil, err
	}
	switch normalized {
	case "median":
		return aggregateMedianUpdates(updates, vectorLength)
	case "weighted_mean":
		return aggregateWeightedUpdates(updates, vectorLength)
	default:
		return nil, fmt.Errorf("unsupported aggregation method %q", normalized)
	}
}

func aggregateMedianUpdates(updates map[string]pendingUpdate, vectorLength int) ([]float32, error) {
	if len(updates) == 0 || vectorLength <= 0 {
		return nil, errors.New("cannot aggregate an empty update set")
	}
	columns := make([][]float64, vectorLength)
	for index := range columns {
		columns[index] = make([]float64, 0, len(updates))
	}
	for _, update := range updates {
		if len(update.Values) != vectorLength {
			return nil, errors.New("pending update vector lengths do not match")
		}
		for index, value := range update.Values {
			converted := float64(value)
			if math.IsNaN(converted) || math.IsInf(converted, 0) {
				return nil, errors.New("pending update contains non-finite values")
			}
			columns[index] = append(columns[index], converted)
		}
	}

	result := make([]float32, vectorLength)
	for index, values := range columns {
		sort.Float64s(values)
		middle := len(values) / 2
		var value float64
		if len(values)%2 == 1 {
			value = values[middle]
		} else {
			value = (values[middle-1] + values[middle]) / 2
		}
		result[index] = float32(value)
	}
	return result, nil
}

func aggregateWeightedUpdates(updates map[string]pendingUpdate, vectorLength int) ([]float32, error) {
	if len(updates) == 0 || vectorLength <= 0 {
		return nil, errors.New("cannot aggregate an empty update set")
	}
	sums := make([]float64, vectorLength)
	var totalWeight float64
	for _, update := range updates {
		if len(update.Values) != vectorLength {
			return nil, errors.New("pending update vector lengths do not match")
		}
		weight := float64(update.SampleCount)
		if weight <= 0 {
			return nil, errors.New("pending update has invalid sample count")
		}
		totalWeight += weight
		for index, value := range update.Values {
			sums[index] += float64(value) * weight
		}
	}
	if totalWeight <= 0 || math.IsInf(totalWeight, 0) || math.IsNaN(totalWeight) {
		return nil, errors.New("aggregate sample weight is invalid")
	}
	result := make([]float32, vectorLength)
	for index := range result {
		value := sums[index] / totalWeight
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, errors.New("aggregated update contains non-finite values")
		}
		result[index] = float32(value)
	}
	return result, nil
}

func (s *Service) currentModel() *flv1.GlobalModel {
	s.modelMu.RLock()
	defer s.modelMu.RUnlock()
	return proto.Clone(s.model).(*flv1.GlobalModel)
}

func requireIdentityAndRegistration(ctx context.Context, registry *ztsecurity.RegistrationStore, nodeID, registrationID string) (ztsecurity.PeerIdentity, error) {
	identity, ok := ztsecurity.AuthorizedPeerIdentity(ctx)
	if !ok {
		return ztsecurity.PeerIdentity{}, status.Error(codes.Internal, "authorized peer identity is missing from context")
	}
	if strings.TrimSpace(nodeID) == "" || nodeID != identity.NodeID {
		return ztsecurity.PeerIdentity{}, status.Error(codes.InvalidArgument, "node_id must match the authenticated certificate identity")
	}
	if strings.TrimSpace(registrationID) == "" {
		return ztsecurity.PeerIdentity{}, status.Error(codes.PermissionDenied, "registration_id is required")
	}
	if _, err := registry.Validate(identity, registrationID); err != nil {
		return ztsecurity.PeerIdentity{}, status.Error(codes.PermissionDenied, "registration is invalid or expired")
	}
	return identity, nil
}

func validateMetrics(metrics *flv1.LocalUpdateMetrics) error {
	if metrics == nil {
		return errors.New("update metrics are required")
	}
	if metrics.GetDynamicEpochs() == 0 {
		return errors.New("dynamic_epochs must be greater than zero")
	}
	if metrics.GetSampleCount() == 0 || metrics.GetSampleCount() > maxReportedSampleCount {
		return fmt.Errorf("sample_count must be between 1 and %d", maxReportedSampleCount)
	}
	if math.IsNaN(metrics.GetLoss()) || math.IsInf(metrics.GetLoss(), 0) {
		return errors.New("loss must be finite")
	}
	for _, norm := range metrics.GetGradientNorms() {
		if norm < 0 || math.IsNaN(norm) || math.IsInf(norm, 0) {
			return errors.New("gradient norms must be finite and non-negative")
		}
	}
	return nil
}

func validateSecurityMetadata(metadata *flv1.SecurityMetadata, now time.Time) error {
	if metadata == nil {
		return errors.New("security metadata is required")
	}
	if len(metadata.GetNonce()) < minimumNonceBytes {
		return fmt.Errorf("security nonce must contain at least %d bytes", minimumNonceBytes)
	}
	issuedAt := time.Unix(metadata.GetIssuedAtUnix(), 0).UTC()
	if issuedAt.IsZero() || issuedAt.Before(now.Add(-requestReplayWindow)) || issuedAt.After(now.Add(requestReplayWindow)) {
		return errors.New("security metadata timestamp is outside the accepted replay window")
	}
	return nil
}

func secureIdentifier(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate secure identifier: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
