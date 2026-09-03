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
	"strings"
	"sync"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const defaultMaxUpdateBytes = 64 << 20

type Config struct {
	LeaseTTL       time.Duration
	MaxUpdateBytes int
	InitialModel   *flv1.GlobalModel
}

type Service struct {
	flv1.UnimplementedCoordinatorServiceServer

	registry       *ztsecurity.RegistrationStore
	leaseTTL       time.Duration
	maxUpdateBytes int

	modelMu sync.RWMutex
	model   *flv1.GlobalModel
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
	if cfg.InitialModel == nil {
		cfg.InitialModel = &flv1.GlobalModel{
			ModelVersion:  "bootstrap",
			RoundId:       0,
			WeightsFormat: "application/x-zerotrust-tensors-v1",
			CreatedAtUnix: time.Now().UTC().Unix(),
		}
	}

	return &Service{
		registry:       registry,
		leaseTTL:       cfg.LeaseTTL,
		maxUpdateBytes: cfg.MaxUpdateBytes,
		model:          proto.Clone(cfg.InitialModel).(*flv1.GlobalModel),
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
		Accepted:         true,
		RegistrationId:   entry.RegistrationID,
		AssignedRole:     entry.Role,
		LeaseExpiresUnix: entry.ExpiresAt.Unix(),
	}, nil
}

func (s *Service) Heartbeat(ctx context.Context, req *flv1.HeartbeatRequest) (*flv1.HeartbeatResponse, error) {
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
		Accepted:            true,
		ServerTimeUnix:      time.Now().UTC().Unix(),
		CurrentModelVersion: model.GetModelVersion(),
		LeaseExpiresUnix:    entry.ExpiresAt.Unix(),
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
	if _, err := requireIdentityAndRegistration(ctx, s.registry, req.GetNodeId(), req.GetRegistrationId()); err != nil {
		return nil, err
	}
	if len(req.GetWeightsPayload()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "weights payload is required")
	}
	if len(req.GetWeightsPayload()) > s.maxUpdateBytes {
		return nil, status.Errorf(codes.ResourceExhausted, "weights payload exceeds %d bytes", s.maxUpdateBytes)
	}
	if strings.TrimSpace(req.GetWeightsFormat()) == "" || len(req.GetWeightsFormat()) > 128 {
		return nil, status.Error(codes.InvalidArgument, "weights_format is required and must be at most 128 characters")
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

	model := s.currentModel()
	if req.GetBaseModelVersion() != model.GetModelVersion() {
		return nil, status.Errorf(codes.FailedPrecondition, "base model version %q is stale; current version is %q", req.GetBaseModelVersion(), model.GetModelVersion())
	}
	if req.GetRoundId() != model.GetRoundId() {
		return nil, status.Errorf(codes.FailedPrecondition, "update round %d does not match current round %d", req.GetRoundId(), model.GetRoundId())
	}

	updateID, err := secureIdentifier(24)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not create update identifier")
	}
	return &flv1.SubmitLocalUpdateResponse{
		Accepted:            true,
		UpdateId:            updateID,
		Reason:              "accepted for aggregation",
		CurrentModelVersion: model.GetModelVersion(),
	}, nil
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
	if metrics.GetSampleCount() == 0 {
		return errors.New("sample_count must be greater than zero")
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

func secureIdentifier(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate secure identifier: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
