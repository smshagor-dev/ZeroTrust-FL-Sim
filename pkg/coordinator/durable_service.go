package coordinator

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/protobuf/proto"
)

type DurableService struct {
	flv1.UnimplementedCoordinatorServiceServer

	service *Service
	store   StateStore

	persistenceMu sync.Mutex
}

func NewDurableService(registry *ztsecurity.RegistrationStore, cfg Config, store StateStore) (*DurableService, error) {
	if store == nil {
		return nil, errors.New("durable state store is required")
	}
	service, err := NewService(registry, cfg)
	if err != nil {
		return nil, err
	}
	durable := &DurableService{service: service, store: store}
	if err := durable.recoverOrInitialize(context.Background()); err != nil {
		return nil, err
	}
	return durable, nil
}

func (s *DurableService) RegisterNode(ctx context.Context, req *flv1.RegisterNodeRequest) (*flv1.RegisterNodeResponse, error) {
	s.persistenceMu.Lock()
	defer s.persistenceMu.Unlock()

	before := s.captureSnapshot()
	response, err := s.service.RegisterNode(ctx, req)
	if err != nil {
		return nil, err
	}
	after := s.captureSnapshot()
	events := []AuditEvent{registrationAuditEvent(req, response, after)}
	if err := s.commitOrRollbackTransition(ctx, before, after, "registration", events); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *DurableService) Heartbeat(ctx context.Context, req *flv1.HeartbeatRequest) (*flv1.HeartbeatResponse, error) {
	s.persistenceMu.Lock()
	defer s.persistenceMu.Unlock()

	before := s.captureSnapshot()
	response, err := s.service.Heartbeat(ctx, req)
	if err != nil {
		return nil, err
	}
	after := s.captureSnapshot()
	events := []AuditEvent{heartbeatAuditEvent(req, response, after)}
	if err := s.commitOrRollbackTransition(ctx, before, after, "lease", events); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *DurableService) GetGlobalModel(ctx context.Context, req *flv1.GetGlobalModelRequest) (*flv1.GlobalModel, error) {
	s.persistenceMu.Lock()
	defer s.persistenceMu.Unlock()
	return s.service.GetGlobalModel(ctx, req)
}

func (s *DurableService) SubmitLocalUpdate(ctx context.Context, req *flv1.SubmitLocalUpdateRequest) (*flv1.SubmitLocalUpdateResponse, error) {
	s.persistenceMu.Lock()
	defer s.persistenceMu.Unlock()

	before := s.captureSnapshot()
	response, err := s.service.SubmitLocalUpdate(ctx, req)
	if err != nil {
		return nil, err
	}
	after := s.captureSnapshot()
	events := s.updateAuditEvents(req, response, before, after)
	if err := s.commitOrRollbackTransition(ctx, before, after, "model-state", events); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *DurableService) commitOrRollback(ctx context.Context, before StateSnapshot, operation string) error {
	return s.commitOrRollbackTransition(ctx, before, s.captureSnapshot(), operation, nil)
}

func (s *DurableService) recoverOrInitialize(ctx context.Context) error {
	snapshot, err := s.store.Load(ctx)
	if errors.Is(err, ErrStateNotFound) {
		current := s.captureSnapshot()
		events := []AuditEvent{stateAuditEvent(AuditEventStateInitialized, current)}
		if err := s.commitCurrentStateWithAudit(ctx, events); err != nil {
			return fmt.Errorf("initialize durable coordinator state: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("load durable coordinator state: %w", err)
	}
	if err := s.restoreSnapshot(snapshot); err != nil {
		return fmt.Errorf("restore durable coordinator state: %w", err)
	}
	recovered := s.captureSnapshot()
	events := []AuditEvent{stateAuditEvent(AuditEventStateRecovered, recovered)}
	if err := s.commitCurrentStateWithAudit(ctx, events); err != nil {
		return fmt.Errorf("normalize recovered coordinator state: %w", err)
	}
	return nil
}

func (s *DurableService) commitCurrentState(ctx context.Context) error {
	return s.store.Commit(ctx, s.captureSnapshot())
}

func (s *DurableService) currentPolicy() StatePolicy {
	return StatePolicy{
		LeaseTTL:            s.service.leaseTTL,
		MaxUpdateBytes:      s.service.maxUpdateBytes,
		MinUpdates:          s.service.minUpdates,
		MaxUpdatesPerMinute: s.service.maxUpdatesPerMinute,
		AggregationMethod:   s.service.aggregationMethod,
	}
}

func (s *DurableService) captureSnapshot() StateSnapshot {
	s.service.roundMu.Lock()
	defer s.service.roundMu.Unlock()

	pending := make([]PersistedUpdate, 0, len(s.service.pending))
	for _, update := range s.service.pending {
		pending = append(pending, PersistedUpdate{
			NodeID:      update.NodeID,
			UpdateID:    update.UpdateID,
			Values:      append([]float32(nil), update.Values...),
			SampleCount: update.SampleCount,
		})
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].NodeID < pending[j].NodeID })

	now := time.Now().UTC()
	replayCutoff := now.Add(-requestReplayWindow)
	nonces := make([]PersistedNonce, 0, len(s.service.nonces))
	for key, seenAt := range s.service.nonces {
		if seenAt.Before(replayCutoff) {
			continue
		}
		nonces = append(nonces, PersistedNonce{Key: key, SeenAt: seenAt})
	}
	sort.Slice(nonces, func(i, j int) bool { return nonces[i].Key < nonces[j].Key })

	rateWindows := make([]PersistedRateWindow, 0, len(s.service.rates))
	for nodeID, window := range s.service.rates {
		if window.StartedAt.IsZero() || now.Sub(window.StartedAt) >= time.Minute {
			continue
		}
		rateWindows = append(rateWindows, PersistedRateWindow{
			NodeID:    nodeID,
			StartedAt: window.StartedAt,
			Count:     window.Count,
		})
	}
	sort.Slice(rateWindows, func(i, j int) bool { return rateWindows[i].NodeID < rateWindows[j].NodeID })

	return StateSnapshot{
		Policy:        s.currentPolicy(),
		Model:         s.service.currentModel(),
		Pending:       pending,
		Registrations: s.service.registry.Snapshot(),
		Nonces:        nonces,
		RateWindows:   rateWindows,
	}
}

func (s *DurableService) restoreSnapshot(snapshot StateSnapshot) error {
	if err := validateStateSnapshot(snapshot); err != nil {
		return err
	}
	if snapshot.Policy != s.currentPolicy() {
		return fmt.Errorf("durable coordinator policy does not match current runtime configuration")
	}

	pending := make(map[string]pendingUpdate, len(snapshot.Pending))
	for _, update := range snapshot.Pending {
		pending[update.NodeID] = pendingUpdate{
			NodeID:      update.NodeID,
			UpdateID:    update.UpdateID,
			Values:      append([]float32(nil), update.Values...),
			SampleCount: update.SampleCount,
		}
	}

	now := time.Now().UTC()
	replayCutoff := now.Add(-requestReplayWindow)
	nonces := make(map[string]time.Time, len(snapshot.Nonces))
	for _, nonce := range snapshot.Nonces {
		if nonce.SeenAt.Before(replayCutoff) {
			continue
		}
		nonces[nonce.Key] = nonce.SeenAt
	}
	rates := make(map[string]updateRateWindow, len(snapshot.RateWindows))
	for _, window := range snapshot.RateWindows {
		if now.Sub(window.StartedAt) >= time.Minute {
			continue
		}
		rates[window.NodeID] = updateRateWindow{StartedAt: window.StartedAt, Count: window.Count}
	}

	s.service.roundMu.Lock()
	defer s.service.roundMu.Unlock()

	if err := s.service.registry.RestoreSnapshot(snapshot.Registrations); err != nil {
		return fmt.Errorf("restore registration snapshot: %w", err)
	}
	s.service.modelMu.Lock()
	s.service.model = proto.Clone(snapshot.Model).(*flv1.GlobalModel)
	s.service.modelMu.Unlock()
	s.service.pending = pending
	s.service.nonces = nonces
	s.service.rates = rates
	return nil
}
