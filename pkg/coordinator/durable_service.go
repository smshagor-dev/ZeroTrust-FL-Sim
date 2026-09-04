package coordinator

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	if err := s.commitCurrentState(ctx); err != nil {
		if restoreErr := s.restoreSnapshot(before); restoreErr != nil {
			return nil, status.Errorf(codes.Internal, "durable registration commit failed and rollback failed: %v", restoreErr)
		}
		return nil, status.Error(codes.Internal, "durable registration commit failed")
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
	if err := s.commitCurrentState(ctx); err != nil {
		if restoreErr := s.restoreSnapshot(before); restoreErr != nil {
			return nil, status.Errorf(codes.Internal, "durable lease commit failed and rollback failed: %v", restoreErr)
		}
		return nil, status.Error(codes.Internal, "durable lease commit failed")
	}
	return response, nil
}

func (s *DurableService) GetGlobalModel(ctx context.Context, req *flv1.GetGlobalModelRequest) (*flv1.GlobalModel, error) {
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
	if err := s.commitCurrentState(ctx); err != nil {
		if restoreErr := s.restoreSnapshot(before); restoreErr != nil {
			return nil, status.Errorf(codes.Internal, "durable model-state commit failed and rollback failed: %v", restoreErr)
		}
		return nil, status.Error(codes.Internal, "durable model-state commit failed")
	}
	return response, nil
}

func (s *DurableService) recoverOrInitialize(ctx context.Context) error {
	snapshot, err := s.store.Load(ctx)
	if errors.Is(err, ErrStateNotFound) {
		if err := s.commitCurrentState(ctx); err != nil {
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
	if err := s.commitCurrentState(ctx); err != nil {
		return fmt.Errorf("normalize recovered coordinator state: %w", err)
	}
	return nil
}

func (s *DurableService) commitCurrentState(ctx context.Context) error {
	return s.store.Commit(ctx, s.captureSnapshot())
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

	return StateSnapshot{
		Model:         s.service.currentModel(),
		Pending:       pending,
		Registrations: s.service.registry.Snapshot(),
	}
}

func (s *DurableService) restoreSnapshot(snapshot StateSnapshot) error {
	if err := validateStateSnapshot(snapshot); err != nil {
		return err
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

	s.service.roundMu.Lock()
	defer s.service.roundMu.Unlock()

	if err := s.service.registry.RestoreSnapshot(snapshot.Registrations); err != nil {
		return fmt.Errorf("restore registration snapshot: %w", err)
	}
	s.service.modelMu.Lock()
	s.service.model = proto.Clone(snapshot.Model).(*flv1.GlobalModel)
	s.service.modelMu.Unlock()
	s.service.pending = pending
	return nil
}
