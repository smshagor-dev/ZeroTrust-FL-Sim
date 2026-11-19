package coordinator

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// p1CommitFault deliberately reports a failure either before or after the
// underlying real file store has completed its durable Commit. This tests
// uncertain *error reporting*, not a physical crash or broken fsync.
type p1CommitFault uint8

const (
	p1FailBeforeWrite p1CommitFault = iota + 1
	p1FailAfterWrite
)

type p1FaultingFileStore struct {
	inner *FileStateStore
	mu    sync.Mutex
	plan  []p1CommitFault
}

func (s *p1FaultingFileStore) Load(ctx context.Context) (StateSnapshot, error) {
	return s.inner.Load(ctx)
}

func (s *p1FaultingFileStore) Commit(ctx context.Context, snapshot StateSnapshot) error {
	s.mu.Lock()
	var fault p1CommitFault
	if len(s.plan) > 0 {
		fault = s.plan[0]
		s.plan = s.plan[1:]
	}
	s.mu.Unlock()

	if fault == p1FailBeforeWrite {
		return errors.New("injected error before file state write")
	}
	if err := s.inner.Commit(ctx, snapshot); err != nil {
		return err
	}
	if fault == p1FailAfterWrite {
		return errors.New("injected lost completion signal after durable file write")
	}
	return nil
}

func (s *p1FaultingFileStore) failNext(faults ...p1CommitFault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.plan) != 0 {
		panic("previous fault plan was not consumed")
	}
	s.plan = append(s.plan, faults...)
}

func (s *p1FaultingFileStore) assertFaultPlanConsumed(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.plan) != 0 {
		t.Fatalf("fault plan has %d unconsumed Commit boundaries", len(s.plan))
	}
}

func p1FileStateHasActiveRegistration(snapshot StateSnapshot, nodeID string) bool {
	for _, entry := range snapshot.Registrations {
		if entry.NodeID == nodeID {
			return entry.RevokedAt.IsZero() && entry.ExpiresAt.After(time.Now())
		}
	}
	return false
}

func p1FileStateHasPending(snapshot StateSnapshot, nodeID string) bool {
	for _, update := range snapshot.Pending {
		if update.NodeID == nodeID {
			return true
		}
	}
	return false
}

// The trusted coordinator can observe an error after a durable revocation
// write. If rolling back the file succeeds, the failed RPC must not erase the
// authorized worker or its pending contribution. If rollback cannot be
// confirmed, the process must refuse every following RPC until recovery.
func TestIEEEFileBackedRevocationUncertainWriteAndRecovery(t *testing.T) {
	tests := []struct {
		name           string
		faults         []p1CommitFault
		wantFenced     bool
		wantDiskActive bool
	}{
		{
			name:           "post-write-error-rollback-confirmed",
			faults:         []p1CommitFault{p1FailAfterWrite},
			wantFenced:     false,
			wantDiskActive: true,
		},
		{
			name:           "post-write-error-rollback-rejected",
			faults:         []p1CommitFault{p1FailAfterWrite, p1FailBeforeWrite},
			wantFenced:     true,
			wantDiskActive: false,
		},
		{
			name:           "post-write-error-rollback-ambiguous",
			faults:         []p1CommitFault{p1FailAfterWrite, p1FailAfterWrite},
			wantFenced:     true,
			wantDiskActive: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := ztsecurity.NewRegistrationStore()
			auth, key := lifecycleAuthorizer(t, registry)
			admin, adminCtx := lifecycleAuthorizedPeer(t, key, "p1-fault-admin", "admin")
			worker, workerCtx := lifecycleAuthorizedPeer(t, key, "p1-fault-worker", "edge-worker")
			for _, identity := range []ztsecurity.PeerIdentity{admin, worker} {
				if _, err := registry.Register(identity, "registration-"+identity.NodeID, time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			file, err := NewFileStateStore(filepath.Join(t.TempDir(), "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			store := &p1FaultingFileStore{inner: file}
			durable, err := NewDurableService(registry, Config{MinUpdates: 2}, store)
			if err != nil {
				t.Fatalf("initialize file-backed coordinator: %v", err)
			}
			update := p1UpdateRequest(t, worker.NodeID, "registration-"+worker.NodeID, "p1-fault-pending-nonce-001", 99)
			accepted, err := invokeLifecycleRPC(auth, workerCtx, ztsecurity.MethodSubmitLocalUpdate, update,
				func(ctx context.Context, input any) (any, error) {
					return durable.SubmitLocalUpdate(ctx, input.(*flv1.SubmitLocalUpdateRequest))
				})
			if err != nil || !accepted.(*flv1.SubmitLocalUpdateResponse).GetAccepted() {
				t.Fatalf("persist an acknowledged pending update: response=%v error=%v", accepted, err)
			}
			before, err := file.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !p1FileStateHasPending(before, worker.NodeID) {
				t.Fatal("test precondition: pending update was not persisted")
			}

			store.failNext(tt.faults...)
			revoke := &flv1.RevokeRegistrationRequest{
				NodeId: admin.NodeID, RegistrationId: "registration-" + admin.NodeID,
				TargetNodeId: worker.NodeID, Reason: "fault injection after model admission",
				Security: lifecycleSecurityMetadata([]byte("p1-fault-revocation-0001")),
			}
			response, err := invokeLifecycleRPC(auth, adminCtx, ztsecurity.MethodRevokeRegistration, revoke,
				func(ctx context.Context, input any) (any, error) {
					return durable.RevokeRegistration(ctx, input.(*flv1.RevokeRegistrationRequest))
				})
			if status.Code(err) != codes.Internal || (response != nil && response.(*flv1.RevokeRegistrationResponse) != nil) {
				t.Fatalf("uncertain revocation must not be acknowledged: response=%v error=%v", response, err)
			}
			store.assertFaultPlanConsumed(t)
			if durable.fenced != tt.wantFenced {
				t.Fatalf("fence=%t, want %t", durable.fenced, tt.wantFenced)
			}
			persisted, err := file.Load(context.Background())
			if err != nil {
				t.Fatalf("independent file observer cannot read persisted state: %v", err)
			}
			if got := p1FileStateHasActiveRegistration(persisted, worker.NodeID); got != tt.wantDiskActive {
				t.Fatalf("independent disk observer: active registration=%t, want %t", got, tt.wantDiskActive)
			}
			if got := p1FileStateHasPending(persisted, worker.NodeID); got != tt.wantDiskActive {
				t.Fatalf("independent disk observer: pending update=%t, want %t", got, tt.wantDiskActive)
			}
			if persisted.Model.GetRoundId() != 0 {
				t.Fatalf("ambiguous revocation unexpectedly advanced model round=%d", persisted.Model.GetRoundId())
			}

			readReq := &flv1.GetGlobalModelRequest{
				NodeId: worker.NodeID, RegistrationId: "registration-" + worker.NodeID,
			}
			readResponse, readErr := invokeLifecycleRPC(auth, workerCtx, ztsecurity.MethodGetGlobalModel,
				readReq, func(ctx context.Context, input any) (any, error) {
					return durable.GetGlobalModel(ctx, input.(*flv1.GetGlobalModelRequest))
				})
			if tt.wantFenced {
				if status.Code(readErr) != codes.Unavailable {
					t.Fatalf("fenced coordinator read returned %v, want Unavailable", readErr)
				}
			} else {
				if readErr != nil {
					t.Fatalf("legitimate model read after confirmed rollback failed: %v", readErr)
				}
				if readResponse.(*flv1.GlobalModel).GetRoundId() != 0 {
					t.Fatal("confirmed rollback exposed an unexpected committed model round")
				}
			}
			restartedRegistry := ztsecurity.NewRegistrationStore()
			restarted, err := NewDurableService(restartedRegistry, Config{MinUpdates: 2}, file)
			if err != nil {
				t.Fatalf("independent file-state recovery: %v", err)
			}
			if got := restartedRegistry.IsRegistered(worker); got != tt.wantDiskActive {
				t.Fatalf("recovered worker active=%t, want %t", got, tt.wantDiskActive)
			}
			if got := len(restarted.captureSnapshot().Pending) == 1; got != tt.wantDiskActive {
				t.Fatalf("recovered pending count=1: %t, want %t", got, tt.wantDiskActive)
			}
		})
	}
}

// A model update may be persisted even though the client never receives
// success. A failed rollback must fence the original process. The recovered
// nonce and model version must then prevent that request from applying twice.
func TestIEEEFileBackedAmbiguousModelUpdateAckRejectsReplayAfterRestart(t *testing.T) {
	registry := ztsecurity.NewRegistrationStore()
	auth, key := lifecycleAuthorizer(t, registry)
	worker, workerCtx := lifecycleAuthorizedPeer(t, key, "p1-ambiguous-worker", "edge-worker")
	const registration = "p1-ambiguous-registration"
	if _, err := registry.Register(worker, registration, time.Hour); err != nil {
		t.Fatal(err)
	}
	file, err := NewFileStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	store := &p1FaultingFileStore{inner: file}
	durable, err := NewDurableService(registry, Config{MinUpdates: 1}, store)
	if err != nil {
		t.Fatal(err)
	}
	req := p1UpdateRequest(t, worker.NodeID, registration, "p1-ambiguous-update-nonce-001", 7)
	store.failNext(p1FailAfterWrite, p1FailBeforeWrite)
	response, err := invokeLifecycleRPC(auth, workerCtx, ztsecurity.MethodSubmitLocalUpdate, req,
		func(ctx context.Context, input any) (any, error) {
			return durable.SubmitLocalUpdate(ctx, input.(*flv1.SubmitLocalUpdateRequest))
		})
	if status.Code(err) != codes.Internal || (response != nil && response.(*flv1.SubmitLocalUpdateResponse) != nil) {
		t.Fatalf("ambiguous model update was acknowledged: response=%v error=%v", response, err)
	}
	store.assertFaultPlanConsumed(t)
	if !durable.fenced {
		t.Fatal("ambiguous persistent rollback did not fence the serving coordinator")
	}
	if _, err := durable.SubmitLocalUpdate(context.Background(), req); status.Code(err) != codes.Unavailable {
		t.Fatalf("fenced service accepted another model update: %v", err)
	}

	observed, err := file.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if observed.Model.GetRoundId() != 1 || len(observed.Nonces) != 1 {
		t.Fatalf("independent disk observer: round=%d nonce count=%d, want 1/1", observed.Model.GetRoundId(), len(observed.Nonces))
	}
	recoveredRegistry := ztsecurity.NewRegistrationStore()
	recovered, err := NewDurableService(recoveredRegistry, Config{MinUpdates: 1}, file)
	if err != nil {
		t.Fatalf("restart from uncertain durable model state: %v", err)
	}
	if recovered.service.currentModel().GetRoundId() != 1 {
		t.Fatalf("recovered round=%d, want 1", recovered.service.currentModel().GetRoundId())
	}

	recoveryAuth, recoveryKey := lifecycleAuthorizer(t, recoveredRegistry)
	recoveredWorker, recoveryCtx := lifecycleAuthorizedPeer(t, recoveryKey, worker.NodeID, "edge-worker")
	if !recoveredRegistry.IsRegistered(recoveredWorker) {
		t.Fatal("recovered legitimate worker registration missing")
	}
	response, err = invokeLifecycleRPC(recoveryAuth, recoveryCtx, ztsecurity.MethodSubmitLocalUpdate, req,
		func(ctx context.Context, input any) (any, error) {
			return recovered.SubmitLocalUpdate(ctx, input.(*flv1.SubmitLocalUpdateRequest))
		})
	if status.Code(err) != codes.AlreadyExists || (response != nil && response.(*flv1.SubmitLocalUpdateResponse) != nil) {
		t.Fatalf("duplicate after acknowledged-unknown restart: response=%v error=%v; want AlreadyExists", response, err)
	}
	finalState, err := file.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if finalState.Model.GetRoundId() != 1 || len(finalState.Nonces) != 1 {
		t.Fatalf("duplicate altered persisted model/replay state: round=%d nonces=%d", finalState.Model.GetRoundId(), len(finalState.Nonces))
	}
}
