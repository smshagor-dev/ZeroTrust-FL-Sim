package coordinator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ieeePostgresFaultStore forwards to actual serializable PostgreSQL commits,
// including their atomic state+audit transaction. An error after successful
// CommitWithAudit models a lost acknowledgment, NOT a database crash.
type ieeePostgresFaultStore struct {
	inner *PostgresStateStore
	mu    sync.Mutex
	plan  []p1CommitFault
}

func (s *ieeePostgresFaultStore) Load(ctx context.Context) (StateSnapshot, error) {
	return s.inner.Load(ctx)
}

func (s *ieeePostgresFaultStore) Commit(ctx context.Context, snapshot StateSnapshot) error {
	fault := s.nextFault()
	if fault == p1FailBeforeWrite {
		return errors.New("injected PostgreSQL write refusal")
	}
	if err := s.inner.Commit(ctx, snapshot); err != nil {
		return err
	}
	if fault == p1FailAfterWrite {
		return errors.New("injected lost PostgreSQL Commit completion signal")
	}
	return nil
}

func (s *ieeePostgresFaultStore) CommitWithAudit(ctx context.Context, snapshot StateSnapshot, events []AuditEvent) error {
	fault := s.nextFault()
	if fault == p1FailBeforeWrite {
		return errors.New("injected PostgreSQL audited transaction refusal")
	}
	if err := s.inner.CommitWithAudit(ctx, snapshot, events); err != nil {
		return err
	}
	if fault == p1FailAfterWrite {
		return errors.New("injected lost PostgreSQL audited transaction completion signal")
	}
	return nil
}

func (s *ieeePostgresFaultStore) nextFault() p1CommitFault {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.plan) == 0 {
		return 0
	}
	fault := s.plan[0]
	s.plan = s.plan[1:]
	return fault
}

func (s *ieeePostgresFaultStore) schedule(faults ...p1CommitFault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.plan) != 0 {
		panic("fault plan was not fully consumed")
	}
	s.plan = append(s.plan, faults...)
}

func (s *ieeePostgresFaultStore) assertComplete(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.plan) != 0 {
		t.Fatalf("unconsumed PostgreSQL fault boundaries: %d", len(s.plan))
	}
}

func ieeePostgresRevokeEventCount(t *testing.T, ctx context.Context, store *PostgresStateStore, nodeID string) int {
	t.Helper()
	records, err := store.ReadAuditEvents(ctx, 0, 500)
	if err != nil {
		t.Fatalf("read independently verified PostgreSQL audit hash chain: %v", err)
	}
	count := 0
	for _, record := range records {
		if record.Event.Type == AuditEventRegistrationRevoked && record.Event.TargetNodeID == nodeID {
			count++
		}
	}
	return count
}

// Observe state through a fresh PostgreSQL connection, not via in-memory
// coordinator snapshots. All cases inject an error AFTER PostgreSQL's real
// CommitWithAudit returns nil, then control the rollback write outcome.
func TestPostgresIEEERevocationCommitAckAndRecovery(t *testing.T) {
	scenarios := []struct {
		name       string
		faults     []p1CommitFault
		wantFenced bool
		wantActive bool
	}{
		{"rollback-confirmed", []p1CommitFault{p1FailAfterWrite}, false, true},
		{"rollback-refused", []p1CommitFault{p1FailAfterWrite, p1FailBeforeWrite}, true, false},
		{"rollback-ack-uncertain", []p1CommitFault{p1FailAfterWrite, p1FailAfterWrite}, true, true},
	}
	dsn := postgresTestDSN(t)
	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			resetPostgresStateTables(t, ctx, dsn)
			inner, err := NewPostgresStateStore(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer inner.Close()

			registry := ztsecurity.NewRegistrationStore()
			authorizer, key := lifecycleAuthorizer(t, registry)
			admin, adminCtx := lifecycleAuthorizedPeer(t, key, "pg-p2-admin", "admin")
			worker, workerCtx := lifecycleAuthorizedPeer(t, key, "pg-p2-worker", "edge-worker")
			for _, identity := range []ztsecurity.PeerIdentity{admin, worker} {
				if _, err := registry.Register(identity, "registration-"+identity.NodeID, time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			faulting := &ieeePostgresFaultStore{inner: inner}
			durable, err := NewDurableService(registry, Config{MinUpdates: 2}, faulting)
			if err != nil {
				t.Fatal(err)
			}
			update := p1UpdateRequest(t, worker.NodeID, "registration-"+worker.NodeID, "p2-pg-pending-nonce-0001", 8)
			_, err = invokeLifecycleRPC(authorizer, workerCtx, ztsecurity.MethodSubmitLocalUpdate,
				update, func(callCtx context.Context, req any) (any, error) {
					return durable.SubmitLocalUpdate(callCtx, req.(*flv1.SubmitLocalUpdateRequest))
				})
			if err != nil {
				t.Fatalf("create legitimately accepted pending contribution: %v", err)
			}

			faulting.schedule(tc.faults...)
			revoke := &flv1.RevokeRegistrationRequest{
				NodeId: admin.NodeID, RegistrationId: "registration-" + admin.NodeID,
				TargetNodeId: worker.NodeID, Reason: "controlled PostgreSQL ack-loss experiment",
				Security: lifecycleSecurityMetadata([]byte("p2-pg-revoke-nonce-0001")),
			}
			_, err = invokeLifecycleRPC(authorizer, adminCtx, ztsecurity.MethodRevokeRegistration,
				revoke, func(callCtx context.Context, req any) (any, error) {
					return durable.RevokeRegistration(callCtx, req.(*flv1.RevokeRegistrationRequest))
				})
			if status.Code(err) != codes.Internal {
				t.Fatalf("revocation acknowledgment on lost commit signal: %v, want Internal", err)
			}
			faulting.assertComplete(t)
			if durable.fenced != tc.wantFenced {
				t.Fatalf("serving fence=%t, want %t", durable.fenced, tc.wantFenced)
			}

			observer, err := NewPostgresStateStore(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close()
			persisted, err := observer.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			active := p1FileStateHasActiveRegistration(persisted, worker.NodeID)
			pending := p1FileStateHasPending(persisted, worker.NodeID)
			if active != tc.wantActive || pending != tc.wantActive || persisted.Model.GetRoundId() != 0 {
				t.Fatalf("independent PostgreSQL state: active=%t pending=%t round=%d; want %t/%t/0",
					active, pending, persisted.Model.GetRoundId(), tc.wantActive, tc.wantActive)
			}
			if tc.wantFenced {
				if _, err := durable.GetGlobalModel(context.Background(), &flv1.GetGlobalModelRequest{}); status.Code(err) != codes.Unavailable {
					t.Fatalf("fenced coordinator accepted model read: %v", err)
				}
			}

			// The hash-chain audit may retain a success-labelled event from a
			// durable write subsequently rolled back. Record this separately:
			// it is NOT proof that the revoked credential remained revoked.
			revocationAuditCount := ieeePostgresRevokeEventCount(t, ctx, observer, worker.NodeID)
			t.Logf("IEEE_P2_POSTGRES scenario=%s fenced=%t disk_active=%t pending=%t revoked_success_audit_events=%d",
				tc.name, durable.fenced, active, pending, revocationAuditCount)

			recoveredRegistry := ztsecurity.NewRegistrationStore()
			recovered, err := NewDurableService(recoveredRegistry, Config{MinUpdates: 2}, observer)
			if err != nil {
				t.Fatalf("independent PostgreSQL recovery: %v", err)
			}
			if recoveredRegistry.IsRegistered(worker) != tc.wantActive {
				t.Fatalf("restarted registration mismatch: active=%t, want %t", recoveredRegistry.IsRegistered(worker), tc.wantActive)
			}
			if p1FileStateHasPending(recovered.captureSnapshot(), worker.NodeID) != tc.wantActive {
				t.Fatal("restarted pending queue did not match independently observed database state")
			}
		})
	}
}

// A PostgreSQL transaction has committed the model and nonce but the
// caller sees an error. When its compensating rollback fails, the service
// fences; after independent DB recovery, identical nonce cannot commit twice.
func TestPostgresIEEEAmbiguousUpdateAckRejectsPostRecoveryReplay(t *testing.T) {
	dsn := postgresTestDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	resetPostgresStateTables(t, ctx, dsn)

	inner, err := NewPostgresStateStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()

	registry := ztsecurity.NewRegistrationStore()
	authorizer, key := lifecycleAuthorizer(t, registry)
	worker, workerCtx := lifecycleAuthorizedPeer(t, key, "pg-p2-replay-worker", "edge-worker")
	const registrationID = "pg-p2-replay-registration"
	if _, err := registry.Register(worker, registrationID, time.Hour); err != nil {
		t.Fatal(err)
	}
	faulting := &ieeePostgresFaultStore{inner: inner}
	durable, err := NewDurableService(registry, Config{MinUpdates: 1}, faulting)
	if err != nil {
		t.Fatal(err)
	}
	request := p1UpdateRequest(t, worker.NodeID, registrationID, "p2-pg-replay-nonce-0001", 7)
	faulting.schedule(p1FailAfterWrite, p1FailBeforeWrite)
	_, err = invokeLifecycleRPC(authorizer, workerCtx, ztsecurity.MethodSubmitLocalUpdate,
		request, func(callCtx context.Context, req any) (any, error) {
			return durable.SubmitLocalUpdate(callCtx, req.(*flv1.SubmitLocalUpdateRequest))
		})
	if status.Code(err) != codes.Internal || !durable.fenced {
		t.Fatalf("ambiguous acknowledged-unknown update: err=%v fenced=%t; want Internal/true", err, durable.fenced)
	}
	faulting.assertComplete(t)

	observer, err := NewPostgresStateStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	snapshot, err := observer.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Model.GetRoundId() != 1 || len(snapshot.Nonces) != 1 {
		t.Fatalf("committed-but-unacknowledged PostgreSQL round=%d nonces=%d; want 1/1", snapshot.Model.GetRoundId(), len(snapshot.Nonces))
	}
	recoveredRegistry := ztsecurity.NewRegistrationStore()
	recovered, err := NewDurableService(recoveredRegistry, Config{MinUpdates: 1}, observer)
	if err != nil {
		t.Fatal(err)
	}
	recoveryAuthorizer, recoveryKey := lifecycleAuthorizer(t, recoveredRegistry)
	recoveredWorker, recoveredCtx := lifecycleAuthorizedPeer(t, recoveryKey, worker.NodeID, "edge-worker")
	if !recoveredRegistry.IsRegistered(recoveredWorker) {
		t.Fatal("legitimate registration did not survive PostgreSQL recovery")
	}
	_, err = invokeLifecycleRPC(recoveryAuthorizer, recoveredCtx, ztsecurity.MethodSubmitLocalUpdate,
		request, func(callCtx context.Context, req any) (any, error) {
			return recovered.SubmitLocalUpdate(callCtx, req.(*flv1.SubmitLocalUpdateRequest))
		})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("persisted nonce reuse after PostgreSQL restart: %v, want AlreadyExists", err)
	}
	after, err := observer.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Model.GetRoundId() != 1 || len(after.Nonces) != 1 {
		t.Fatalf("duplicate retry changed committed PostgreSQL state: round=%d nonces=%d", after.Model.GetRoundId(), len(after.Nonces))
	}
	t.Logf("IEEE_P2_POSTGRES scenario=ambiguous_model_update fenced=true recovered_round=%d replay_denied=true", after.Model.GetRoundId())
}
