package coordinator

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// p1CommitBarrierStore pauses one real StateStore commit. This lets a test
// establish the update/revocation order without relying on a scheduler sleep.
// It is not a power-loss or independently published baseline experiment.
type p1CommitBarrierStore struct {
	inner   StateStore
	mu      sync.Mutex
	armed   bool
	entered chan struct{}
	release chan struct{}
}

func (s *p1CommitBarrierStore) Load(ctx context.Context) (StateSnapshot, error) {
	return s.inner.Load(ctx)
}

func (s *p1CommitBarrierStore) Commit(ctx context.Context, snapshot StateSnapshot) error {
	s.mu.Lock()
	armed := s.armed
	entered, release := s.entered, s.release
	if armed {
		s.armed = false
	}
	s.mu.Unlock()
	if armed {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.inner.Commit(ctx, snapshot)
}

func (s *p1CommitBarrierStore) blockNextCommit() (<-chan struct{}, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.armed = true
	s.entered = make(chan struct{})
	s.release = make(chan struct{})
	return s.entered, s.release
}

func p1WaitForBarrier(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("durable commit did not reach deterministic barrier")
	}
}

func p1WaitForResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("durable coordinator request did not complete")
		return nil
	}
}

func p1UpdateRequest(t *testing.T, nodeID, registrationID, nonce string, value float32) *flv1.SubmitLocalUpdateRequest {
	t.Helper()
	payload, err := encodeNPYFloat32([]float32{value})
	if err != nil {
		t.Fatalf("encode test update: %v", err)
	}
	digest := sha256.Sum256(payload)
	return &flv1.SubmitLocalUpdateRequest{
		NodeId:           nodeID,
		RegistrationId:   registrationID,
		RoundId:          0,
		BaseModelVersion: "bootstrap",
		WeightsPayload:   payload,
		WeightsFormat:    networkWeightsFormat,
		UpdateSha256:     digest[:],
		Metrics:          &flv1.LocalUpdateMetrics{DynamicEpochs: 1, SampleCount: 1},
		Security:         lifecycleSecurityMetadata([]byte(nonce)),
	}
}

func TestIEEEPendingRevocationDurabilityAndRecovery(t *testing.T) {
	registry := ztsecurity.NewRegistrationStore()
	authorizer, key := lifecycleAuthorizer(t, registry)
	contexts := make(map[string]context.Context)
	identities := make(map[string]ztsecurity.PeerIdentity)
	for _, nodeID := range []string{"p1-admin", "p1-worker-a", "p1-worker-b", "p1-worker-c"} {
		role := "edge-worker"
		if nodeID == "p1-admin" {
			role = "admin"
		}
		identity, ctx := lifecycleAuthorizedPeer(t, key, nodeID, role)
		identities[nodeID], contexts[nodeID] = identity, ctx
		if _, err := registry.Register(identity, "registration-"+nodeID, time.Hour); err != nil {
			t.Fatalf("register %s: %v", nodeID, err)
		}
	}
	store, err := NewFileStateStore(filepath.Join(t.TempDir(), "coordinator-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	durable, err := NewDurableService(registry, Config{MinUpdates: 2}, store)
	if err != nil {
		t.Fatal(err)
	}
	submit := func(nodeID, nonce string, delta float32) error {
		request := p1UpdateRequest(t, nodeID, "registration-"+nodeID, nonce, delta)
		response, err := invokeLifecycleRPC(authorizer, contexts[nodeID], ztsecurity.MethodSubmitLocalUpdate,
			request, func(ctx context.Context, input any) (any, error) {
				return durable.SubmitLocalUpdate(ctx, input.(*flv1.SubmitLocalUpdateRequest))
			})
		if err != nil {
			return err
		}
		if !response.(*flv1.SubmitLocalUpdateResponse).GetAccepted() {
			return fmt.Errorf("update %s was not acknowledged", nodeID)
		}
		return nil
	}

	// The first contribution is genuinely acknowledged and persisted as
	// pending, but has not yet changed the model version.
	if err := submit("p1-worker-a", "p1-a-initial-nonce-0001", 100); err != nil {
		t.Fatalf("submit first pending update: %v", err)
	}
	before, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Pending) != 1 || before.Pending[0].NodeID != "p1-worker-a" || before.Model.GetRoundId() != 0 {
		t.Fatalf("unexpected persisted pre-revocation state: pending=%v round=%d", before.Pending, before.Model.GetRoundId())
	}

	request := &flv1.RevokeRegistrationRequest{
		NodeId: "p1-admin", RegistrationId: "registration-p1-admin",
		TargetNodeId: "p1-worker-a", Reason: "compromised test generation",
		Security: lifecycleSecurityMetadata([]byte("p1-admin-revoke-0001")),
	}
	resp, err := invokeLifecycleRPC(authorizer, contexts["p1-admin"], ztsecurity.MethodRevokeRegistration,
		request, func(ctx context.Context, input any) (any, error) {
			return durable.RevokeRegistration(ctx, input.(*flv1.RevokeRegistrationRequest))
		})
	if err != nil || !resp.(*flv1.RevokeRegistrationResponse).GetAccepted() {
		t.Fatalf("durable revocation not acknowledged: response=%v error=%v", resp, err)
	}
	after, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Pending) != 0 || after.Model.GetRoundId() != 0 {
		t.Fatalf("revocation did not remove persisted pending contribution: pending=%v round=%d", after.Pending, after.Model.GetRoundId())
	}
	if _, err := registry.Validate(identities["p1-worker-a"], "registration-p1-worker-a"); err == nil {
		t.Fatal("revoked registration remained valid after durable revocation")
	}
	if err := submit("p1-worker-a", "p1-a-revoked-nonce-0002", 100); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked worker submit result %v, want PermissionDenied", err)
	}

	// Two legitimate clients now satisfy quorum. Their median delta is 3;
	// the revoked client's earlier delta=100 must not reach the model.
	if err := submit("p1-worker-b", "p1-b-valid-nonce-0001", 2); err != nil {
		t.Fatal(err)
	}
	if err := submit("p1-worker-c", "p1-c-valid-nonce-0001", 4); err != nil {
		t.Fatal(err)
	}
	finalState, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	values, err := decodeNPYFloat32(finalState.Model.GetWeightsPayload())
	if err != nil {
		t.Fatal(err)
	}
	if finalState.Model.GetRoundId() != 1 || len(finalState.Pending) != 0 || len(values) != 1 || values[0] != 3 {
		t.Fatalf("durable model contains wrong quorum contribution: round=%d pending=%v values=%v", finalState.Model.GetRoundId(), finalState.Pending, values)
	}

	recoveredRegistry := ztsecurity.NewRegistrationStore()
	recovered, err := NewDurableService(recoveredRegistry, Config{MinUpdates: 2}, store)
	if err != nil {
		t.Fatalf("restart from real durable state: %v", err)
	}
	if recovered.service.currentModel().GetRoundId() != 1 || recoveredRegistry.IsRegistered(identities["p1-worker-a"]) {
		t.Fatal("recovered service lost revocation tombstone or committed model version")
	}
}

// The barrier forces either update->revoke or revoke->update to enter the real
// file-backed durable transition first. Neither outcome is a network or
// hardware-crash guarantee, and neither relies on a test-only policy bypass.
func TestIEEEDurableUpdateRevocationOrdering(t *testing.T) {
	for _, firstOperation := range []string{"update", "revoke"} {
		t.Run(firstOperation+"_first", func(t *testing.T) {
			registry := ztsecurity.NewRegistrationStore()
			authorizer, key := lifecycleAuthorizer(t, registry)
			worker, workerCtx := lifecycleAuthorizedPeer(t, key, "p1-race-worker", "edge-worker")
			admin, adminCtx := lifecycleAuthorizedPeer(t, key, "p1-race-admin", "admin")
			if _, err := registry.Register(worker, "p1-worker-registration", time.Hour); err != nil {
				t.Fatal(err)
			}
			if _, err := registry.Register(admin, "p1-admin-registration", time.Hour); err != nil {
				t.Fatal(err)
			}
			fileStore, err := NewFileStateStore(filepath.Join(t.TempDir(), "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			store := &p1CommitBarrierStore{inner: fileStore}
			durable, err := NewDurableService(registry, Config{MinUpdates: 1}, store)
			if err != nil {
				t.Fatal(err)
			}
			updateRequest := p1UpdateRequest(t, worker.NodeID, "p1-worker-registration", "p1-race-update-nonce-0001", 7)
			revokeRequest := &flv1.RevokeRegistrationRequest{
				NodeId: admin.NodeID, RegistrationId: "p1-admin-registration",
				TargetNodeId: worker.NodeID, Reason: "deterministic interleaving test",
				Security: lifecycleSecurityMetadata([]byte("p1-race-revoke-nonce-0001")),
			}
			update := func() error {
				res, err := invokeLifecycleRPC(authorizer, workerCtx, ztsecurity.MethodSubmitLocalUpdate,
					updateRequest, func(ctx context.Context, input any) (any, error) {
						return durable.SubmitLocalUpdate(ctx, input.(*flv1.SubmitLocalUpdateRequest))
					})
				if err != nil {
					return err
				}
				if !res.(*flv1.SubmitLocalUpdateResponse).GetAccepted() {
					return fmt.Errorf("model mutation not acknowledged")
				}
				return nil
			}
			revoke := func() error {
				res, err := invokeLifecycleRPC(authorizer, adminCtx, ztsecurity.MethodRevokeRegistration,
					revokeRequest, func(ctx context.Context, input any) (any, error) {
						return durable.RevokeRegistration(ctx, input.(*flv1.RevokeRegistrationRequest))
					})
				if err != nil {
					return err
				}
				if !res.(*flv1.RevokeRegistrationResponse).GetAccepted() {
					return fmt.Errorf("registration revocation not acknowledged")
				}
				return nil
			}
			entered, release := store.blockNextCommit()
			firstDone, secondDone := make(chan error, 1), make(chan error, 1)
			if firstOperation == "update" {
				go func() { firstDone <- update() }()
			} else {
				go func() { firstDone <- revoke() }()
			}
			p1WaitForBarrier(t, entered)
			// This operation overlaps a paused durable commit; its final
			// outcome must follow the first operation's serialization order.
			if firstOperation == "update" {
				go func() { secondDone <- revoke() }()
			} else {
				go func() { secondDone <- update() }()
			}
			select {
			case early := <-firstDone:
				t.Fatalf("operation acknowledged before durable commit was released: %v", early)
			default:
			}
			close(release)
			firstErr := p1WaitForResult(t, firstDone)
			secondErr := p1WaitForResult(t, secondDone)
			if firstErr != nil {
				t.Fatalf("first %s operation failed: %v", firstOperation, firstErr)
			}
			if firstOperation == "update" {
				if secondErr != nil {
					t.Fatalf("following revocation failed: %v", secondErr)
				}
			} else if status.Code(secondErr) != codes.PermissionDenied {
				t.Fatalf("post-revocation update result=%v, want PermissionDenied", secondErr)
			}
			snapshot, err := fileStore.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			wantRound := uint64(0)
			if firstOperation == "update" {
				wantRound = 1
			}
			if snapshot.Model.GetRoundId() != wantRound || registry.IsRegistered(worker) {
				t.Fatalf("serialization contradiction: round=%d, want=%d, worker active=%t", snapshot.Model.GetRoundId(), wantRound, registry.IsRegistered(worker))
			}
			if _, err := NewDurableService(ztsecurity.NewRegistrationStore(), Config{MinUpdates: 1}, fileStore); err != nil {
				t.Fatalf("recover serialized state: %v", err)
			}
		})
	}
}
