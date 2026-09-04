package coordinator

import (
	"context"
	"testing"
	"time"

	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
)

func TestDurableCredentialRotationRollbackRestoresOldCredential(t *testing.T) {
	registry := ztsecurity.NewRegistrationStore()
	identity := ztsecurity.PeerIdentity{
		NodeID:                 "worker-a",
		Role:                   "edge-worker",
		CertificateFingerprint: "sha256:worker-a",
	}
	entry, err := registry.Register(identity, "registration-1", time.Hour)
	if err != nil {
		t.Fatalf("seed registration: %v", err)
	}
	service, err := NewService(registry, Config{})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	store := &failOnceStateStore{}
	durable := &DurableService{service: service, store: store}
	before := durable.captureSnapshot()

	rotated, err := registry.Rotate(identity, entry.RegistrationID, "registration-2", time.Hour)
	if err != nil {
		t.Fatalf("apply transient credential rotation: %v", err)
	}
	after := durable.captureSnapshot()
	if err := durable.commitOrRollbackTransition(context.Background(), before, after, "rotation-test", nil); err == nil {
		t.Fatal("injected lifecycle persistence failure was acknowledged")
	}
	if _, err := registry.Validate(identity, entry.RegistrationID); err != nil {
		t.Fatalf("old credential was not restored after rollback: %v", err)
	}
	if _, err := registry.Validate(identity, rotated.RegistrationID); err == nil {
		t.Fatal("uncommitted rotated credential survived rollback")
	}
}

func TestDurableRevocationRollbackRestoresRegistrationAndPendingUpdate(t *testing.T) {
	registry := ztsecurity.NewRegistrationStore()
	identity := ztsecurity.PeerIdentity{
		NodeID:                 "worker-a",
		Role:                   "edge-worker",
		CertificateFingerprint: "sha256:worker-a",
	}
	entry, err := registry.Register(identity, "registration-1", time.Hour)
	if err != nil {
		t.Fatalf("seed registration: %v", err)
	}
	service, err := NewService(registry, Config{MinUpdates: 2})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	service.pending[identity.NodeID] = pendingUpdate{
		NodeID:      identity.NodeID,
		UpdateID:    "pending-1",
		Values:      []float32{1},
		SampleCount: 1,
	}
	store := &failOnceStateStore{}
	durable := &DurableService{service: service, store: store}
	before := durable.captureSnapshot()

	if _, err := registry.Revoke(identity.NodeID, "transient revocation"); err != nil {
		t.Fatalf("apply transient revocation: %v", err)
	}
	delete(service.pending, identity.NodeID)
	after := durable.captureSnapshot()
	if err := durable.commitOrRollbackTransition(context.Background(), before, after, "revocation-test", nil); err == nil {
		t.Fatal("injected revocation persistence failure was acknowledged")
	}
	if _, err := registry.Validate(identity, entry.RegistrationID); err != nil {
		t.Fatalf("registration was not restored after revocation rollback: %v", err)
	}
	if _, ok := service.pending[identity.NodeID]; !ok {
		t.Fatal("pending update was not restored after revocation rollback")
	}
}
