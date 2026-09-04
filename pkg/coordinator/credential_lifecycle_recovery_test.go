package coordinator

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
)

func TestDurableServiceRecoversRegistrationRevocationTombstone(t *testing.T) {
	store, err := NewFileStateStore(filepath.Join(t.TempDir(), "coordinator-state.json"))
	if err != nil {
		t.Fatalf("create file state store: %v", err)
	}
	snapshot := testStateSnapshot(t)
	now := time.Now().UTC()
	snapshot.Pending = nil
	snapshot.RateWindows = nil
	snapshot.Registrations = []ztsecurity.Registration{{
		NodeID:                 "worker-a",
		Role:                   "edge-worker",
		CertificateFingerprint: "sha256:test-worker-a",
		RegistrationID:         "revoked-registration",
		ExpiresAt:              now.Add(time.Hour),
		Generation:             4,
		RevokedAt:              now,
		RevocationReason:       "operator revocation",
	}}
	if err := store.Commit(context.Background(), snapshot); err != nil {
		t.Fatalf("seed revoked durable state: %v", err)
	}

	registry := ztsecurity.NewRegistrationStore()
	_, err = NewDurableService(registry, Config{LeaseTTL: 5 * time.Minute, MinUpdates: 2}, store)
	if err != nil {
		t.Fatalf("recover durable service with revocation tombstone: %v", err)
	}
	identity := ztsecurity.PeerIdentity{
		NodeID:                 "worker-a",
		Role:                   "edge-worker",
		CertificateFingerprint: "sha256:test-worker-a",
	}
	if registry.IsRegistered(identity) {
		t.Fatal("revoked registration became active after restart")
	}
	if _, err := registry.Validate(identity, "revoked-registration"); err == nil {
		t.Fatal("revoked credential became valid after restart")
	}
	if _, err := registry.Register(identity, "replacement-registration", time.Hour); err == nil {
		t.Fatal("restart recovery allowed revoked identity to bypass active tombstone")
	}

	persisted, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load normalized durable state: %v", err)
	}
	if len(persisted.Registrations) != 1 || persisted.Registrations[0].Generation != 4 || persisted.Registrations[0].RevokedAt.IsZero() {
		t.Fatalf("normalized revocation tombstone = %#v", persisted.Registrations)
	}
}
