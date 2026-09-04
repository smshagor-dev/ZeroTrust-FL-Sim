package security

import (
	"testing"
	"time"
)

func TestRegistrationStoreSnapshotAndRestore(t *testing.T) {
	identity := PeerIdentity{
		NodeID:                 "worker-a",
		Role:                   "edge-worker",
		CertificateFingerprint: "sha256:worker-a",
	}
	store := NewRegistrationStore()
	registered, err := store.Register(identity, "registration-a", time.Hour)
	if err != nil {
		t.Fatalf("register identity: %v", err)
	}

	snapshot := store.Snapshot()
	if len(snapshot) != 1 || snapshot[0].RegistrationID != registered.RegistrationID {
		t.Fatalf("snapshot = %#v", snapshot)
	}

	recovered := NewRegistrationStore()
	if err := recovered.RestoreSnapshot(snapshot); err != nil {
		t.Fatalf("restore snapshot: %v", err)
	}
	entry, err := recovered.Validate(identity, "registration-a")
	if err != nil {
		t.Fatalf("validate recovered registration: %v", err)
	}
	if !entry.ExpiresAt.Equal(registered.ExpiresAt) {
		t.Fatalf("recovered expiry = %v, want %v", entry.ExpiresAt, registered.ExpiresAt)
	}
}

func TestRegistrationStoreRestoreDropsExpiredEntries(t *testing.T) {
	store := NewRegistrationStore()
	if err := store.RestoreSnapshot([]Registration{
		{
			NodeID:                 "expired-worker",
			Role:                   "edge-worker",
			CertificateFingerprint: "sha256:expired",
			RegistrationID:         "expired-registration",
			ExpiresAt:              time.Now().UTC().Add(-time.Minute),
		},
	}); err != nil {
		t.Fatalf("restore expired snapshot: %v", err)
	}
	if got := store.Snapshot(); len(got) != 0 {
		t.Fatalf("expired registration survived restore: %#v", got)
	}
}

func TestRegistrationStoreRestoreRejectsDuplicateNodes(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour)
	store := NewRegistrationStore()
	err := store.RestoreSnapshot([]Registration{
		{
			NodeID:                 "worker-a",
			Role:                   "edge-worker",
			CertificateFingerprint: "sha256:a",
			RegistrationID:         "registration-a",
			ExpiresAt:              expires,
		},
		{
			NodeID:                 "worker-a",
			Role:                   "edge-worker",
			CertificateFingerprint: "sha256:b",
			RegistrationID:         "registration-b",
			ExpiresAt:              expires,
		},
	})
	if err == nil {
		t.Fatal("duplicate registration snapshot was accepted")
	}
}
