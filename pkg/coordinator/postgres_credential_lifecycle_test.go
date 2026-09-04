package coordinator

import (
	"context"
	"testing"
	"time"
)

func TestPostgresRegistrationLifecycleAuditEvents(t *testing.T) {
	dsn := postgresTestDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetPostgresStateTables(t, ctx, dsn)

	store, err := NewPostgresStateStore(ctx, dsn)
	if err != nil {
		t.Fatalf("create PostgreSQL state store: %v", err)
	}
	defer store.Close()

	snapshot := testStateSnapshot(t)
	rotation := stateAuditEvent(AuditEventCredentialRotated, snapshot)
	rotation.NodeID = "worker-a"
	rotation.RegistrationIDHash = hashAuditOpaqueIdentifier("rotated-registration")
	rotation.LeaseExpiresUnix = time.Now().UTC().Add(time.Hour).Unix()
	rotation.CredentialGeneration = 2

	revocation := stateAuditEvent(AuditEventRegistrationRevoked, snapshot)
	revocation.NodeID = "admin-a"
	revocation.TargetNodeID = "worker-a"
	revocation.CredentialGeneration = 2
	revocation.BlockedUntilUnix = rotation.LeaseExpiresUnix

	if err := store.CommitWithAudit(ctx, snapshot, []AuditEvent{rotation, revocation}); err != nil {
		t.Fatalf("commit lifecycle audit events: %v", err)
	}
	records, err := store.ReadAuditEvents(ctx, 0, 10)
	if err != nil {
		t.Fatalf("read lifecycle audit events: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("lifecycle audit record count = %d, want 2", len(records))
	}
	if records[0].Event.Type != AuditEventCredentialRotated || records[0].Event.CredentialGeneration != 2 {
		t.Fatalf("rotation audit record = %#v", records[0])
	}
	if records[1].Event.Type != AuditEventRegistrationRevoked || records[1].Event.TargetNodeID != "worker-a" || records[1].Event.CredentialGeneration != 2 {
		t.Fatalf("revocation audit record = %#v", records[1])
	}
	if records[1].PreviousHash != records[0].EventHash {
		t.Fatalf("lifecycle audit chain link = %q, want %q", records[1].PreviousHash, records[0].EventHash)
	}
}
