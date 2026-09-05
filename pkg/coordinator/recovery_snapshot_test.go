package coordinator

import (
	"context"
	"testing"
	"time"
)

func TestPostgresRecoverySnapshotPinsStateArtifactAndAuditView(t *testing.T) {
	dsn := postgresTestDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	resetPostgresStateTables(t, ctx, dsn)

	artifacts := s3TestArtifactStore(t, ctx)
	store, err := NewPostgresStateStoreWithArtifacts(ctx, dsn, artifacts)
	if err != nil {
		t.Fatalf("create PostgreSQL artifact state store: %v", err)
	}
	defer store.Close()

	initial := testStateSnapshot(t)
	initialized := stateAuditEvent(AuditEventStateInitialized, initial)
	if err := store.CommitWithAudit(ctx, initial, []AuditEvent{initialized}); err != nil {
		t.Fatalf("seed audited recovery state: %v", err)
	}

	recovery, err := store.BeginRecoverySnapshot(ctx)
	if err != nil {
		t.Fatalf("begin PostgreSQL recovery snapshot: %v", err)
	}
	defer recovery.Close(context.Background())
	if recovery.SnapshotID() == "" {
		t.Fatal("PostgreSQL recovery snapshot ID is empty")
	}

	metadata := recovery.Metadata()
	if metadata.StateSchemaVersion != coordinatorStateSchemaVersion {
		t.Fatalf("state schema version = %d, want %d", metadata.StateSchemaVersion, coordinatorStateSchemaVersion)
	}
	if metadata.ModelVersion != initial.Model.GetModelVersion() || metadata.RoundID != initial.Model.GetRoundId() {
		t.Fatalf("recovery model = %q round %d, want %q round %d", metadata.ModelVersion, metadata.RoundID, initial.Model.GetModelVersion(), initial.Model.GetRoundId())
	}
	if metadata.Artifact == nil {
		t.Fatal("artifact-backed state has no recovery artifact reference")
	}
	if len(metadata.Migrations) != 3 {
		t.Fatalf("recovery migration count = %d, want 3", len(metadata.Migrations))
	}
	if metadata.AuditHead.Sequence != 1 || metadata.AuditHead.EventHash == "" {
		t.Fatalf("recovery audit head = %#v", metadata.AuditHead)
	}
	if metadata.PostgreSQLVersion == "" || metadata.PostgreSQLVersionNum <= 0 {
		t.Fatalf("recovery PostgreSQL version metadata = %#v", metadata)
	}

	replacement := cloneStateSnapshot(initial)
	replacement.Model.ModelVersion = "round-8-after-backup-snapshot"
	replacement.Model.RoundId = initial.Model.GetRoundId() + 1
	replacement.Model.CreatedAtUnix = time.Now().UTC().Unix()
	recoveredEvent := stateAuditEvent(AuditEventStateRecovered, replacement)
	if err := store.CommitWithAudit(ctx, replacement, []AuditEvent{recoveredEvent}); err != nil {
		t.Fatalf("commit state after exported recovery snapshot: %v", err)
	}

	pinned := recovery.Metadata()
	if pinned.ModelVersion != initial.Model.GetModelVersion() || pinned.RoundID != initial.Model.GetRoundId() {
		t.Fatalf("exported recovery metadata moved after concurrent commit: %#v", pinned)
	}
	if pinned.AuditHead.Sequence != 1 {
		t.Fatalf("exported recovery audit head moved to %d, want 1", pinned.AuditHead.Sequence)
	}

	records, err := recovery.ReadAuditEvents(ctx)
	if err != nil {
		t.Fatalf("read pinned recovery audit chain: %v", err)
	}
	if len(records) != 1 || records[0].Event.Type != AuditEventStateInitialized {
		t.Fatalf("pinned recovery audit records = %#v", records)
	}

	live, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("load live state after concurrent commit: %v", err)
	}
	if live.Model.GetModelVersion() != replacement.Model.GetModelVersion() {
		t.Fatalf("live model version = %q, want %q", live.Model.GetModelVersion(), replacement.Model.GetModelVersion())
	}
}
