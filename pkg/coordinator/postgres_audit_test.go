package coordinator

import (
	"context"
	"strings"
	"testing"
	"time"

	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
)

func TestPostgresAuditedCommitIsAtomicAndTamperEvident(t *testing.T) {
	dsn := postgresTestDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetPostgresStateTables(t, ctx, dsn)

	store, err := NewPostgresStateStore(ctx, dsn)
	if err != nil {
		t.Fatalf("create PostgreSQL state store: %v", err)
	}
	defer store.Close()

	base := testStateSnapshot(t)
	initialized := stateAuditEvent(AuditEventStateInitialized, base)
	if err := store.CommitWithAudit(ctx, base, []AuditEvent{initialized}); err != nil {
		t.Fatalf("commit initial audited state: %v", err)
	}
	records, err := store.ReadAuditEvents(ctx, 0, 100)
	if err != nil {
		t.Fatalf("read initial audit chain: %v", err)
	}
	if len(records) != 1 || records[0].Sequence != 1 || records[0].Event.Type != AuditEventStateInitialized {
		t.Fatalf("initial audit records = %#v", records)
	}

	replacement := cloneStateSnapshot(base)
	replacement.Model.ModelVersion = "round-8-audited"
	replacement.Model.RoundId = 8
	replacement.Model.CreatedAtUnix = time.Now().UTC().Unix()
	recovered := stateAuditEvent(AuditEventStateRecovered, replacement)

	if _, err := store.pool.Exec(ctx, `
		ALTER TABLE ztfl_audit_events
		ADD CONSTRAINT ztfl_test_reject_recovery
		CHECK (event_type <> 'coordinator.state.recovered')
	`); err != nil {
		t.Fatalf("install audit failure constraint: %v", err)
	}
	if err := store.CommitWithAudit(ctx, replacement, []AuditEvent{recovered}); err == nil {
		t.Fatal("audited state commit succeeded even though the audit insert was rejected")
	}
	if _, err := store.pool.Exec(ctx, `ALTER TABLE ztfl_audit_events DROP CONSTRAINT ztfl_test_reject_recovery`); err != nil {
		t.Fatalf("remove audit failure constraint: %v", err)
	}

	loaded, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("load state after failed audited transaction: %v", err)
	}
	assertPostgresSnapshotEquivalent(t, loaded, base)
	records, err = store.ReadAuditEvents(ctx, 0, 100)
	if err != nil {
		t.Fatalf("read audit chain after failed transaction: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("audit records after failed transaction = %d, want 1", len(records))
	}

	if err := store.CommitWithAudit(ctx, replacement, []AuditEvent{recovered}); err != nil {
		t.Fatalf("commit recovered audited state: %v", err)
	}
	page, err := store.ReadAuditEvents(ctx, 1, 1)
	if err != nil {
		t.Fatalf("read paged audit record: %v", err)
	}
	if len(page) != 1 || page[0].Sequence != 2 || page[0].Event.Type != AuditEventStateRecovered {
		t.Fatalf("paged audit records = %#v", page)
	}
	if _, err := store.ReadAuditEvents(ctx, 999, 1); err == nil {
		t.Fatal("missing audit cursor was accepted")
	}

	if _, err := store.pool.Exec(ctx, `
		UPDATE ztfl_audit_events
		SET event_payload = jsonb_set(event_payload, '{model_version}', '"tampered"'::jsonb)
		WHERE sequence = 2
	`); err != nil {
		t.Fatalf("tamper audit payload fixture: %v", err)
	}
	if _, err := store.ReadAuditEvents(ctx, 0, 100); err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("tampered audit chain error = %v, want hash verification failure", err)
	}
}

func TestPostgresDurableServiceAuditsBootstrapAndRecovery(t *testing.T) {
	dsn := postgresTestDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetPostgresStateTables(t, ctx, dsn)

	store, err := NewPostgresStateStore(ctx, dsn)
	if err != nil {
		t.Fatalf("create PostgreSQL state store: %v", err)
	}
	defer store.Close()

	if _, err := NewDurableService(ztsecurity.NewRegistrationStore(), Config{}, store); err != nil {
		t.Fatalf("initialize durable service: %v", err)
	}
	records, err := store.ReadAuditEvents(ctx, 0, 10)
	if err != nil {
		t.Fatalf("read bootstrap audit event: %v", err)
	}
	if len(records) != 1 || records[0].Event.Type != AuditEventStateInitialized {
		t.Fatalf("bootstrap audit records = %#v", records)
	}

	if _, err := NewDurableService(ztsecurity.NewRegistrationStore(), Config{}, store); err != nil {
		t.Fatalf("recover durable service: %v", err)
	}
	records, err = store.ReadAuditEvents(ctx, 0, 10)
	if err != nil {
		t.Fatalf("read recovery audit chain: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("audit records after restart = %d, want 2", len(records))
	}
	if records[0].Event.Type != AuditEventStateInitialized || records[1].Event.Type != AuditEventStateRecovered {
		t.Fatalf("restart audit event types = %q, %q", records[0].Event.Type, records[1].Event.Type)
	}
}
