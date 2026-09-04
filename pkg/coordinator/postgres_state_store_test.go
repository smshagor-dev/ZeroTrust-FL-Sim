package coordinator

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

const postgresTestDSNEnv = "ZTFL_TEST_POSTGRES_DSN"

func TestPostgresStateStoreRejectsEmptyDSN(t *testing.T) {
	if _, err := NewPostgresStateStore(context.Background(), "   "); err == nil {
		t.Fatal("empty PostgreSQL DSN was accepted")
	}
}

func TestPostgresStateStoreRoundTripMigrationAndReconnect(t *testing.T) {
	dsn := postgresTestDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetPostgresStateTables(t, ctx, dsn)

	store, err := NewPostgresStateStore(ctx, dsn)
	if err != nil {
		t.Fatalf("create PostgreSQL state store: %v", err)
	}
	if _, err := store.Load(ctx); !errors.Is(err, ErrStateNotFound) {
		store.Close()
		t.Fatalf("load missing PostgreSQL state error = %v, want ErrStateNotFound", err)
	}

	var migrationCount int
	if err := store.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ztfl_schema_migrations`).Scan(&migrationCount); err != nil {
		store.Close()
		t.Fatalf("count PostgreSQL migrations: %v", err)
	}
	if migrationCount != 1 {
		store.Close()
		t.Fatalf("migration count = %d, want 1", migrationCount)
	}

	snapshot := testStateSnapshot(t)
	if err := store.Commit(ctx, snapshot); err != nil {
		store.Close()
		t.Fatalf("commit PostgreSQL state: %v", err)
	}
	loaded, err := store.Load(ctx)
	if err != nil {
		store.Close()
		t.Fatalf("load PostgreSQL state: %v", err)
	}
	assertPostgresSnapshotEquivalent(t, loaded, snapshot)

	replacement := cloneStateSnapshot(snapshot)
	replacement.Model.ModelVersion = "round-8-postgres"
	replacement.Model.RoundId = 8
	replacement.Model.CreatedAtUnix = time.Now().UTC().Unix()
	if err := store.Commit(ctx, replacement); err != nil {
		store.Close()
		t.Fatalf("overwrite PostgreSQL state: %v", err)
	}
	store.Close()

	reopened, err := NewPostgresStateStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen PostgreSQL state store: %v", err)
	}
	defer reopened.Close()
	recovered, err := reopened.Load(ctx)
	if err != nil {
		t.Fatalf("load PostgreSQL state after reconnect: %v", err)
	}
	assertPostgresSnapshotEquivalent(t, recovered, replacement)

	invalid := cloneStateSnapshot(replacement)
	invalid.Model = nil
	if err := reopened.Commit(ctx, invalid); err == nil {
		t.Fatal("invalid PostgreSQL state snapshot was committed")
	}

	if _, err := reopened.pool.Exec(ctx, `UPDATE ztfl_coordinator_state SET state_schema_version = 999 WHERE singleton_id = 1`); err != nil {
		t.Fatalf("corrupt PostgreSQL state schema version: %v", err)
	}
	if _, err := reopened.Load(ctx); err == nil || errors.Is(err, ErrStateNotFound) {
		t.Fatalf("unsupported PostgreSQL state schema error = %v, want fail-closed validation", err)
	}
}

func TestPostgresStateStoreRejectsUnknownDatabaseMigration(t *testing.T) {
	dsn := postgresTestDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetPostgresStateTables(t, ctx, dsn)

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `
		CREATE TABLE ztfl_schema_migrations (
			version INTEGER PRIMARY KEY CHECK (version > 0),
			name TEXT NOT NULL UNIQUE,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		t.Fatalf("create migration ledger: %v", err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO ztfl_schema_migrations (version, name) VALUES (999, '999_future.sql')`); err != nil {
		t.Fatalf("seed future migration: %v", err)
	}

	if store, err := NewPostgresStateStore(ctx, dsn); err == nil {
		store.Close()
		t.Fatal("PostgreSQL state store accepted an unknown database migration")
	}
}

func postgresTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(postgresTestDSNEnv)
	if dsn == "" {
		t.Skipf("%s is not configured", postgresTestDSNEnv)
	}
	return dsn
}

func resetPostgresStateTables(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect PostgreSQL for reset: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `DROP TABLE IF EXISTS ztfl_coordinator_state`); err != nil {
		t.Fatalf("drop PostgreSQL coordinator state table: %v", err)
	}
	if _, err := conn.Exec(ctx, `DROP TABLE IF EXISTS ztfl_schema_migrations`); err != nil {
		t.Fatalf("drop PostgreSQL migration ledger: %v", err)
	}
}

func assertPostgresSnapshotEquivalent(t *testing.T, got, want StateSnapshot) {
	t.Helper()
	if got.Policy != want.Policy {
		t.Fatalf("loaded policy = %#v, want %#v", got.Policy, want.Policy)
	}
	if !proto.Equal(got.Model, want.Model) {
		t.Fatalf("loaded model = %v, want %v", got.Model, want.Model)
	}
	if len(got.Pending) != len(want.Pending) || got.Pending[0].NodeID != want.Pending[0].NodeID || got.Pending[0].UpdateID != want.Pending[0].UpdateID {
		t.Fatalf("loaded pending updates = %#v, want %#v", got.Pending, want.Pending)
	}
	if len(got.Registrations) != len(want.Registrations) || got.Registrations[0].RegistrationID != want.Registrations[0].RegistrationID {
		t.Fatalf("loaded registrations = %#v, want %#v", got.Registrations, want.Registrations)
	}
	if len(got.Nonces) != len(want.Nonces) || got.Nonces[0].Key != want.Nonces[0].Key {
		t.Fatalf("loaded nonces = %#v, want %#v", got.Nonces, want.Nonces)
	}
	if len(got.RateWindows) != len(want.RateWindows) || got.RateWindows[0].Count != want.RateWindows[0].Count {
		t.Fatalf("loaded rate windows = %#v, want %#v", got.RateWindows, want.RateWindows)
	}
}
