package recovery

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	"github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/coordinator"
)

func TestRecoveryBackupDoesNotAutoMigrateSource(t *testing.T) {
	dsn := integrationEnv(t, "ZTFL_TEST_POSTGRES_DSN")
	pgDump := integrationEnv(t, "ZTFL_TEST_PG_DUMP")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	resetRecoveryDatabase(t, ctx, dsn)

	store, err := coordinator.NewPostgresStateStore(ctx, dsn)
	if err != nil {
		t.Fatalf("initialize recovery source schema: %v", err)
	}
	state := coordinator.StateSnapshot{
		Policy: coordinator.StatePolicy{
			LeaseTTL:            5 * time.Minute,
			MaxUpdateBytes:      8 << 20,
			MinUpdates:          1,
			MaxUpdatesPerMinute: 60,
			AggregationMethod:   "median",
		},
		Model: &flv1.GlobalModel{
			ModelVersion:  "bootstrap-recovery-source-schema",
			RoundId:       0,
			WeightsFormat: "application/x-npy-f32",
			CreatedAtUnix: time.Now().UTC().Unix(),
		},
	}
	if err := store.Commit(ctx, state); err != nil {
		store.Close()
		t.Fatalf("seed recovery source state: %v", err)
	}
	store.Close()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect recovery source migration fixture: %v", err)
	}
	var before int
	if err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM ztfl_schema_migrations`).Scan(&before); err != nil {
		_ = conn.Close(ctx)
		t.Fatalf("count recovery source migrations: %v", err)
	}
	if before < 2 {
		_ = conn.Close(ctx)
		t.Fatalf("recovery source migration count = %d, want at least 2", before)
	}
	if _, err := conn.Exec(ctx, `DELETE FROM ztfl_schema_migrations WHERE version = (SELECT MAX(version) FROM ztfl_schema_migrations)`); err != nil {
		_ = conn.Close(ctx)
		t.Fatalf("remove latest migration ledger row: %v", err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatalf("close recovery source migration fixture: %v", err)
	}

	output := filepath.Join(t.TempDir(), "should-not-publish")
	if _, err := Backup(ctx, BackupConfig{
		PostgresDSN: dsn,
		OutputDir:   output,
		PgDumpPath:  pgDump,
	}); err == nil {
		t.Fatal("recovery backup accepted an incomplete source migration ledger")
	}

	conn, err = pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("reconnect recovery source migration fixture: %v", err)
	}
	defer conn.Close(ctx)
	var after int
	if err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM ztfl_schema_migrations`).Scan(&after); err != nil {
		t.Fatalf("count migrations after failed recovery backup: %v", err)
	}
	if after != before-1 {
		t.Fatalf("recovery backup mutated source migration ledger: before=%d after=%d", before, after)
	}
}
