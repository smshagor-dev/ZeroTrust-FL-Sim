package coordinator

import (
	"context"
	"testing"
	"time"
)

func TestPostgresStateStoreCommitsEmptyCollectionsAsJSONArrays(t *testing.T) {
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
	snapshot.Pending = nil
	snapshot.Registrations = nil
	snapshot.Nonces = nil
	snapshot.RateWindows = nil
	if err := store.Commit(ctx, snapshot); err != nil {
		t.Fatalf("commit state with empty collections: %v", err)
	}

	var pendingType, registrationsType, noncesType, rateWindowsType string
	if err := store.pool.QueryRow(ctx, `
		SELECT jsonb_typeof(pending_updates), jsonb_typeof(registrations),
		       jsonb_typeof(replay_nonces), jsonb_typeof(rate_windows)
		FROM ztfl_coordinator_state
		WHERE singleton_id = 1
	`).Scan(&pendingType, &registrationsType, &noncesType, &rateWindowsType); err != nil {
		t.Fatalf("inspect persisted empty collections: %v", err)
	}
	for name, value := range map[string]string{
		"pending_updates": pendingType,
		"registrations":   registrationsType,
		"replay_nonces":   noncesType,
		"rate_windows":    rateWindowsType,
	} {
		if value != "array" {
			t.Fatalf("%s JSON type = %q, want array", name, value)
		}
	}

	loaded, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("load state with empty collections: %v", err)
	}
	if len(loaded.Pending) != 0 || len(loaded.Registrations) != 0 || len(loaded.Nonces) != 0 || len(loaded.RateWindows) != 0 {
		t.Fatalf("loaded empty collections are not empty: %#v", loaded)
	}
}
