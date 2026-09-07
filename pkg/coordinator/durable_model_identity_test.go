package coordinator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/protobuf/proto"
)

func TestDurableServiceUpgradesSchemaV2ModelIdentityExactlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coordinator-state.json")
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}
	snapshot := testStateSnapshot(t)
	snapshot.Policy.ModelID = ""
	writeRawDiskState(t, path, previousCoordinatorStateSchemaVersion, snapshot)

	if _, err := NewDurableServiceWithIdentity(
		ztsecurity.NewRegistrationStore(),
		Config{MinUpdates: 2},
		store,
		ExperimentConfig{},
		"model-v2-adopted",
	); err != nil {
		t.Fatalf("upgrade schema v2 state: %v", err)
	}

	upgraded := readRawDiskState(t, path)
	if upgraded.SchemaVersion != coordinatorStateSchemaVersion {
		t.Fatalf("upgraded schema = %d, want %d", upgraded.SchemaVersion, coordinatorStateSchemaVersion)
	}
	if upgraded.Policy.ModelID != "model-v2-adopted" {
		t.Fatalf("upgraded model id = %q", upgraded.Policy.ModelID)
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read upgraded state: %v", err)
	}
	if _, err := NewDurableServiceWithIdentity(
		ztsecurity.NewRegistrationStore(),
		Config{MinUpdates: 2},
		store,
		ExperimentConfig{},
		"different-model",
	); err == nil || !strings.Contains(err.Error(), "durable model identity") {
		t.Fatalf("model identity drift error = %v, want fail-closed identity rejection", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state after rejected restart: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("rejected model identity restart mutated durable state")
	}
}

func TestFileStateStoreRejectsSchemaV3WithoutModelIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coordinator-state.json")
	snapshot := testStateSnapshot(t)
	snapshot.Policy.ModelID = ""
	writeRawDiskState(t, path, coordinatorStateSchemaVersion, snapshot)

	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}
	if _, err := store.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "model_id") {
		t.Fatalf("schema-v3 missing model identity error = %v", err)
	}
}

func TestDurableServiceSameModelIdentityRestartSucceeds(t *testing.T) {
	store, err := NewFileStateStore(filepath.Join(t.TempDir(), "coordinator-state.json"))
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := NewDurableServiceWithIdentity(
			ztsecurity.NewRegistrationStore(),
			Config{},
			store,
			ExperimentConfig{},
			"stable-model",
		); err != nil {
			t.Fatalf("restart %d with stable model identity: %v", attempt, err)
		}
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load stable state: %v", err)
	}
	if loaded.Policy.ModelID != "stable-model" {
		t.Fatalf("persisted model id = %q, want stable-model", loaded.Policy.ModelID)
	}
}

func TestPostgresSchemaV2ModelIdentityUpgrade(t *testing.T) {
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
	if err := store.Commit(ctx, snapshot); err != nil {
		t.Fatalf("seed PostgreSQL state: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `
		UPDATE ztfl_coordinator_state
		SET state_schema_version = $1,
		    policy = policy - 'model_id'
		WHERE singleton_id = 1
	`, previousCoordinatorStateSchemaVersion); err != nil {
		t.Fatalf("downgrade PostgreSQL state fixture: %v", err)
	}

	if _, err := NewDurableServiceWithIdentity(
		ztsecurity.NewRegistrationStore(),
		Config{MinUpdates: 2},
		store,
		ExperimentConfig{},
		"postgres-adopted-model",
	); err != nil {
		t.Fatalf("upgrade PostgreSQL schema-v2 model identity: %v", err)
	}

	var schemaVersion int
	var modelID string
	if err := store.pool.QueryRow(ctx, `
		SELECT state_schema_version, policy->>'model_id'
		FROM ztfl_coordinator_state
		WHERE singleton_id = 1
	`).Scan(&schemaVersion, &modelID); err != nil {
		t.Fatalf("read upgraded PostgreSQL identity: %v", err)
	}
	if schemaVersion != coordinatorStateSchemaVersion || modelID != "postgres-adopted-model" {
		t.Fatalf("upgraded PostgreSQL identity = schema %d model %q", schemaVersion, modelID)
	}

	if _, err := NewDurableServiceWithIdentity(
		ztsecurity.NewRegistrationStore(),
		Config{MinUpdates: 2},
		store,
		ExperimentConfig{},
		"postgres-drifted-model",
	); err == nil || !strings.Contains(err.Error(), "durable model identity") {
		t.Fatalf("PostgreSQL model identity drift error = %v", err)
	}
}

func writeRawDiskState(t *testing.T, path string, schemaVersion int, snapshot StateSnapshot) {
	t.Helper()
	modelBytes, err := proto.Marshal(snapshot.Model)
	if err != nil {
		t.Fatalf("marshal model: %v", err)
	}
	encoded := diskState{
		SchemaVersion: schemaVersion,
		Policy:        snapshot.Policy,
		ModelProto:    modelBytes,
		Pending:       snapshot.Pending,
		Registrations: snapshot.Registrations,
		Nonces:        snapshot.Nonces,
		RateWindows:   snapshot.RateWindows,
	}
	data, err := json.Marshal(encoded)
	if err != nil {
		t.Fatalf("marshal raw state: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write raw state: %v", err)
	}
}

func readRawDiskState(t *testing.T, path string) diskState {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read raw state: %v", err)
	}
	var encoded diskState
	if err := json.Unmarshal(data, &encoded); err != nil {
		t.Fatalf("decode raw state: %v", err)
	}
	return encoded
}
