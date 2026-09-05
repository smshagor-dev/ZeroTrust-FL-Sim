package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/protobuf/proto"
)

func TestFileStateStoreRoundTrip(t *testing.T) {
	store, err := NewFileStateStore(filepath.Join(t.TempDir(), "coordinator-state.json"))
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}
	snapshot := testStateSnapshot(t)
	if err := store.Commit(context.Background(), snapshot); err != nil {
		t.Fatalf("commit state: %v", err)
	}

	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if loaded.Policy != snapshot.Policy {
		t.Fatalf("loaded policy = %#v, want %#v", loaded.Policy, snapshot.Policy)
	}
	if !proto.Equal(loaded.Model, snapshot.Model) {
		t.Fatalf("loaded model = %v, want %v", loaded.Model, snapshot.Model)
	}
	if len(loaded.Pending) != 1 || loaded.Pending[0].NodeID != "worker-a" || loaded.Pending[0].Values[1] != -0.25 {
		t.Fatalf("unexpected pending updates: %#v", loaded.Pending)
	}
	if len(loaded.Registrations) != 1 || loaded.Registrations[0].RegistrationID != "registration-a" {
		t.Fatalf("unexpected registrations: %#v", loaded.Registrations)
	}
	if len(loaded.Nonces) != 1 || loaded.Nonces[0].Key != "worker-a:00112233445566778899aabbccddeeff" {
		t.Fatalf("unexpected replay nonces: %#v", loaded.Nonces)
	}
	if len(loaded.RateWindows) != 1 || loaded.RateWindows[0].Count != 2 {
		t.Fatalf("unexpected rate windows: %#v", loaded.RateWindows)
	}

	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("state file permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestFileStateStoreMissingState(t *testing.T) {
	store, err := NewFileStateStore(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("load missing state error = %v, want ErrStateNotFound", err)
	}
}

func TestFileStateStoreRejectsCorruptState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coordinator-state.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"unexpected":true}`), 0o600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}
	if _, err := store.Load(context.Background()); err == nil || errors.Is(err, ErrStateNotFound) {
		t.Fatalf("corrupt state error = %v, want validation failure", err)
	}
}

func TestFileStateStoreRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows runners")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "state.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	store, err := NewFileStateStore(link)
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}
	if _, err := store.Load(context.Background()); err == nil {
		t.Fatal("symlink state file was accepted")
	}
}

func TestDurableServiceRecoversModelPendingRegistrationAndReplayState(t *testing.T) {
	store, err := NewFileStateStore(filepath.Join(t.TempDir(), "coordinator-state.json"))
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}
	snapshot := testStateSnapshot(t)
	if err := store.Commit(context.Background(), snapshot); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	registry := ztsecurity.NewRegistrationStore()
	service, err := NewDurableService(registry, Config{MinUpdates: 2}, store)
	if err != nil {
		t.Fatalf("create durable service: %v", err)
	}
	model := service.service.currentModel()
	if model.GetModelVersion() != snapshot.Model.GetModelVersion() || model.GetRoundId() != snapshot.Model.GetRoundId() {
		t.Fatalf("recovered model = version %q round %d", model.GetModelVersion(), model.GetRoundId())
	}
	if len(service.service.pending) != 1 || service.service.pending["worker-a"].UpdateID != "update-a" {
		t.Fatalf("recovered pending state = %#v", service.service.pending)
	}
	registrations := registry.Snapshot()
	if len(registrations) != 1 || registrations[0].NodeID != "worker-a" {
		t.Fatalf("recovered registrations = %#v", registrations)
	}
	if len(service.service.nonces) != 1 {
		t.Fatalf("recovered nonce cache = %#v", service.service.nonces)
	}
	if service.service.rates["worker-a"].Count != 2 {
		t.Fatalf("recovered rate windows = %#v", service.service.rates)
	}
}

func TestDurableServiceInitializesMissingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "coordinator-state.json")
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}
	if _, err := NewDurableService(ztsecurity.NewRegistrationStore(), Config{}, store); err != nil {
		t.Fatalf("initialize durable service: %v", err)
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load initialized state: %v", err)
	}
	if loaded.Model.GetModelVersion() != "bootstrap" || loaded.Model.GetRoundId() != 0 {
		t.Fatalf("initialized model = %q round %d", loaded.Model.GetModelVersion(), loaded.Model.GetRoundId())
	}
	if loaded.Policy.MinUpdates != 1 || loaded.Policy.AggregationMethod != "median" {
		t.Fatalf("initialized policy = %#v", loaded.Policy)
	}
	if loaded.Policy.Experiment.ID != defaultExperimentID || loaded.Policy.Experiment.ConfigSHA256 == "" || loaded.Policy.Experiment.CreatedAt.IsZero() {
		t.Fatalf("initialized experiment metadata = %#v", loaded.Policy.Experiment)
	}
}

func TestDurableServiceFailsClosedOnInvalidState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coordinator-state.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":999}`), 0o600); err != nil {
		t.Fatalf("write invalid state: %v", err)
	}
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}
	if _, err := NewDurableService(ztsecurity.NewRegistrationStore(), Config{}, store); err == nil {
		t.Fatal("durable service accepted unsupported state schema")
	}
}

func TestDurableServiceRejectsPolicyDrift(t *testing.T) {
	store, err := NewFileStateStore(filepath.Join(t.TempDir(), "coordinator-state.json"))
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}
	if err := store.Commit(context.Background(), testStateSnapshot(t)); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	if _, err := NewDurableService(ztsecurity.NewRegistrationStore(), Config{MinUpdates: 3}, store); err == nil {
		t.Fatal("durable service accepted quorum-policy drift")
	}
}

func TestDurableServiceRejectsExperimentIdentityDrift(t *testing.T) {
	store, err := NewFileStateStore(filepath.Join(t.TempDir(), "coordinator-state.json"))
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}
	digest := "1111111111111111111111111111111111111111111111111111111111111111"
	if _, err := NewDurableServiceWithExperiment(ztsecurity.NewRegistrationStore(), Config{}, store, ExperimentConfig{ID: "experiment-a", ConfigSHA256: digest}); err != nil {
		t.Fatalf("initialize experiment: %v", err)
	}
	if _, err := NewDurableServiceWithExperiment(ztsecurity.NewRegistrationStore(), Config{}, store, ExperimentConfig{ID: "experiment-b", ConfigSHA256: digest}); err == nil {
		t.Fatal("durable service accepted experiment identity drift")
	}
}

func TestDurableServicePreservesExperimentCreationTime(t *testing.T) {
	store, err := NewFileStateStore(filepath.Join(t.TempDir(), "coordinator-state.json"))
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}
	config := ExperimentConfig{
		ID:           "experiment-stable-time",
		ConfigSHA256: "2222222222222222222222222222222222222222222222222222222222222222",
	}
	if _, err := NewDurableServiceWithExperiment(ztsecurity.NewRegistrationStore(), Config{}, store, config); err != nil {
		t.Fatalf("initialize experiment: %v", err)
	}
	first, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load first state: %v", err)
	}
	if _, err := NewDurableServiceWithExperiment(ztsecurity.NewRegistrationStore(), Config{}, store, config); err != nil {
		t.Fatalf("recover experiment: %v", err)
	}
	second, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load recovered state: %v", err)
	}
	if !second.Policy.Experiment.CreatedAt.Equal(first.Policy.Experiment.CreatedAt) {
		t.Fatalf("recovered created_at = %v, want %v", second.Policy.Experiment.CreatedAt, first.Policy.Experiment.CreatedAt)
	}
}

func TestDurableServiceUpgradesLegacyV1ExperimentIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coordinator-state.json")
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}
	snapshot := testStateSnapshot(t)
	snapshot.Policy.Experiment = ExperimentMetadata{}
	modelBytes, err := proto.Marshal(snapshot.Model)
	if err != nil {
		t.Fatalf("marshal legacy model: %v", err)
	}
	legacy := diskState{
		SchemaVersion: legacyCoordinatorStateSchemaVersion,
		Policy:        snapshot.Policy,
		ModelProto:    modelBytes,
		Pending:       snapshot.Pending,
		Registrations: snapshot.Registrations,
		Nonces:        snapshot.Nonces,
		RateWindows:   snapshot.RateWindows,
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy state: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write legacy state: %v", err)
	}

	experimentConfig := ExperimentConfig{
		ID:           "adopted-v1-experiment",
		ConfigSHA256: "3333333333333333333333333333333333333333333333333333333333333333",
	}
	if _, err := NewDurableServiceWithExperiment(ztsecurity.NewRegistrationStore(), Config{MinUpdates: 2}, store, experimentConfig); err != nil {
		t.Fatalf("upgrade legacy state: %v", err)
	}
	upgradedData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read upgraded state: %v", err)
	}
	var upgraded diskState
	if err := json.Unmarshal(upgradedData, &upgraded); err != nil {
		t.Fatalf("decode upgraded state: %v", err)
	}
	if upgraded.SchemaVersion != coordinatorStateSchemaVersion {
		t.Fatalf("upgraded schema version = %d, want %d", upgraded.SchemaVersion, coordinatorStateSchemaVersion)
	}
	if upgraded.Policy.Experiment.ID != experimentConfig.ID || upgraded.Policy.Experiment.ConfigSHA256 != experimentConfig.ConfigSHA256 {
		t.Fatalf("upgraded experiment metadata = %#v", upgraded.Policy.Experiment)
	}
}

func testStateSnapshot(t *testing.T) StateSnapshot {
	t.Helper()
	payload, err := encodeNPYFloat32([]float32{1.5, -2.0})
	if err != nil {
		t.Fatalf("encode model: %v", err)
	}
	digest := sha256.Sum256(payload)
	now := time.Now().UTC()
	policy := StatePolicy{
		LeaseTTL:            5 * time.Minute,
		MaxUpdateBytes:      defaultMaxUpdateBytes,
		MinUpdates:          2,
		MaxUpdatesPerMinute: defaultMaxUpdatesPerMinute,
		AggregationMethod:   "median",
	}
	experiment, err := newExperimentMetadata(ExperimentConfig{}, policy, now)
	if err != nil {
		t.Fatalf("create experiment metadata: %v", err)
	}
	policy.Experiment = experiment
	return StateSnapshot{
		Policy: policy,
		Model: &flv1.GlobalModel{
			ModelVersion:   "round-7-test",
			RoundId:        7,
			WeightsPayload: payload,
			WeightsFormat:  networkWeightsFormat,
			Sha256:         digest[:],
			CreatedAtUnix:  now.Unix(),
		},
		Pending: []PersistedUpdate{
			{
				NodeID:      "worker-a",
				UpdateID:    "update-a",
				Values:      []float32{0.5, -0.25},
				SampleCount: 64,
			},
		},
		Registrations: []ztsecurity.Registration{
			{
				NodeID:                 "worker-a",
				Role:                   "edge-worker",
				CertificateFingerprint: "sha256:test-worker-a",
				RegistrationID:         "registration-a",
				ExpiresAt:              now.Add(time.Hour),
			},
		},
		Nonces: []PersistedNonce{
			{Key: "worker-a:00112233445566778899aabbccddeeff", SeenAt: now},
		},
		RateWindows: []PersistedRateWindow{
			{NodeID: "worker-a", StartedAt: now, Count: 2},
		},
	}
}
