package coordinator

import (
	"context"
	"crypto/sha256"
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
	if !proto.Equal(loaded.Model, snapshot.Model) {
		t.Fatalf("loaded model = %v, want %v", loaded.Model, snapshot.Model)
	}
	if len(loaded.Pending) != 1 || loaded.Pending[0].NodeID != "worker-a" || loaded.Pending[0].Values[1] != -0.25 {
		t.Fatalf("unexpected pending updates: %#v", loaded.Pending)
	}
	if len(loaded.Registrations) != 1 || loaded.Registrations[0].RegistrationID != "registration-a" {
		t.Fatalf("unexpected registrations: %#v", loaded.Registrations)
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

func TestDurableServiceRecoversModelPendingAndRegistrationState(t *testing.T) {
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
}

func TestDurableServiceFailsClosedOnInvalidState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coordinator-state.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":999,"model_proto":"AA==","pending_updates":[],"registrations":[]}`), 0o600); err != nil {
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

func testStateSnapshot(t *testing.T) StateSnapshot {
	t.Helper()
	payload, err := encodeNPYFloat32([]float32{1.5, -2.0})
	if err != nil {
		t.Fatalf("encode model: %v", err)
	}
	digest := sha256.Sum256(payload)
	return StateSnapshot{
		Model: &flv1.GlobalModel{
			ModelVersion:   "round-7-test",
			RoundId:        7,
			WeightsPayload: payload,
			WeightsFormat:  networkWeightsFormat,
			Sha256:         digest[:],
			CreatedAtUnix:  time.Now().UTC().Unix(),
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
				ExpiresAt:              time.Now().UTC().Add(time.Hour),
			},
		},
	}
}
