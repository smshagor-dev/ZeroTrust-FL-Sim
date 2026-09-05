package coordinator

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDisasterRecoveryManifestDeterministicAndPathSafe(t *testing.T) {
	dump := []byte("postgres-custom-dump")
	audit := []byte("{\"audit\":true}\n")
	dumpFile, err := NewDisasterRecoveryFile("postgres.dump", dump)
	if err != nil {
		t.Fatal(err)
	}
	auditFile, err := NewDisasterRecoveryFile("audit.ndjson", audit)
	if err != nil {
		t.Fatal(err)
	}
	artifactDigest := sha256.Sum256([]byte("model"))
	manifest := DisasterRecoveryManifest{
		SchemaVersion:                 DisasterRecoveryManifestSchemaVersion,
		CreatedAt:                     time.Date(2026, 9, 5, 12, 0, 0, 123456000, time.UTC),
		CoordinatorStateSchemaVersion: coordinatorStateSchemaVersion,
		PostgreSQLSnapshotID:          "00000003-0000001A-1",
		PostgreSQLServerVersion:       "18.6",
		PostgreSQLMigrations: []DisasterRecoveryMigration{
			{Version: 3, Name: "003_audit_events.sql"},
			{Version: 1, Name: "001_coordinator_state.sql"},
			{Version: 2, Name: "002_model_artifacts.sql"},
		},
		PostgreSQLDump:        dumpFile,
		AuditExport:           auditFile,
		AuditTerminalSequence: 0,
		ModelArtifacts: []DisasterRecoveryArtifact{
			{
				Bucket:    "ztfl-model-artifacts",
				Key:       "models/sha256/" + hex.EncodeToString(artifactDigest[:]) + ".npy",
				Path:      "artifacts/" + hex.EncodeToString(artifactDigest[:]) + ".npy",
				SHA256:    hex.EncodeToString(artifactDigest[:]),
				SizeBytes: 5,
			},
		},
	}

	first, err := EncodeDisasterRecoveryManifest(manifest)
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	second, err := EncodeDisasterRecoveryManifest(manifest)
	if err != nil {
		t.Fatalf("encode manifest twice: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("manifest encoding is not deterministic")
	}
	decoded, err := DecodeDisasterRecoveryManifest(first)
	if err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if decoded.PostgreSQLMigrations[0].Version != 1 || decoded.PostgreSQLMigrations[2].Version != 3 {
		t.Fatalf("migrations were not canonicalized: %#v", decoded.PostgreSQLMigrations)
	}

	bad := manifest
	bad.PostgreSQLDump.Path = "../postgres.dump"
	if _, err := EncodeDisasterRecoveryManifest(bad); err == nil {
		t.Fatal("parent-traversing disaster-recovery path was accepted")
	}
	bad = manifest
	bad.ModelArtifacts[0].Path = "/tmp/model.npy"
	if _, err := EncodeDisasterRecoveryManifest(bad); err == nil {
		t.Fatal("absolute artifact path was accepted")
	}
}

func TestVerifyDisasterRecoveryBundleDetectsCorruptionAndSymlink(t *testing.T) {
	root := t.TempDir()
	dump := []byte("postgres-custom-dump")
	audit := []byte("{\"audit\":true}\n")
	artifact := []byte("model")
	for name, data := range map[string][]byte{
		"postgres.dump":  dump,
		"audit.ndjson":   audit,
		"artifacts/a.npy": artifact,
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dumpFile, _ := NewDisasterRecoveryFile("postgres.dump", dump)
	auditFile, _ := NewDisasterRecoveryFile("audit.ndjson", audit)
	artifactDigest := sha256.Sum256(artifact)
	manifest := DisasterRecoveryManifest{
		SchemaVersion:                 DisasterRecoveryManifestSchemaVersion,
		CreatedAt:                     time.Now().UTC().Truncate(time.Microsecond),
		CoordinatorStateSchemaVersion: coordinatorStateSchemaVersion,
		PostgreSQLServerVersion:       "18.6",
		PostgreSQLMigrations:          []DisasterRecoveryMigration{{Version: 1, Name: "001.sql"}},
		PostgreSQLDump:                dumpFile,
		AuditExport:                   auditFile,
		ModelArtifacts: []DisasterRecoveryArtifact{{
			Bucket: "bucket", Key: "models/a.npy", Path: "artifacts/a.npy",
			SHA256: hex.EncodeToString(artifactDigest[:]), SizeBytes: int64(len(artifact)),
		}},
	}
	if err := VerifyDisasterRecoveryBundle(root, manifest); err != nil {
		t.Fatalf("verify valid bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "artifacts", "a.npy"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDisasterRecoveryBundle(root, manifest); err == nil || !strings.Contains(err.Error(), "digest") && !strings.Contains(err.Error(), "size") {
		t.Fatalf("corrupt artifact error = %v", err)
	}

	if err := os.Remove(filepath.Join(root, "postgres.dump")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "audit.ndjson"), filepath.Join(root, "postgres.dump")); err == nil {
		if err := VerifyDisasterRecoveryBundle(root, manifest); err == nil {
			t.Fatal("symlinked dump was accepted")
		}
	}
}

func TestDecodeDisasterRecoveryManifestRejectsUnknownFields(t *testing.T) {
	data := []byte(`{"schema_version":1,"unexpected":true}`)
	if _, err := DecodeDisasterRecoveryManifest(data); err == nil {
		t.Fatal("manifest with unknown field was accepted")
	}
}
