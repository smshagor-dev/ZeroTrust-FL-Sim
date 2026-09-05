package recovery

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestManifestRoundTripAndFileVerification(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, postgresDumpPath), []byte("postgres-dump-fixture"), 0o600); err != nil {
		t.Fatalf("write dump fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, auditExportPath), []byte(""), 0o600); err != nil {
		t.Fatalf("write audit fixture: %v", err)
	}
	artifactDigest := "5c6fd60a6ad0ce3fffdf2f2c61fbf1e9677f780c64a1ee33563bb2a40f29ef80"
	artifactRelative := "artifacts/sha256/" + artifactDigest + ".npy"
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, artifactRelative)), 0o700); err != nil {
		t.Fatalf("create artifact fixture directory: %v", err)
	}
	artifactPayload := []byte("artifact-payload")
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(artifactRelative)), artifactPayload, 0o600); err != nil {
		t.Fatalf("write artifact fixture: %v", err)
	}

	dump, err := DigestFile(root, postgresDumpPath)
	if err != nil {
		t.Fatalf("digest dump fixture: %v", err)
	}
	audit, err := DigestFile(root, auditExportPath)
	if err != nil {
		t.Fatalf("digest audit fixture: %v", err)
	}
	artifact, err := DigestFile(root, artifactRelative)
	if err != nil {
		t.Fatalf("digest artifact fixture: %v", err)
	}
	if artifact.SHA256 != artifactDigest || artifact.SizeBytes != int64(len(artifactPayload)) {
		t.Fatalf("artifact digest fixture = %#v", artifact)
	}

	manifest := NewManifest(time.Date(2026, 9, 4, 20, 5, 0, 123456000, time.UTC))
	manifest.Database = DatabaseManifest{
		PostgreSQLVersion:    "18.6",
		PostgreSQLVersionNum: 180006,
		StateSchemaVersion:   2,
		Experiment:           testExperimentManifest(),
		ModelVersion:         "round-7-test",
		RoundID:              7,
		Migrations: []MigrationManifest{
			{Version: 1, Name: "001_coordinator_state.sql"},
			{Version: 2, Name: "002_model_artifacts.sql"},
			{Version: 3, Name: "003_audit_events.sql"},
		},
		Dump: dump,
	}
	manifest.Artifact = &ArtifactManifest{
		Bucket:    "ztfl-model-artifacts",
		Key:       "models/sha256/" + artifactDigest + ".npy",
		SHA256:    artifactDigest,
		SizeBytes: artifact.SizeBytes,
		File:      artifact,
	}
	manifest.Audit = AuditManifest{File: audit}

	if err := WriteManifest(root, manifest); err != nil {
		t.Fatalf("write recovery manifest: %v", err)
	}
	loaded, err := LoadManifest(root)
	if err != nil {
		t.Fatalf("load recovery manifest: %v", err)
	}
	if loaded.Database.ModelVersion != manifest.Database.ModelVersion || loaded.Database.Experiment != manifest.Database.Experiment || loaded.Artifact == nil || loaded.Artifact.Key != manifest.Artifact.Key {
		t.Fatalf("loaded recovery manifest = %#v", loaded)
	}
	if err := VerifyFile(root, loaded.Database.Dump); err != nil {
		t.Fatalf("verify dump file: %v", err)
	}
	if err := VerifyFile(root, loaded.Artifact.File); err != nil {
		t.Fatalf("verify artifact file: %v", err)
	}
}

func TestManifestChecksumAndBundleFileTamperingFailClosed(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, postgresDumpPath), []byte("dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, auditExportPath), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dump, _ := DigestFile(root, postgresDumpPath)
	audit, _ := DigestFile(root, auditExportPath)
	manifest := NewManifest(time.Now().UTC())
	manifest.Database = DatabaseManifest{
		PostgreSQLVersion:    "18.6",
		PostgreSQLVersionNum: 180006,
		StateSchemaVersion:   2,
		Experiment:           testExperimentManifest(),
		ModelVersion:         "bootstrap",
		Migrations:           []MigrationManifest{{Version: 1, Name: "001_coordinator_state.sql"}},
		Dump:                 dump,
	}
	manifest.Audit = AuditManifest{File: audit}
	if err := WriteManifest(root, manifest); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(root, manifestFileName)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, append(data, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(root); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("tampered manifest error = %v, want checksum failure", err)
	}

	if err := WriteManifest(root, manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, postgresDumpPath), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(root, manifest.Database.Dump); err == nil {
		t.Fatal("tampered PostgreSQL dump passed bundle verification")
	}
}

func TestManifestRejectsInvalidExperimentMetadata(t *testing.T) {
	manifest := Manifest{
		SchemaVersion: BundleSchemaVersion,
		CreatedAt:     time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC),
		Database: DatabaseManifest{
			PostgreSQLVersion:    "18.6",
			PostgreSQLVersionNum: 180006,
			StateSchemaVersion:   2,
			Experiment: ExperimentManifest{
				ID:           "experiment-a",
				ConfigSHA256: "not-a-digest",
				CreatedAt:    time.Date(2026, 9, 5, 9, 0, 0, 0, time.UTC),
			},
			ModelVersion: "bootstrap",
			Migrations:   []MigrationManifest{{Version: 1, Name: "001_coordinator_state.sql"}},
			Dump: FileManifest{
				Path:      postgresDumpPath,
				SHA256:    strings.Repeat("0", 64),
				SizeBytes: 1,
			},
		},
		Audit: AuditManifest{File: FileManifest{Path: auditExportPath, SHA256: strings.Repeat("0", 64)}},
	}
	if err := manifest.Validate(); err == nil || !strings.Contains(err.Error(), "experiment") {
		t.Fatalf("invalid experiment manifest error = %v", err)
	}
}

func TestManifestRejectsTraversalAndSymlinkBundleFiles(t *testing.T) {
	bad := FileManifest{Path: "../postgres.dump", SHA256: strings.Repeat("00", 32), SizeBytes: 1}
	if err := validateFileManifest(bad, postgresDumpPath, false); err == nil {
		t.Fatal("path traversal recovery file was accepted")
	}
	if runtime.GOOS == "windows" {
		return
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, postgresDumpPath)); err != nil {
		t.Fatal(err)
	}
	if _, err := DigestFile(root, postgresDumpPath); err == nil {
		t.Fatal("symlinked recovery bundle file was accepted")
	}
}

func testExperimentManifest() ExperimentManifest {
	return ExperimentManifest{
		ID:           "experiment-test",
		ConfigSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CreatedAt:    time.Date(2026, 9, 4, 19, 0, 0, 123456000, time.UTC),
	}
}
