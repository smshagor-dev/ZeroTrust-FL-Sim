package recovery

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/coordinator"
)

type BackupConfig struct {
	PostgresDSN string
	Artifacts   coordinator.ModelArtifactStore
	OutputDir   string
	PgDumpPath  string
	Now         func() time.Time
}

type BackupResult struct {
	Manifest      Manifest
	PgDumpVersion string
}

type RestoreConfig struct {
	PostgresDSN      string
	Artifacts        coordinator.ModelArtifactStore
	InputDir         string
	PgRestorePath    string
	AllowDestructive bool
}

type RestoreResult struct {
	ModelVersion     string
	RoundID          uint64
	AuditHead        coordinator.RecoveryAuditHead
	PgRestoreVersion string
}

type recoveryNamespaceInspector interface {
	RecoveryNamespaceEmpty(context.Context) (bool, error)
}

func Backup(ctx context.Context, cfg BackupConfig) (BackupResult, error) {
	if strings.TrimSpace(cfg.PostgresDSN) == "" {
		return BackupResult{}, errors.New("PostgreSQL DSN is required for recovery backup")
	}
	output := filepath.Clean(strings.TrimSpace(cfg.OutputDir))
	if output == "" || output == "." {
		return BackupResult{}, errors.New("recovery backup output directory is required")
	}
	if _, err := os.Lstat(output); err == nil {
		return BackupResult{}, fmt.Errorf("recovery backup output already exists: %s", output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return BackupResult{}, fmt.Errorf("inspect recovery backup output: %w", err)
	}

	parent := filepath.Dir(output)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return BackupResult{}, fmt.Errorf("create recovery backup parent directory: %w", err)
	}
	tempDir, err := os.MkdirTemp(parent, ".ztfl-recovery-*")
	if err != nil {
		return BackupResult{}, fmt.Errorf("create temporary recovery backup directory: %w", err)
	}
	if err := os.Chmod(tempDir, 0o700); err != nil {
		_ = os.RemoveAll(tempDir)
		return BackupResult{}, fmt.Errorf("set temporary recovery directory permissions: %w", err)
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.RemoveAll(tempDir)
		}
	}()

	// Recovery backup must never mutate the source database merely by opening
	// it. Schema compatibility is checked explicitly against the embedded
	// migration ledger below.
	store, err := coordinator.OpenPostgresStateStoreForRecovery(ctx, cfg.PostgresDSN, cfg.Artifacts)
	if err != nil {
		return BackupResult{}, fmt.Errorf("open PostgreSQL state for recovery backup: %w", err)
	}
	defer store.Close()

	recoverySnapshot, err := store.BeginRecoverySnapshot(ctx)
	if err != nil {
		return BackupResult{}, err
	}
	snapshotOpen := true
	defer func() {
		if snapshotOpen {
			_ = recoverySnapshot.Close(context.Background())
		}
	}()
	metadata := recoverySnapshot.Metadata()
	if err := coordinator.ValidateRecoveryMigrationLedger(metadata.Migrations); err != nil {
		return BackupResult{}, fmt.Errorf("validate recovery source migration ledger: %w", err)
	}

	auditRecords, err := recoverySnapshot.ReadAuditEvents(ctx)
	if err != nil {
		return BackupResult{}, err
	}
	auditPath := filepath.Join(tempDir, auditExportPath)
	auditFile, err := os.OpenFile(auditPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return BackupResult{}, fmt.Errorf("create recovery audit export: %w", err)
	}
	if err := coordinator.ExportAuditNDJSON(auditFile, auditRecords); err != nil {
		_ = auditFile.Close()
		return BackupResult{}, err
	}
	if err := auditFile.Sync(); err != nil {
		_ = auditFile.Close()
		return BackupResult{}, fmt.Errorf("sync recovery audit export: %w", err)
	}
	if err := auditFile.Close(); err != nil {
		return BackupResult{}, fmt.Errorf("close recovery audit export: %w", err)
	}

	var artifactManifest *ArtifactManifest
	if metadata.Artifact != nil {
		if cfg.Artifacts == nil {
			return BackupResult{}, errors.New("recovery backup requires the configured model artifact store")
		}
		payload, err := cfg.Artifacts.Get(ctx, *metadata.Artifact)
		if err != nil {
			return BackupResult{}, fmt.Errorf("read recovery model artifact: %w", err)
		}
		digestHex := hex.EncodeToString(metadata.Artifact.SHA256)
		artifactRelative := "artifacts/sha256/" + digestHex + ".npy"
		artifactPath := filepath.Join(tempDir, filepath.FromSlash(artifactRelative))
		if err := os.MkdirAll(filepath.Dir(artifactPath), 0o700); err != nil {
			return BackupResult{}, fmt.Errorf("create recovery artifact directory: %w", err)
		}
		if err := os.WriteFile(artifactPath, payload, 0o600); err != nil {
			return BackupResult{}, fmt.Errorf("write recovery model artifact: %w", err)
		}
		artifactFile, err := DigestFile(tempDir, artifactRelative)
		if err != nil {
			return BackupResult{}, err
		}
		if artifactFile.SHA256 != digestHex || artifactFile.SizeBytes != metadata.Artifact.SizeBytes {
			return BackupResult{}, errors.New("recovery model artifact digest/size changed while building bundle")
		}
		artifactManifest = &ArtifactManifest{
			Bucket:    metadata.Artifact.Bucket,
			Key:       metadata.Artifact.Key,
			SHA256:    digestHex,
			SizeBytes: metadata.Artifact.SizeBytes,
			File:      artifactFile,
		}
	}

	dumpFile := filepath.Join(tempDir, postgresDumpPath)
	pgDumpVersion, err := runPgDump(ctx, defaultTool(cfg.PgDumpPath, "pg_dump"), cfg.PostgresDSN, recoverySnapshot.SnapshotID(), dumpFile, metadata.PostgreSQLVersionNum)
	if err != nil {
		return BackupResult{}, err
	}
	if err := os.Chmod(dumpFile, 0o600); err != nil {
		return BackupResult{}, fmt.Errorf("set PostgreSQL recovery dump permissions: %w", err)
	}
	if err := recoverySnapshot.Close(ctx); err != nil {
		return BackupResult{}, err
	}
	snapshotOpen = false

	dumpManifest, err := DigestFile(tempDir, postgresDumpPath)
	if err != nil {
		return BackupResult{}, err
	}
	auditManifest, err := DigestFile(tempDir, auditExportPath)
	if err != nil {
		return BackupResult{}, err
	}
	manifest := NewManifest(backupNow(cfg))
	manifest.Database = DatabaseManifest{
		PostgreSQLVersion:    metadata.PostgreSQLVersion,
		PostgreSQLVersionNum: metadata.PostgreSQLVersionNum,
		StateSchemaVersion:   metadata.StateSchemaVersion,
		Experiment: ExperimentManifest{
			ID:           metadata.Experiment.ID,
			ConfigSHA256: metadata.Experiment.ConfigSHA256,
			CreatedAt:    metadata.Experiment.CreatedAt,
		},
		ModelVersion: metadata.ModelVersion,
		RoundID:      metadata.RoundID,
		Dump:         dumpManifest,
	}
	for _, migration := range metadata.Migrations {
		manifest.Database.Migrations = append(manifest.Database.Migrations, MigrationManifest{Version: migration.Version, Name: migration.Name})
	}
	manifest.Artifact = artifactManifest
	manifest.Audit = AuditManifest{
		HeadSequence: metadata.AuditHead.Sequence,
		HeadHash:     metadata.AuditHead.EventHash,
		File:         auditManifest,
	}
	if err := WriteManifest(tempDir, manifest); err != nil {
		return BackupResult{}, err
	}
	if err := syncDirectory(tempDir); err != nil {
		return BackupResult{}, err
	}
	if err := os.Rename(tempDir, output); err != nil {
		return BackupResult{}, fmt.Errorf("publish recovery backup atomically: %w", err)
	}
	removeTemp = false
	if err := syncDirectory(parent); err != nil {
		return BackupResult{}, err
	}
	return BackupResult{Manifest: manifest, PgDumpVersion: pgDumpVersion}, nil
}

func Restore(ctx context.Context, cfg RestoreConfig) (RestoreResult, error) {
	if !cfg.AllowDestructive {
		return RestoreResult{}, errors.New("recovery restore requires explicit destructive-operation approval")
	}
	if strings.TrimSpace(cfg.PostgresDSN) == "" {
		return RestoreResult{}, errors.New("PostgreSQL DSN is required for recovery restore")
	}
	root := filepath.Clean(strings.TrimSpace(cfg.InputDir))
	if root == "" || root == "." {
		return RestoreResult{}, errors.New("recovery restore input directory is required")
	}
	manifest, err := LoadManifest(root)
	if err != nil {
		return RestoreResult{}, err
	}
	if err := validateManifestMigrationLedger(manifest); err != nil {
		return RestoreResult{}, err
	}
	if err := VerifyFile(root, manifest.Database.Dump); err != nil {
		return RestoreResult{}, err
	}
	if err := VerifyFile(root, manifest.Audit.File); err != nil {
		return RestoreResult{}, err
	}

	auditPath, err := safeBundleFile(root, manifest.Audit.File.Path)
	if err != nil {
		return RestoreResult{}, err
	}
	auditFile, err := os.Open(auditPath)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("open recovery audit export: %w", err)
	}
	auditRecords, decodeErr := coordinator.DecodeAuditNDJSON(auditFile, 0)
	closeErr := auditFile.Close()
	if decodeErr != nil {
		return RestoreResult{}, decodeErr
	}
	if closeErr != nil {
		return RestoreResult{}, fmt.Errorf("close recovery audit export: %w", closeErr)
	}
	if int64(len(auditRecords)) != manifest.Audit.HeadSequence {
		return RestoreResult{}, fmt.Errorf("recovery audit export contains %d records, manifest declares %d", len(auditRecords), manifest.Audit.HeadSequence)
	}
	if len(auditRecords) > 0 && auditRecords[len(auditRecords)-1].EventHash != manifest.Audit.HeadHash {
		return RestoreResult{}, errors.New("recovery audit export head hash disagrees with manifest")
	}

	// Validate every target before writing either authority. This prevents a
	// dirty PostgreSQL target from causing a partial S3 restore, and prevents a
	// dirty S3 namespace from being mixed with the recovered database.
	if err := ensureCleanPostgresTarget(ctx, cfg.PostgresDSN, manifest.Database.PostgreSQLVersionNum); err != nil {
		return RestoreResult{}, err
	}
	if manifest.Artifact != nil {
		if cfg.Artifacts == nil {
			return RestoreResult{}, errors.New("recovery restore requires the configured model artifact store")
		}
		if err := ensureCleanArtifactTarget(ctx, cfg.Artifacts); err != nil {
			return RestoreResult{}, err
		}
		if err := VerifyFile(root, manifest.Artifact.File); err != nil {
			return RestoreResult{}, err
		}
		artifactPath, err := safeBundleFile(root, manifest.Artifact.File.Path)
		if err != nil {
			return RestoreResult{}, err
		}
		payload, err := readBoundedFile(artifactPath, manifest.Artifact.SizeBytes)
		if err != nil {
			return RestoreResult{}, fmt.Errorf("read recovery model artifact: %w", err)
		}
		restoredRef, err := cfg.Artifacts.Put(ctx, payload)
		if err != nil {
			return RestoreResult{}, fmt.Errorf("restore model artifact: %w", err)
		}
		if !artifactRefMatchesManifest(restoredRef, *manifest.Artifact) {
			return RestoreResult{}, errors.New("restored model artifact reference does not match recovery manifest; bucket/prefix configuration differs")
		}
	}

	dumpPath, err := safeBundleFile(root, manifest.Database.Dump.Path)
	if err != nil {
		return RestoreResult{}, err
	}
	pgRestoreVersion, err := runPgRestore(ctx, defaultTool(cfg.PgRestorePath, "pg_restore"), cfg.PostgresDSN, dumpPath, manifest.Database.PostgreSQLVersionNum)
	if err != nil {
		return RestoreResult{}, err
	}

	// Verification is intentionally no-migrate. A restore must reproduce the
	// exact schema ledger in the manifest rather than succeeding because the
	// current binary silently upgraded it after pg_restore.
	store, err := coordinator.OpenPostgresStateStoreForRecovery(ctx, cfg.PostgresDSN, cfg.Artifacts)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("open restored coordinator state: %w", err)
	}
	defer store.Close()
	state, err := store.Load(ctx)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("validate restored coordinator state: %w", err)
	}
	if !experimentMatchesManifest(state.Policy.Experiment, manifest.Database.Experiment) {
		return RestoreResult{}, errors.New("restored coordinator experiment metadata disagrees with recovery manifest")
	}
	if state.Model.GetModelVersion() != manifest.Database.ModelVersion || state.Model.GetRoundId() != manifest.Database.RoundID {
		return RestoreResult{}, errors.New("restored coordinator model version/round disagrees with recovery manifest")
	}

	verification, err := store.BeginRecoverySnapshot(ctx)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("verify restored recovery metadata: %w", err)
	}
	metadata := verification.Metadata()
	if err := coordinator.ValidateRecoveryMigrationLedger(metadata.Migrations); err != nil {
		_ = verification.Close(context.Background())
		return RestoreResult{}, fmt.Errorf("validate restored migration ledger: %w", err)
	}
	restoredAudit, auditErr := verification.ReadAuditEvents(ctx)
	closeVerificationErr := verification.Close(context.Background())
	if auditErr != nil {
		return RestoreResult{}, auditErr
	}
	if closeVerificationErr != nil {
		return RestoreResult{}, closeVerificationErr
	}
	if err := compareRecoveryMetadata(manifest, metadata); err != nil {
		return RestoreResult{}, err
	}
	if int64(len(restoredAudit)) != manifest.Audit.HeadSequence {
		return RestoreResult{}, errors.New("restored PostgreSQL audit chain length disagrees with recovery manifest")
	}
	if len(restoredAudit) > 0 && restoredAudit[len(restoredAudit)-1].EventHash != manifest.Audit.HeadHash {
		return RestoreResult{}, errors.New("restored PostgreSQL audit chain head disagrees with recovery manifest")
	}

	return RestoreResult{
		ModelVersion:     state.Model.GetModelVersion(),
		RoundID:          state.Model.GetRoundId(),
		AuditHead:        metadata.AuditHead,
		PgRestoreVersion: pgRestoreVersion,
	}, nil
}

func validateManifestMigrationLedger(manifest Manifest) error {
	migrations := make([]coordinator.RecoveryMigration, len(manifest.Database.Migrations))
	for index, migration := range manifest.Database.Migrations {
		migrations[index] = coordinator.RecoveryMigration{Version: migration.Version, Name: migration.Name}
	}
	if err := coordinator.ValidateRecoveryMigrationLedger(migrations); err != nil {
		return fmt.Errorf("validate recovery manifest migration ledger: %w", err)
	}
	return nil
}

func ensureCleanArtifactTarget(ctx context.Context, artifacts coordinator.ModelArtifactStore) error {
	inspector, ok := artifacts.(recoveryNamespaceInspector)
	if !ok {
		return errors.New("recovery artifact store cannot prove that its target namespace is empty")
	}
	empty, err := inspector.RecoveryNamespaceEmpty(ctx)
	if err != nil {
		return err
	}
	if !empty {
		return errors.New("recovery S3 target namespace is not clean")
	}
	return nil
}

func artifactRefMatchesManifest(ref coordinator.ModelArtifactRef, manifest ArtifactManifest) bool {
	digest, err := hex.DecodeString(manifest.SHA256)
	if err != nil {
		return false
	}
	return ref.Bucket == manifest.Bucket && ref.Key == manifest.Key && ref.SizeBytes == manifest.SizeBytes && bytes.Equal(ref.SHA256, digest)
}

func experimentMatchesManifest(metadata coordinator.ExperimentMetadata, manifest ExperimentManifest) bool {
	return metadata.ID == manifest.ID && metadata.ConfigSHA256 == manifest.ConfigSHA256 && metadata.CreatedAt.Equal(manifest.CreatedAt)
}

func compareRecoveryMetadata(manifest Manifest, metadata coordinator.RecoveryMetadata) error {
	if metadata.StateSchemaVersion != manifest.Database.StateSchemaVersion || metadata.ModelVersion != manifest.Database.ModelVersion || metadata.RoundID != manifest.Database.RoundID {
		return errors.New("restored coordinator recovery metadata disagrees with manifest")
	}
	if !experimentMatchesManifest(metadata.Experiment, manifest.Database.Experiment) {
		return errors.New("restored coordinator experiment recovery metadata disagrees with manifest")
	}
	if len(metadata.Migrations) != len(manifest.Database.Migrations) {
		return errors.New("restored PostgreSQL migration ledger length disagrees with manifest")
	}
	for index := range metadata.Migrations {
		if metadata.Migrations[index].Version != manifest.Database.Migrations[index].Version || metadata.Migrations[index].Name != manifest.Database.Migrations[index].Name {
			return fmt.Errorf("restored PostgreSQL migration %d disagrees with manifest", index)
		}
	}
	if metadata.AuditHead.Sequence != manifest.Audit.HeadSequence || metadata.AuditHead.EventHash != manifest.Audit.HeadHash {
		return errors.New("restored PostgreSQL audit head disagrees with manifest")
	}
	if manifest.Artifact == nil {
		if metadata.Artifact != nil {
			return errors.New("restored coordinator unexpectedly references a model artifact")
		}
		return nil
	}
	if metadata.Artifact == nil || !artifactRefMatchesManifest(*metadata.Artifact, *manifest.Artifact) {
		return errors.New("restored coordinator artifact reference disagrees with manifest")
	}
	return nil
}

func backupNow(cfg BackupConfig) time.Time {
	if cfg.Now != nil {
		return cfg.Now().UTC()
	}
	return time.Now().UTC()
}

func defaultTool(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open recovery directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync recovery directory: %w", err)
	}
	return nil
}
