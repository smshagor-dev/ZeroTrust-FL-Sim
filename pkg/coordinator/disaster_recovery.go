package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	DisasterRecoveryManifestSchemaVersion = 1
	maxDisasterRecoveryManifestBytes      = 4 << 20
)

type DisasterRecoveryFile struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type DisasterRecoveryMigration struct {
	Version int    `json:"version"`
	Name    string `json:"name"`
}

type DisasterRecoveryArtifact struct {
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type DisasterRecoveryManifest struct {
	SchemaVersion                 int                         `json:"schema_version"`
	CreatedAt                     time.Time                   `json:"created_at"`
	CoordinatorStateSchemaVersion int                         `json:"coordinator_state_schema_version"`
	PostgreSQLSnapshotID          string                      `json:"postgresql_snapshot_id,omitempty"`
	PostgreSQLServerVersion       string                      `json:"postgresql_server_version"`
	PostgreSQLMigrations          []DisasterRecoveryMigration `json:"postgresql_migrations"`
	PostgreSQLDump                DisasterRecoveryFile        `json:"postgresql_dump"`
	AuditExport                   DisasterRecoveryFile        `json:"audit_export"`
	AuditTerminalSequence         int64                       `json:"audit_terminal_sequence"`
	AuditTerminalHash             string                      `json:"audit_terminal_hash,omitempty"`
	ModelArtifacts                []DisasterRecoveryArtifact  `json:"model_artifacts"`
}

type DisasterRecoverySnapshot struct {
	tx                  pgx.Tx
	SnapshotID          string
	PostgreSQLVersion   string
	Migrations          []DisasterRecoveryMigration
	StateSchemaVersion  int
	ArtifactRef         *ModelArtifactRef
	AuditRecords        []AuditRecord
}

func (s *PostgresStateStore) BeginDisasterRecoverySnapshot(ctx context.Context) (*DisasterRecoverySnapshot, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("PostgreSQL state store is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("begin disaster-recovery snapshot transaction: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback(context.Background())
		}
	}()

	var snapshotID, serverVersion string
	if err := tx.QueryRow(ctx, `SELECT pg_export_snapshot(), current_setting('server_version')`).Scan(&snapshotID, &serverVersion); err != nil {
		return nil, fmt.Errorf("export PostgreSQL disaster-recovery snapshot: %w", err)
	}

	migrationRows, err := tx.Query(ctx, `SELECT version, name FROM ztfl_schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("read disaster-recovery migration ledger: %w", err)
	}
	migrations := make([]DisasterRecoveryMigration, 0)
	for migrationRows.Next() {
		var migration DisasterRecoveryMigration
		if err := migrationRows.Scan(&migration.Version, &migration.Name); err != nil {
			migrationRows.Close()
			return nil, fmt.Errorf("scan disaster-recovery migration ledger: %w", err)
		}
		migrations = append(migrations, migration)
	}
	if err := migrationRows.Err(); err != nil {
		migrationRows.Close()
		return nil, fmt.Errorf("iterate disaster-recovery migration ledger: %w", err)
	}
	migrationRows.Close()

	var (
		stateSchemaVersion int
		artifactBucket     pgtype.Text
		artifactKey        pgtype.Text
		artifactSHA256     []byte
		artifactSize       pgtype.Int8
	)
	if err := tx.QueryRow(ctx, `
		SELECT state_schema_version, model_artifact_bucket, model_artifact_key,
		       model_artifact_sha256, model_artifact_size_bytes
		FROM ztfl_coordinator_state
		WHERE singleton_id = 1
	`).Scan(&stateSchemaVersion, &artifactBucket, &artifactKey, &artifactSHA256, &artifactSize); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("disaster-recovery backup requires initialized coordinator state")
		}
		return nil, fmt.Errorf("read disaster-recovery coordinator state metadata: %w", err)
	}
	if stateSchemaVersion != coordinatorStateSchemaVersion {
		return nil, fmt.Errorf("unsupported coordinator state schema version %d", stateSchemaVersion)
	}

	var artifactRef *ModelArtifactRef
	hasArtifactRef := artifactBucket.Valid || artifactKey.Valid || artifactSHA256 != nil || artifactSize.Valid
	if hasArtifactRef {
		if !artifactBucket.Valid || !artifactKey.Valid || len(artifactSHA256) != sha256.Size || !artifactSize.Valid {
			return nil, errors.New("coordinator state contains an incomplete disaster-recovery artifact reference")
		}
		artifactRef = &ModelArtifactRef{
			Bucket:    artifactBucket.String,
			Key:       artifactKey.String,
			SHA256:    append([]byte(nil), artifactSHA256...),
			SizeBytes: artifactSize.Int64,
		}
		if s.artifacts == nil {
			return nil, errors.New("coordinator state references a model artifact but no artifact store is configured")
		}
	}

	auditRows, err := tx.Query(ctx, `
		SELECT sequence, event_id, occurred_at, event_type, event_payload, previous_hash, event_hash
		FROM ztfl_audit_events
		ORDER BY sequence
	`)
	if err != nil {
		return nil, fmt.Errorf("read disaster-recovery audit chain: %w", err)
	}
	auditRecords := make([]AuditRecord, 0)
	for auditRows.Next() {
		record, err := scanAuditRecord(auditRows)
		if err != nil {
			auditRows.Close()
			return nil, fmt.Errorf("scan disaster-recovery audit chain: %w", err)
		}
		auditRecords = append(auditRecords, record)
	}
	if err := auditRows.Err(); err != nil {
		auditRows.Close()
		return nil, fmt.Errorf("iterate disaster-recovery audit chain: %w", err)
	}
	auditRows.Close()
	if err := verifyAuditRecords(auditRecords, nil, 0); err != nil {
		return nil, fmt.Errorf("verify disaster-recovery audit chain: %w", err)
	}

	rollback = false
	return &DisasterRecoverySnapshot{
		tx:                 tx,
		SnapshotID:         snapshotID,
		PostgreSQLVersion:  serverVersion,
		Migrations:         migrations,
		StateSchemaVersion: stateSchemaVersion,
		ArtifactRef:        artifactRef,
		AuditRecords:       auditRecords,
	}, nil
}

func (s *DisasterRecoverySnapshot) Close(ctx context.Context) error {
	if s == nil || s.tx == nil {
		return nil
	}
	err := s.tx.Rollback(ctx)
	s.tx = nil
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

func (s *PostgresStateStore) DisasterRecoveryArtifact(ctx context.Context, snapshot *DisasterRecoverySnapshot) ([]byte, error) {
	if snapshot == nil || snapshot.ArtifactRef == nil {
		return nil, nil
	}
	if s == nil || s.artifacts == nil {
		return nil, errors.New("model artifact store is required")
	}
	payload, err := s.artifacts.Get(ctx, *snapshot.ArtifactRef)
	if err != nil {
		return nil, fmt.Errorf("read disaster-recovery model artifact: %w", err)
	}
	return payload, nil
}

func NewDisasterRecoveryFile(path string, data []byte) (DisasterRecoveryFile, error) {
	cleaned, err := validateDisasterRecoveryRelativePath(path)
	if err != nil {
		return DisasterRecoveryFile{}, err
	}
	if len(data) == 0 {
		return DisasterRecoveryFile{}, fmt.Errorf("disaster-recovery file %q is empty", cleaned)
	}
	digest := sha256.Sum256(data)
	return DisasterRecoveryFile{Path: cleaned, SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(data))}, nil
}

func ValidateDisasterRecoveryManifest(manifest DisasterRecoveryManifest) error {
	if manifest.SchemaVersion != DisasterRecoveryManifestSchemaVersion {
		return fmt.Errorf("unsupported disaster-recovery manifest schema version %d", manifest.SchemaVersion)
	}
	if manifest.CreatedAt.IsZero() || !manifest.CreatedAt.Equal(manifest.CreatedAt.UTC().Truncate(time.Microsecond)) {
		return errors.New("disaster-recovery created_at must use UTC microsecond precision")
	}
	if manifest.CoordinatorStateSchemaVersion != coordinatorStateSchemaVersion {
		return fmt.Errorf("unsupported coordinator state schema version %d", manifest.CoordinatorStateSchemaVersion)
	}
	if strings.TrimSpace(manifest.PostgreSQLServerVersion) == "" {
		return errors.New("PostgreSQL server version is required")
	}
	if len(manifest.PostgreSQLMigrations) == 0 {
		return errors.New("PostgreSQL migration ledger is required")
	}
	previousVersion := 0
	for _, migration := range manifest.PostgreSQLMigrations {
		if migration.Version <= previousVersion || strings.TrimSpace(migration.Name) == "" {
			return errors.New("PostgreSQL migrations must be strictly increasing and named")
		}
		previousVersion = migration.Version
	}
	if err := validateDisasterRecoveryFile(manifest.PostgreSQLDump, "PostgreSQL dump"); err != nil {
		return err
	}
	if err := validateDisasterRecoveryFile(manifest.AuditExport, "audit export"); err != nil {
		return err
	}
	if manifest.AuditTerminalSequence < 0 {
		return errors.New("audit terminal sequence must not be negative")
	}
	if manifest.AuditTerminalSequence == 0 {
		if manifest.AuditTerminalHash != "" {
			return errors.New("empty audit chain must not have a terminal hash")
		}
	} else if err := validateSHA256Hex(manifest.AuditTerminalHash); err != nil {
		return fmt.Errorf("audit terminal hash: %w", err)
	}
	seenObjects := make(map[string]struct{}, len(manifest.ModelArtifacts))
	seenPaths := map[string]struct{}{manifest.PostgreSQLDump.Path: {}, manifest.AuditExport.Path: {}}
	for _, artifact := range manifest.ModelArtifacts {
		if strings.TrimSpace(artifact.Bucket) == "" || strings.TrimSpace(artifact.Key) == "" {
			return errors.New("model artifact bucket and key are required")
		}
		if artifact.SizeBytes <= 0 {
			return errors.New("model artifact size must be positive")
		}
		if err := validateSHA256Hex(artifact.SHA256); err != nil {
			return fmt.Errorf("model artifact SHA-256: %w", err)
		}
		path, err := validateDisasterRecoveryRelativePath(artifact.Path)
		if err != nil {
			return err
		}
		if path != artifact.Path {
			return errors.New("model artifact path must be canonical")
		}
		objectID := artifact.Bucket + "/" + artifact.Key
		if _, exists := seenObjects[objectID]; exists {
			return fmt.Errorf("duplicate model artifact %q", objectID)
		}
		seenObjects[objectID] = struct{}{}
		if _, exists := seenPaths[path]; exists {
			return fmt.Errorf("duplicate disaster-recovery path %q", path)
		}
		seenPaths[path] = struct{}{}
	}
	return nil
}

func EncodeDisasterRecoveryManifest(manifest DisasterRecoveryManifest) ([]byte, error) {
	manifest.CreatedAt = manifest.CreatedAt.UTC().Truncate(time.Microsecond)
	manifest.PostgreSQLMigrations = append([]DisasterRecoveryMigration(nil), manifest.PostgreSQLMigrations...)
	manifest.ModelArtifacts = append([]DisasterRecoveryArtifact(nil), manifest.ModelArtifacts...)
	sort.Slice(manifest.PostgreSQLMigrations, func(i, j int) bool { return manifest.PostgreSQLMigrations[i].Version < manifest.PostgreSQLMigrations[j].Version })
	sort.Slice(manifest.ModelArtifacts, func(i, j int) bool {
		if manifest.ModelArtifacts[i].Bucket == manifest.ModelArtifacts[j].Bucket {
			return manifest.ModelArtifacts[i].Key < manifest.ModelArtifacts[j].Key
		}
		return manifest.ModelArtifacts[i].Bucket < manifest.ModelArtifacts[j].Bucket
	})
	if err := ValidateDisasterRecoveryManifest(manifest); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode disaster-recovery manifest: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxDisasterRecoveryManifestBytes {
		return nil, fmt.Errorf("disaster-recovery manifest exceeds %d bytes", maxDisasterRecoveryManifestBytes)
	}
	return data, nil
}

func DecodeDisasterRecoveryManifest(data []byte) (DisasterRecoveryManifest, error) {
	if len(data) == 0 || len(data) > maxDisasterRecoveryManifestBytes {
		return DisasterRecoveryManifest{}, errors.New("disaster-recovery manifest size is invalid")
	}
	var manifest DisasterRecoveryManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return DisasterRecoveryManifest{}, fmt.Errorf("decode disaster-recovery manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return DisasterRecoveryManifest{}, err
	}
	if err := ValidateDisasterRecoveryManifest(manifest); err != nil {
		return DisasterRecoveryManifest{}, err
	}
	return manifest, nil
}

func VerifyDisasterRecoveryBundle(root string, manifest DisasterRecoveryManifest) error {
	if err := ValidateDisasterRecoveryManifest(manifest); err != nil {
		return err
	}
	cleanRoot, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return fmt.Errorf("resolve disaster-recovery bundle root: %w", err)
	}
	files := []DisasterRecoveryFile{manifest.PostgreSQLDump, manifest.AuditExport}
	for _, file := range files {
		if err := verifyDisasterRecoveryFile(cleanRoot, file); err != nil {
			return err
		}
	}
	for _, artifact := range manifest.ModelArtifacts {
		if err := verifyDisasterRecoveryFile(cleanRoot, DisasterRecoveryFile{Path: artifact.Path, SHA256: artifact.SHA256, SizeBytes: artifact.SizeBytes}); err != nil {
			return err
		}
	}
	return nil
}

func ReadDisasterRecoveryFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("disaster-recovery input must be a regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

func validateDisasterRecoveryFile(file DisasterRecoveryFile, label string) error {
	path, err := validateDisasterRecoveryRelativePath(file.Path)
	if err != nil {
		return fmt.Errorf("%s path: %w", label, err)
	}
	if path != file.Path {
		return fmt.Errorf("%s path must be canonical", label)
	}
	if file.SizeBytes <= 0 {
		return fmt.Errorf("%s size must be positive", label)
	}
	if err := validateSHA256Hex(file.SHA256); err != nil {
		return fmt.Errorf("%s SHA-256: %w", label, err)
	}
	return nil
}

func verifyDisasterRecoveryFile(root string, expected DisasterRecoveryFile) error {
	path, err := secureDisasterRecoveryPath(root, expected.Path)
	if err != nil {
		return err
	}
	data, err := ReadDisasterRecoveryFile(path)
	if err != nil {
		return fmt.Errorf("read disaster-recovery file %q: %w", expected.Path, err)
	}
	if int64(len(data)) != expected.SizeBytes {
		return fmt.Errorf("disaster-recovery file %q has size %d, want %d", expected.Path, len(data), expected.SizeBytes)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expected.SHA256 {
		return fmt.Errorf("disaster-recovery file %q SHA-256 digest mismatch", expected.Path)
	}
	return nil
}

func secureDisasterRecoveryPath(root, relative string) (string, error) {
	cleaned, err := validateDisasterRecoveryRelativePath(relative)
	if err != nil {
		return "", err
	}
	candidate := filepath.Join(root, filepath.FromSlash(cleaned))
	absolute, err := filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, absolute)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("disaster-recovery path escapes bundle root")
	}
	return absolute, nil
}

func validateDisasterRecoveryRelativePath(value string) (string, error) {
	if strings.TrimSpace(value) == "" || strings.Contains(value, "\\") {
		return "", errors.New("disaster-recovery path must be a non-empty forward-slash relative path")
	}
	if strings.HasPrefix(value, "/") || filepath.IsAbs(value) {
		return "", errors.New("disaster-recovery path must be relative")
	}
	cleaned := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != value {
		return "", errors.New("disaster-recovery path must be canonical and must not traverse parents")
	}
	return cleaned, nil
}

func validateSHA256Hex(value string) error {
	if value != strings.ToLower(value) {
		return errors.New("digest must use lowercase hex")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("digest must encode exactly 32 bytes")
	}
	return nil
}
