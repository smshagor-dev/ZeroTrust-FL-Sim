package coordinator

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	"google.golang.org/protobuf/proto"
)

// RecoveryMigration records one applied coordinator schema migration in a
// point-in-time recovery snapshot.
type RecoveryMigration struct {
	Version int    `json:"version"`
	Name    string `json:"name"`
}

// RecoveryAuditHead records the verified append-only audit chain head that is
// visible to a point-in-time recovery snapshot.
type RecoveryAuditHead struct {
	Sequence  int64  `json:"sequence"`
	EventHash string `json:"event_hash,omitempty"`
}

// RecoveryMetadata is the database metadata required to bind a PostgreSQL dump
// to the experiment identity, global-model artifact and audit chain captured
// from the same MVCC snapshot.
type RecoveryMetadata struct {
	PostgreSQLVersion    string              `json:"postgresql_version"`
	PostgreSQLVersionNum int                 `json:"postgresql_version_num"`
	StateSchemaVersion   int                 `json:"state_schema_version"`
	Experiment           ExperimentMetadata  `json:"experiment"`
	ModelVersion         string              `json:"model_version"`
	RoundID              uint64              `json:"round_id"`
	Artifact             *ModelArtifactRef   `json:"artifact,omitempty"`
	Migrations           []RecoveryMigration `json:"migrations"`
	AuditHead            RecoveryAuditHead   `json:"audit_head"`
}

// PostgresRecoverySnapshot holds a PostgreSQL REPEATABLE READ transaction open
// so pg_dump can import the exact same MVCC snapshot with --snapshot.
type PostgresRecoverySnapshot struct {
	tx         pgx.Tx
	snapshotID string
	metadata   RecoveryMetadata
}

// BeginRecoverySnapshot exports a PostgreSQL MVCC snapshot and captures the
// coordinator state/artifact/migration/audit metadata visible inside it.
func (s *PostgresStateStore) BeginRecoverySnapshot(ctx context.Context) (*PostgresRecoverySnapshot, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("PostgreSQL state store is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("begin PostgreSQL recovery snapshot: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback(context.Background())
		}
	}()

	var snapshotID string
	if err := tx.QueryRow(ctx, `SELECT pg_export_snapshot()`).Scan(&snapshotID); err != nil {
		return nil, fmt.Errorf("export PostgreSQL recovery snapshot: %w", err)
	}
	if snapshotID == "" {
		return nil, errors.New("PostgreSQL exported an empty recovery snapshot identifier")
	}

	metadata, err := readRecoveryMetadataTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	rollback = false
	return &PostgresRecoverySnapshot{tx: tx, snapshotID: snapshotID, metadata: metadata}, nil
}

func readRecoveryMetadataTx(ctx context.Context, tx pgx.Tx) (RecoveryMetadata, error) {
	var (
		serverVersion    string
		serverVersionNum string
	)
	if err := tx.QueryRow(ctx, `SHOW server_version`).Scan(&serverVersion); err != nil {
		return RecoveryMetadata{}, fmt.Errorf("read PostgreSQL server version: %w", err)
	}
	if err := tx.QueryRow(ctx, `SHOW server_version_num`).Scan(&serverVersionNum); err != nil {
		return RecoveryMetadata{}, fmt.Errorf("read PostgreSQL numeric server version: %w", err)
	}
	parsedVersionNum, err := strconv.Atoi(serverVersionNum)
	if err != nil || parsedVersionNum <= 0 {
		return RecoveryMetadata{}, fmt.Errorf("parse PostgreSQL server_version_num %q", serverVersionNum)
	}

	var (
		stateSchemaVersion int
		policyJSON         []byte
		modelBytes         []byte
		artifactBucket     *string
		artifactKey        *string
		artifactSHA256     []byte
		artifactSize       *int64
	)
	if err := tx.QueryRow(ctx, `
		SELECT state_schema_version, policy, model_proto,
		       model_artifact_bucket, model_artifact_key,
		       model_artifact_sha256, model_artifact_size_bytes
		FROM ztfl_coordinator_state
		WHERE singleton_id = 1
	`).Scan(
		&stateSchemaVersion,
		&policyJSON,
		&modelBytes,
		&artifactBucket,
		&artifactKey,
		&artifactSHA256,
		&artifactSize,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RecoveryMetadata{}, ErrStateNotFound
		}
		return RecoveryMetadata{}, fmt.Errorf("read coordinator recovery metadata: %w", err)
	}
	if stateSchemaVersion != coordinatorStateSchemaVersion {
		return RecoveryMetadata{}, fmt.Errorf("unsupported coordinator state schema version %d", stateSchemaVersion)
	}
	if len(modelBytes) == 0 {
		return RecoveryMetadata{}, errors.New("coordinator recovery metadata is missing the global model envelope")
	}

	var policy StatePolicy
	if err := decodePostgresJSON(policyJSON, &policy, "recovery policy"); err != nil {
		return RecoveryMetadata{}, err
	}
	if err := validateExperimentMetadata(policy.Experiment); err != nil {
		return RecoveryMetadata{}, fmt.Errorf("validate recovery experiment metadata: %w", err)
	}

	model := &flv1.GlobalModel{}
	if err := proto.Unmarshal(modelBytes, model); err != nil {
		return RecoveryMetadata{}, fmt.Errorf("decode coordinator recovery model envelope: %w", err)
	}
	if model.GetModelVersion() == "" {
		return RecoveryMetadata{}, errors.New("coordinator recovery model version is empty")
	}

	metadata := RecoveryMetadata{
		PostgreSQLVersion:    serverVersion,
		PostgreSQLVersionNum: parsedVersionNum,
		StateSchemaVersion:   stateSchemaVersion,
		Experiment:           policy.Experiment,
		ModelVersion:         model.GetModelVersion(),
		RoundID:              model.GetRoundId(),
	}

	hasArtifact := artifactBucket != nil || artifactKey != nil || artifactSHA256 != nil || artifactSize != nil
	if hasArtifact {
		if artifactBucket == nil || artifactKey == nil || len(artifactSHA256) != 32 || artifactSize == nil || *artifactSize <= 0 {
			return RecoveryMetadata{}, errors.New("coordinator recovery metadata contains an incomplete model artifact reference")
		}
		if len(model.GetWeightsPayload()) != 0 {
			return RecoveryMetadata{}, errors.New("artifact-backed recovery model unexpectedly contains inline weights")
		}
		if len(model.GetSha256()) != len(artifactSHA256) || !bytes.Equal(model.GetSha256(), artifactSHA256) {
			return RecoveryMetadata{}, errors.New("recovery model digest does not match the artifact reference")
		}
		metadata.Artifact = &ModelArtifactRef{
			Bucket:    *artifactBucket,
			Key:       *artifactKey,
			SHA256:    append([]byte(nil), artifactSHA256...),
			SizeBytes: *artifactSize,
		}
	}

	rows, err := tx.Query(ctx, `SELECT version, name FROM ztfl_schema_migrations ORDER BY version`)
	if err != nil {
		return RecoveryMetadata{}, fmt.Errorf("read recovery migration ledger: %w", err)
	}
	for rows.Next() {
		var migration RecoveryMigration
		if err := rows.Scan(&migration.Version, &migration.Name); err != nil {
			rows.Close()
			return RecoveryMetadata{}, fmt.Errorf("scan recovery migration ledger: %w", err)
		}
		metadata.Migrations = append(metadata.Migrations, migration)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return RecoveryMetadata{}, fmt.Errorf("iterate recovery migration ledger: %w", err)
	}
	rows.Close()
	if len(metadata.Migrations) == 0 {
		return RecoveryMetadata{}, errors.New("recovery migration ledger is empty")
	}

	var auditHash []byte
	err = tx.QueryRow(ctx, `
		SELECT sequence, event_hash
		FROM ztfl_audit_events
		ORDER BY sequence DESC
		LIMIT 1
	`).Scan(&metadata.AuditHead.Sequence, &auditHash)
	if errors.Is(err, pgx.ErrNoRows) {
		metadata.AuditHead = RecoveryAuditHead{}
	} else if err != nil {
		return RecoveryMetadata{}, fmt.Errorf("read recovery audit head: %w", err)
	} else {
		if len(auditHash) != 32 {
			return RecoveryMetadata{}, errors.New("recovery audit head has an invalid hash length")
		}
		metadata.AuditHead.EventHash = hex.EncodeToString(auditHash)
	}
	return metadata, nil
}

// SnapshotID returns the PostgreSQL snapshot identifier passed to pg_dump
// --snapshot. It remains valid only while Close has not been called.
func (s *PostgresRecoverySnapshot) SnapshotID() string {
	if s == nil {
		return ""
	}
	return s.snapshotID
}

// Metadata returns a defensive copy of point-in-time recovery metadata.
func (s *PostgresRecoverySnapshot) Metadata() RecoveryMetadata {
	if s == nil {
		return RecoveryMetadata{}
	}
	metadata := s.metadata
	metadata.Migrations = append([]RecoveryMigration(nil), s.metadata.Migrations...)
	if s.metadata.Artifact != nil {
		artifact := *s.metadata.Artifact
		artifact.SHA256 = append([]byte(nil), s.metadata.Artifact.SHA256...)
		metadata.Artifact = &artifact
	}
	return metadata
}

// ReadAuditEvents returns and verifies the complete bounded audit chain visible
// to this recovery snapshot.
func (s *PostgresRecoverySnapshot) ReadAuditEvents(ctx context.Context) ([]AuditRecord, error) {
	if s == nil || s.tx == nil {
		return nil, errors.New("PostgreSQL recovery snapshot is nil")
	}
	if s.metadata.AuditHead.Sequence == 0 {
		return []AuditRecord{}, nil
	}
	if s.metadata.AuditHead.Sequence > maxAuditExportRows {
		return nil, fmt.Errorf("recovery audit chain contains %d rows; maximum supported bundle export is %d", s.metadata.AuditHead.Sequence, maxAuditExportRows)
	}

	rows, err := s.tx.Query(ctx, `
		SELECT sequence, event_id, occurred_at, event_type, event_payload, previous_hash, event_hash
		FROM ztfl_audit_events
		WHERE sequence <= $1
		ORDER BY sequence
	`, s.metadata.AuditHead.Sequence)
	if err != nil {
		return nil, fmt.Errorf("query recovery audit chain: %w", err)
	}
	defer rows.Close()

	records := make([]AuditRecord, 0, int(s.metadata.AuditHead.Sequence))
	for rows.Next() {
		record, err := scanAuditRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scan recovery audit chain: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate recovery audit chain: %w", err)
	}
	if int64(len(records)) != s.metadata.AuditHead.Sequence {
		return nil, fmt.Errorf("recovery audit chain contains %d records, want %d", len(records), s.metadata.AuditHead.Sequence)
	}
	if err := verifyAuditRecords(records, nil, 0); err != nil {
		return nil, fmt.Errorf("verify recovery audit chain: %w", err)
	}
	if records[len(records)-1].EventHash != s.metadata.AuditHead.EventHash {
		return nil, errors.New("recovery audit chain head does not match snapshot metadata")
	}
	return records, nil
}

// Close releases the exported PostgreSQL snapshot. The read-only transaction is
// rolled back intentionally because it never mutates state.
func (s *PostgresRecoverySnapshot) Close(ctx context.Context) error {
	if s == nil || s.tx == nil {
		return nil
	}
	err := s.tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("close PostgreSQL recovery snapshot: %w", err)
	}
	s.tx = nil
	return nil
}
