package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
)

func OpenPostgresStateStoreForDisasterRecovery(ctx context.Context, dsn string, artifacts ModelArtifactStore) (*PostgresStateStore, error) {
	trimmed := strings.TrimSpace(dsn)
	if trimmed == "" {
		return nil, errors.New("PostgreSQL DSN is required")
	}
	config, err := pgxpool.ParseConfig(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL DSN: %w", err)
	}
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL disaster-recovery connection pool: %w", err)
	}
	store := &PostgresStateStore{pool: pool, artifacts: artifacts}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect PostgreSQL disaster-recovery store: %w", err)
	}
	return store, nil
}

func ValidateDisasterRecoveryMigrationLedger(migrations []DisasterRecoveryMigration) error {
	embedded, err := loadPostgresMigrations()
	if err != nil {
		return err
	}
	if len(migrations) != len(embedded) {
		return fmt.Errorf("disaster-recovery migration count %d does not match binary count %d", len(migrations), len(embedded))
	}
	for index := range embedded {
		if migrations[index].Version != embedded[index].version || migrations[index].Name != embedded[index].name {
			return fmt.Errorf(
				"disaster-recovery migration %d mismatch: backup=%d/%q binary=%d/%q",
				index,
				migrations[index].Version,
				migrations[index].Name,
				embedded[index].version,
				embedded[index].name,
			)
		}
	}
	return nil
}

func DisasterRecoveryArtifactPath(ref ModelArtifactRef) (string, error) {
	if len(ref.SHA256) != sha256.Size || ref.SizeBytes <= 0 {
		return "", errors.New("invalid model artifact reference")
	}
	return "artifacts/sha256/" + hex.EncodeToString(ref.SHA256) + ".npy", nil
}

func VerifyDisasterRecoveryAuditExport(data []byte, terminalSequence int64, terminalHash string) ([]AuditRecord, error) {
	if terminalSequence < 0 {
		return nil, errors.New("audit terminal sequence must not be negative")
	}
	decoder := jsonNewStrictDecoder(bytes.NewReader(data))
	records := make([]AuditRecord, 0)
	for {
		var record AuditRecord
		err := decoder.Decode(&record)
		if errors.Is(err, errJSONEOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode disaster-recovery audit export: %w", err)
		}
		records = append(records, record)
		if len(records) > 1_000_000 {
			return nil, errors.New("disaster-recovery audit export exceeds record limit")
		}
	}
	if err := verifyAuditRecords(records, nil, 0); err != nil {
		return nil, fmt.Errorf("verify disaster-recovery audit export: %w", err)
	}
	if int64(len(records)) != terminalSequence {
		return nil, fmt.Errorf("audit terminal sequence %d does not match export length %d", terminalSequence, len(records))
	}
	if terminalSequence == 0 {
		if terminalHash != "" {
			return nil, errors.New("empty audit export must not have a terminal hash")
		}
		return records, nil
	}
	if records[len(records)-1].EventHash != terminalHash {
		return nil, errors.New("audit terminal hash does not match export")
	}
	return records, nil
}

func (s *S3ModelArtifactStore) DisasterRecoveryNamespaceEmpty(ctx context.Context) (bool, error) {
	if s == nil || s.client == nil {
		return false, errors.New("S3 model artifact store is nil")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	prefix := s.prefix + "/"
	for object := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if object.Err != nil {
			return false, fmt.Errorf("list S3 disaster-recovery namespace: %w", object.Err)
		}
		return false, nil
	}
	return true, nil
}

func SameDisasterRecoveryArtifactRef(expected DisasterRecoveryArtifact, actual *ModelArtifactRef) bool {
	if actual == nil {
		return false
	}
	decoded, err := hex.DecodeString(expected.SHA256)
	if err != nil {
		return false
	}
	return expected.Bucket == actual.Bucket && expected.Key == actual.Key && expected.SizeBytes == actual.SizeBytes && bytes.Equal(decoded, actual.SHA256)
}
