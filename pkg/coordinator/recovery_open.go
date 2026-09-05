package coordinator

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// OpenPostgresStateStoreForRecovery opens the durable PostgreSQL authority
// without applying migrations. Recovery backup/verification must never mutate
// the source database merely because an operator asked to capture it.
func OpenPostgresStateStoreForRecovery(ctx context.Context, dsn string, artifacts ModelArtifactStore) (*PostgresStateStore, error) {
	trimmed := strings.TrimSpace(dsn)
	if trimmed == "" {
		return nil, errors.New("PostgreSQL DSN is required")
	}
	config, err := pgxpool.ParseConfig(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL recovery DSN: %w", err)
	}
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL recovery connection pool: %w", err)
	}
	store := &PostgresStateStore{pool: pool, artifacts: artifacts}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect PostgreSQL recovery store: %w", err)
	}
	return store, nil
}

// ValidateRecoveryMigrationLedger requires the backup/restore database schema
// to match the exact migrations embedded in this binary. Recovery never
// silently upgrades an old bundle or accepts an unknown future schema.
func ValidateRecoveryMigrationLedger(migrations []RecoveryMigration) error {
	embedded, err := loadPostgresMigrations()
	if err != nil {
		return err
	}
	if len(migrations) != len(embedded) {
		return fmt.Errorf("recovery migration count %d does not match binary count %d", len(migrations), len(embedded))
	}
	for index, expected := range embedded {
		actual := migrations[index]
		if actual.Version != expected.version || actual.Name != expected.name {
			return fmt.Errorf(
				"recovery migration %d mismatch: database=%d/%q binary=%d/%q",
				index,
				actual.Version,
				actual.Name,
				expected.version,
				expected.name,
			)
		}
	}
	return nil
}
