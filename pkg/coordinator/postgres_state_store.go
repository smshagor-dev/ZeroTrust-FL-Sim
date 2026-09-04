package coordinator

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	"google.golang.org/protobuf/proto"
)

const postgresMigrationLockKey int64 = 0x5A54464C53544154

//go:embed migrations/*.sql
var postgresMigrations embed.FS

type PostgresStateStore struct {
	pool      *pgxpool.Pool
	artifacts ModelArtifactStore
}

type postgresMigration struct {
	version int
	name    string
	sql     string
}

func NewPostgresStateStore(ctx context.Context, dsn string) (*PostgresStateStore, error) {
	return newPostgresStateStore(ctx, dsn, nil)
}

func NewPostgresStateStoreWithArtifacts(ctx context.Context, dsn string, artifacts ModelArtifactStore) (*PostgresStateStore, error) {
	if artifacts == nil {
		return nil, errors.New("model artifact store is required")
	}
	return newPostgresStateStore(ctx, dsn, artifacts)
}

func newPostgresStateStore(ctx context.Context, dsn string, artifacts ModelArtifactStore) (*PostgresStateStore, error) {
	trimmed := strings.TrimSpace(dsn)
	if trimmed == "" {
		return nil, errors.New("PostgreSQL DSN is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	config, err := pgxpool.ParseConfig(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL DSN: %w", err)
	}
	config.MaxConns = 4

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL connection pool: %w", err)
	}
	store := &PostgresStateStore{pool: pool, artifacts: artifacts}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect PostgreSQL state store: %w", err)
	}
	if err := store.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

func (s *PostgresStateStore) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

func (s *PostgresStateStore) Load(ctx context.Context) (StateSnapshot, error) {
	if s == nil || s.pool == nil {
		return StateSnapshot{}, errors.New("PostgreSQL state store is nil")
	}
	if err := ctx.Err(); err != nil {
		return StateSnapshot{}, err
	}

	var (
		stateSchemaVersion int
		policyJSON         []byte
		modelBytes         []byte
		pendingJSON        []byte
		registrationsJSON  []byte
		noncesJSON         []byte
		rateWindowsJSON    []byte
		artifactBucket     pgtype.Text
		artifactKey        pgtype.Text
		artifactSHA256     []byte
		artifactSize       pgtype.Int8
	)
	err := s.pool.QueryRow(ctx, `
		SELECT state_schema_version, policy, model_proto, pending_updates,
		       registrations, replay_nonces, rate_windows,
		       model_artifact_bucket, model_artifact_key,
		       model_artifact_sha256, model_artifact_size_bytes
		FROM ztfl_coordinator_state
		WHERE singleton_id = 1
	`).Scan(
		&stateSchemaVersion,
		&policyJSON,
		&modelBytes,
		&pendingJSON,
		&registrationsJSON,
		&noncesJSON,
		&rateWindowsJSON,
		&artifactBucket,
		&artifactKey,
		&artifactSHA256,
		&artifactSize,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return StateSnapshot{}, ErrStateNotFound
	}
	if err != nil {
		return StateSnapshot{}, fmt.Errorf("load PostgreSQL coordinator state: %w", err)
	}
	if stateSchemaVersion != coordinatorStateSchemaVersion {
		return StateSnapshot{}, fmt.Errorf("unsupported coordinator state schema version %d", stateSchemaVersion)
	}
	if len(modelBytes) == 0 {
		return StateSnapshot{}, errors.New("PostgreSQL coordinator state is missing the global model")
	}

	var snapshot StateSnapshot
	if err := decodePostgresJSON(policyJSON, &snapshot.Policy, "policy"); err != nil {
		return StateSnapshot{}, err
	}
	if err := decodePostgresJSON(pendingJSON, &snapshot.Pending, "pending updates"); err != nil {
		return StateSnapshot{}, err
	}
	if err := decodePostgresJSON(registrationsJSON, &snapshot.Registrations, "registrations"); err != nil {
		return StateSnapshot{}, err
	}
	if err := decodePostgresJSON(noncesJSON, &snapshot.Nonces, "replay nonces"); err != nil {
		return StateSnapshot{}, err
	}
	if err := decodePostgresJSON(rateWindowsJSON, &snapshot.RateWindows, "rate windows"); err != nil {
		return StateSnapshot{}, err
	}

	model := &flv1.GlobalModel{}
	if err := proto.Unmarshal(modelBytes, model); err != nil {
		return StateSnapshot{}, fmt.Errorf("decode PostgreSQL global model: %w", err)
	}

	hasArtifactRef := artifactBucket.Valid || artifactKey.Valid || artifactSHA256 != nil || artifactSize.Valid
	if hasArtifactRef {
		if !artifactBucket.Valid || !artifactKey.Valid || len(artifactSHA256) == 0 || !artifactSize.Valid {
			return StateSnapshot{}, errors.New("PostgreSQL coordinator state contains an incomplete model artifact reference")
		}
		if len(model.GetWeightsPayload()) != 0 {
			return StateSnapshot{}, errors.New("PostgreSQL coordinator state contains both inline and artifact-backed model payloads")
		}
		if s.artifacts == nil {
			return StateSnapshot{}, errors.New("PostgreSQL coordinator state references a model artifact but no artifact store is configured")
		}
		ref := ModelArtifactRef{
			Bucket:    artifactBucket.String,
			Key:       artifactKey.String,
			SHA256:    append([]byte(nil), artifactSHA256...),
			SizeBytes: artifactSize.Int64,
		}
		if len(model.GetSha256()) != len(ref.SHA256) || !bytes.Equal(model.GetSha256(), ref.SHA256) {
			return StateSnapshot{}, errors.New("PostgreSQL model metadata digest does not match the artifact reference")
		}
		payload, err := s.artifacts.Get(ctx, ref)
		if err != nil {
			return StateSnapshot{}, fmt.Errorf("load global model artifact: %w", err)
		}
		model.WeightsPayload = payload
	}

	snapshot.Model = model
	if err := validateStateSnapshot(snapshot); err != nil {
		return StateSnapshot{}, fmt.Errorf("validate PostgreSQL coordinator state: %w", err)
	}
	return cloneStateSnapshot(snapshot), nil
}

func (s *PostgresStateStore) Commit(ctx context.Context, snapshot StateSnapshot) error {
	if s == nil || s.pool == nil {
		return errors.New("PostgreSQL state store is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateStateSnapshot(snapshot); err != nil {
		return fmt.Errorf("validate PostgreSQL coordinator state before commit: %w", err)
	}

	canonical := cloneStateSnapshot(snapshot)
	sort.Slice(canonical.Pending, func(i, j int) bool { return canonical.Pending[i].NodeID < canonical.Pending[j].NodeID })
	sort.Slice(canonical.Registrations, func(i, j int) bool { return canonical.Registrations[i].NodeID < canonical.Registrations[j].NodeID })
	sort.Slice(canonical.Nonces, func(i, j int) bool { return canonical.Nonces[i].Key < canonical.Nonces[j].Key })
	sort.Slice(canonical.RateWindows, func(i, j int) bool { return canonical.RateWindows[i].NodeID < canonical.RateWindows[j].NodeID })

	modelForStorage := proto.Clone(canonical.Model).(*flv1.GlobalModel)
	var artifactRef *ModelArtifactRef
	if s.artifacts != nil && len(modelForStorage.GetWeightsPayload()) > 0 {
		ref, err := s.artifacts.Put(ctx, modelForStorage.GetWeightsPayload())
		if err != nil {
			return fmt.Errorf("persist global model artifact: %w", err)
		}
		if len(modelForStorage.GetSha256()) != len(ref.SHA256) || !bytes.Equal(modelForStorage.GetSha256(), ref.SHA256) {
			return errors.New("model artifact digest does not match validated global model digest")
		}
		artifactRef = &ref
		modelForStorage.WeightsPayload = nil
	}
	modelBytes, err := proto.Marshal(modelForStorage)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL global model: %w", err)
	}

	policyJSON, err := json.Marshal(canonical.Policy)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL policy: %w", err)
	}
	pendingJSON, err := json.Marshal(canonical.Pending)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL pending updates: %w", err)
	}
	registrationsJSON, err := json.Marshal(canonical.Registrations)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL registrations: %w", err)
	}
	noncesJSON, err := json.Marshal(canonical.Nonces)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL replay nonces: %w", err)
	}
	rateWindowsJSON, err := json.Marshal(canonical.RateWindows)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL rate windows: %w", err)
	}

	var artifactBucket any
	var artifactKey any
	var artifactSHA any
	var artifactSize any
	if artifactRef != nil {
		artifactBucket = artifactRef.Bucket
		artifactKey = artifactRef.Key
		artifactSHA = artifactRef.SHA256
		artifactSize = artifactRef.SizeBytes
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin PostgreSQL state transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO ztfl_coordinator_state (
			singleton_id,
			state_schema_version,
			policy,
			model_proto,
			pending_updates,
			registrations,
			replay_nonces,
			rate_windows,
			model_artifact_bucket,
			model_artifact_key,
			model_artifact_sha256,
			model_artifact_size_bytes
		) VALUES (1, $1, $2::jsonb, $3, $4::jsonb, $5::jsonb, $6::jsonb, $7::jsonb, $8, $9, $10, $11)
		ON CONFLICT (singleton_id) DO UPDATE SET
			state_schema_version = EXCLUDED.state_schema_version,
			policy = EXCLUDED.policy,
			model_proto = EXCLUDED.model_proto,
			pending_updates = EXCLUDED.pending_updates,
			registrations = EXCLUDED.registrations,
			replay_nonces = EXCLUDED.replay_nonces,
			rate_windows = EXCLUDED.rate_windows,
			model_artifact_bucket = EXCLUDED.model_artifact_bucket,
			model_artifact_key = EXCLUDED.model_artifact_key,
			model_artifact_sha256 = EXCLUDED.model_artifact_sha256,
			model_artifact_size_bytes = EXCLUDED.model_artifact_size_bytes,
			updated_at = CURRENT_TIMESTAMP
	`,
		coordinatorStateSchemaVersion,
		string(policyJSON),
		modelBytes,
		string(pendingJSON),
		string(registrationsJSON),
		string(noncesJSON),
		string(rateWindowsJSON),
		artifactBucket,
		artifactKey,
		artifactSHA,
		artifactSize,
	)
	if err != nil {
		return fmt.Errorf("write PostgreSQL coordinator state: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit PostgreSQL coordinator state: %w", err)
	}
	return nil
}

func (s *PostgresStateStore) migrate(ctx context.Context) error {
	migrations, err := loadPostgresMigrations()
	if err != nil {
		return err
	}
	if len(migrations) == 0 {
		return errors.New("no PostgreSQL state migrations are embedded")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin PostgreSQL migration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, postgresMigrationLockKey); err != nil {
		return fmt.Errorf("lock PostgreSQL state migrations: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS ztfl_schema_migrations (
			version INTEGER PRIMARY KEY CHECK (version > 0),
			name TEXT NOT NULL UNIQUE,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("initialize PostgreSQL migration ledger: %w", err)
	}

	rows, err := tx.Query(ctx, `SELECT version, name FROM ztfl_schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("read PostgreSQL migration ledger: %w", err)
	}
	applied := make(map[int]string)
	for rows.Next() {
		var version int
		var name string
		if err := rows.Scan(&version, &name); err != nil {
			rows.Close()
			return fmt.Errorf("scan PostgreSQL migration ledger: %w", err)
		}
		applied[version] = name
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate PostgreSQL migration ledger: %w", err)
	}
	rows.Close()

	embedded := make(map[int]string, len(migrations))
	for _, migration := range migrations {
		embedded[migration.version] = migration.name
	}
	for version, name := range applied {
		embeddedName, ok := embedded[version]
		if !ok {
			return fmt.Errorf("database has unknown PostgreSQL migration version %d (%s)", version, name)
		}
		if embeddedName != name {
			return fmt.Errorf("PostgreSQL migration version %d name mismatch: database=%q binary=%q", version, name, embeddedName)
		}
	}

	for _, migration := range migrations {
		if _, ok := applied[migration.version]; ok {
			continue
		}
		if _, err := tx.Exec(ctx, migration.sql); err != nil {
			return fmt.Errorf("apply PostgreSQL migration %s: %w", migration.name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ztfl_schema_migrations (version, name) VALUES ($1, $2)`, migration.version, migration.name); err != nil {
			return fmt.Errorf("record PostgreSQL migration %s: %w", migration.name, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit PostgreSQL migrations: %w", err)
	}
	return nil
}

func loadPostgresMigrations() ([]postgresMigration, error) {
	entries, err := postgresMigrations.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded PostgreSQL migrations: %w", err)
	}
	migrations := make([]postgresMigration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		parts := strings.SplitN(strings.TrimSuffix(entry.Name(), ".sql"), "_", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid PostgreSQL migration filename %q", entry.Name())
		}
		version, err := strconv.Atoi(parts[0])
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("invalid PostgreSQL migration version in %q", entry.Name())
		}
		data, err := postgresMigrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read PostgreSQL migration %s: %w", entry.Name(), err)
		}
		migrations = append(migrations, postgresMigration{version: version, name: entry.Name(), sql: string(data)})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	for i := 1; i < len(migrations); i++ {
		if migrations[i-1].version == migrations[i].version {
			return nil, fmt.Errorf("duplicate PostgreSQL migration version %d", migrations[i].version)
		}
	}
	return migrations, nil
}

func decodePostgresJSON(data []byte, target any, field string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode PostgreSQL %s: %w", field, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fmt.Errorf("decode PostgreSQL %s: %w", field, err)
	}
	return nil
}
