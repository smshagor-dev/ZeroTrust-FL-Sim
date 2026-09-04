package coordinator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minio/minio-go/v7"
	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	"google.golang.org/protobuf/proto"
)

const (
	postgresTestDSNEnv       = "ZTFL_TEST_POSTGRES_DSN"
	s3TestEndpointEnv        = "ZTFL_TEST_S3_ENDPOINT"
	s3TestBucketEnv          = "ZTFL_TEST_S3_BUCKET"
	s3TestAccessKeyIDEnv     = "ZTFL_TEST_S3_ACCESS_KEY_ID"
	s3TestSecretAccessKeyEnv = "ZTFL_TEST_S3_SECRET_ACCESS_KEY"
)

func TestPostgresStateStoreRejectsEmptyDSN(t *testing.T) {
	if _, err := NewPostgresStateStore(context.Background(), "   "); err == nil {
		t.Fatal("empty PostgreSQL DSN was accepted")
	}
}

func TestPostgresStateStoreRoundTripMigrationAndReconnect(t *testing.T) {
	dsn := postgresTestDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetPostgresStateTables(t, ctx, dsn)

	store, err := NewPostgresStateStore(ctx, dsn)
	if err != nil {
		t.Fatalf("create PostgreSQL state store: %v", err)
	}
	if _, err := store.Load(ctx); !errors.Is(err, ErrStateNotFound) {
		store.Close()
		t.Fatalf("load missing PostgreSQL state error = %v, want ErrStateNotFound", err)
	}

	var migrationCount int
	if err := store.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ztfl_schema_migrations`).Scan(&migrationCount); err != nil {
		store.Close()
		t.Fatalf("count PostgreSQL migrations: %v", err)
	}
	if migrationCount != 3 {
		store.Close()
		t.Fatalf("migration count = %d, want 3", migrationCount)
	}

	snapshot := testStateSnapshot(t)
	if err := store.Commit(ctx, snapshot); err != nil {
		store.Close()
		t.Fatalf("commit PostgreSQL state: %v", err)
	}
	loaded, err := store.Load(ctx)
	if err != nil {
		store.Close()
		t.Fatalf("load PostgreSQL state: %v", err)
	}
	assertPostgresSnapshotEquivalent(t, loaded, snapshot)

	replacement := cloneStateSnapshot(snapshot)
	replacement.Model.ModelVersion = "round-8-postgres"
	replacement.Model.RoundId = 8
	replacement.Model.CreatedAtUnix = time.Now().UTC().Unix()
	if err := store.Commit(ctx, replacement); err != nil {
		store.Close()
		t.Fatalf("overwrite PostgreSQL state: %v", err)
	}
	store.Close()

	reopened, err := NewPostgresStateStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen PostgreSQL state store: %v", err)
	}
	defer reopened.Close()
	recovered, err := reopened.Load(ctx)
	if err != nil {
		t.Fatalf("load PostgreSQL state after reconnect: %v", err)
	}
	assertPostgresSnapshotEquivalent(t, recovered, replacement)

	invalid := cloneStateSnapshot(replacement)
	invalid.Model = nil
	if err := reopened.Commit(ctx, invalid); err == nil {
		t.Fatal("invalid PostgreSQL state snapshot was committed")
	}

	if _, err := reopened.pool.Exec(ctx, `UPDATE ztfl_coordinator_state SET state_schema_version = 999 WHERE singleton_id = 1`); err != nil {
		t.Fatalf("corrupt PostgreSQL state schema version: %v", err)
	}
	if _, err := reopened.Load(ctx); err == nil || errors.Is(err, ErrStateNotFound) {
		t.Fatalf("unsupported PostgreSQL state schema error = %v, want fail-closed validation", err)
	}
}

func TestPostgresStateStoreExternalizesLegacyInlineModelToS3(t *testing.T) {
	dsn := postgresTestDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	resetPostgresStateTables(t, ctx, dsn)

	snapshot := testStateSnapshot(t)
	inlineStore, err := NewPostgresStateStore(ctx, dsn)
	if err != nil {
		t.Fatalf("create inline PostgreSQL state store: %v", err)
	}
	if err := inlineStore.Commit(ctx, snapshot); err != nil {
		inlineStore.Close()
		t.Fatalf("seed legacy inline PostgreSQL state: %v", err)
	}
	inlineStore.Close()

	artifacts := s3TestArtifactStore(t, ctx)
	artifactStore, err := NewPostgresStateStoreWithArtifacts(ctx, dsn, artifacts)
	if err != nil {
		t.Fatalf("create PostgreSQL state store with artifacts: %v", err)
	}

	legacyLoaded, err := artifactStore.Load(ctx)
	if err != nil {
		artifactStore.Close()
		t.Fatalf("load legacy inline PostgreSQL state with artifact backend: %v", err)
	}
	assertPostgresSnapshotEquivalent(t, legacyLoaded, snapshot)

	if err := artifactStore.Commit(ctx, legacyLoaded); err != nil {
		artifactStore.Close()
		t.Fatalf("externalize legacy inline model: %v", err)
	}

	var (
		storedModelBytes []byte
		artifactBucket   pgtype.Text
		artifactKey      pgtype.Text
		artifactDigest   []byte
		artifactSize     pgtype.Int8
	)
	if err := artifactStore.pool.QueryRow(ctx, `
		SELECT model_proto, model_artifact_bucket, model_artifact_key,
		       model_artifact_sha256, model_artifact_size_bytes
		FROM ztfl_coordinator_state
		WHERE singleton_id = 1
	`).Scan(&storedModelBytes, &artifactBucket, &artifactKey, &artifactDigest, &artifactSize); err != nil {
		artifactStore.Close()
		t.Fatalf("inspect artifact-backed PostgreSQL state: %v", err)
	}
	storedModel := &flv1.GlobalModel{}
	if err := proto.Unmarshal(storedModelBytes, storedModel); err != nil {
		artifactStore.Close()
		t.Fatalf("decode metadata-only PostgreSQL model: %v", err)
	}
	if len(storedModel.GetWeightsPayload()) != 0 {
		artifactStore.Close()
		t.Fatalf("PostgreSQL model still contains %d inline payload bytes after externalization", len(storedModel.GetWeightsPayload()))
	}
	if !bytes.Equal(storedModel.GetSha256(), snapshot.Model.GetSha256()) {
		artifactStore.Close()
		t.Fatal("metadata-only PostgreSQL model lost the model digest")
	}
	if !artifactBucket.Valid || !artifactKey.Valid || len(artifactDigest) != 32 || !artifactSize.Valid {
		artifactStore.Close()
		t.Fatal("PostgreSQL state is missing a complete model artifact reference")
	}
	if artifactSize.Int64 != int64(len(snapshot.Model.GetWeightsPayload())) {
		artifactStore.Close()
		t.Fatalf("artifact size = %d, want %d", artifactSize.Int64, len(snapshot.Model.GetWeightsPayload()))
	}

	loaded, err := artifactStore.Load(ctx)
	if err != nil {
		artifactStore.Close()
		t.Fatalf("load artifact-backed PostgreSQL state: %v", err)
	}
	assertPostgresSnapshotEquivalent(t, loaded, snapshot)
	artifactStore.Close()

	reopened, err := NewPostgresStateStoreWithArtifacts(ctx, dsn, artifacts)
	if err != nil {
		t.Fatalf("reopen PostgreSQL artifact state store: %v", err)
	}
	recovered, err := reopened.Load(ctx)
	if err != nil {
		reopened.Close()
		t.Fatalf("recover artifact-backed PostgreSQL state: %v", err)
	}
	assertPostgresSnapshotEquivalent(t, recovered, snapshot)
	reopened.Close()

	withoutArtifacts, err := NewPostgresStateStore(ctx, dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL state store without artifacts: %v", err)
	}
	if _, err := withoutArtifacts.Load(ctx); err == nil {
		withoutArtifacts.Close()
		t.Fatal("artifact-backed PostgreSQL state loaded without an artifact backend")
	}
	withoutArtifacts.Close()

	badPayload := bytes.Repeat([]byte{0xA5}, int(artifactSize.Int64))
	if _, err := artifacts.client.PutObject(
		ctx,
		artifactBucket.String,
		artifactKey.String,
		bytes.NewReader(badPayload),
		int64(len(badPayload)),
		minio.PutObjectOptions{ContentType: networkWeightsFormat},
	); err != nil {
		t.Fatalf("corrupt model artifact fixture: %v", err)
	}
	corruptStore, err := NewPostgresStateStoreWithArtifacts(ctx, dsn, artifacts)
	if err != nil {
		t.Fatalf("reopen PostgreSQL state store for corruption check: %v", err)
	}
	defer corruptStore.Close()
	if _, err := corruptStore.Load(ctx); err == nil {
		t.Fatal("corrupted model artifact was accepted")
	}
}

func TestPostgresStateStoreRejectsUnknownDatabaseMigration(t *testing.T) {
	dsn := postgresTestDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetPostgresStateTables(t, ctx, dsn)

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `
		CREATE TABLE ztfl_schema_migrations (
			version INTEGER PRIMARY KEY CHECK (version > 0),
			name TEXT NOT NULL UNIQUE,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		t.Fatalf("create migration ledger: %v", err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO ztfl_schema_migrations (version, name) VALUES (999, '999_future.sql')`); err != nil {
		t.Fatalf("seed future migration: %v", err)
	}

	if store, err := NewPostgresStateStore(ctx, dsn); err == nil {
		store.Close()
		t.Fatal("PostgreSQL state store accepted an unknown database migration")
	}
}

func postgresTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(postgresTestDSNEnv)
	if dsn == "" {
		t.Skipf("%s is not configured", postgresTestDSNEnv)
	}
	return dsn
}

func s3TestArtifactStore(t *testing.T, ctx context.Context) *S3ModelArtifactStore {
	t.Helper()
	endpoint := os.Getenv(s3TestEndpointEnv)
	bucket := os.Getenv(s3TestBucketEnv)
	accessKey := os.Getenv(s3TestAccessKeyIDEnv)
	secretKey := os.Getenv(s3TestSecretAccessKeyEnv)
	if endpoint == "" || bucket == "" || accessKey == "" || secretKey == "" {
		t.Skipf("S3 integration requires %s, %s, %s and %s", s3TestEndpointEnv, s3TestBucketEnv, s3TestAccessKeyIDEnv, s3TestSecretAccessKeyEnv)
	}
	store, err := NewS3ModelArtifactStore(S3ArtifactStoreConfig{
		EndpointURL:       endpoint,
		Bucket:            bucket,
		Prefix:            fmt.Sprintf("tests/%d", time.Now().UTC().UnixNano()),
		Region:            "us-east-1",
		AccessKeyID:       accessKey,
		SecretAccessKey:   secretKey,
		AllowInsecureHTTP: true,
		ForcePathStyle:    true,
	})
	if err != nil {
		t.Fatalf("create S3 test artifact store: %v", err)
	}
	exists, err := store.client.BucketExists(ctx, bucket)
	if err != nil {
		t.Fatalf("check S3 test bucket: %v", err)
	}
	if !exists {
		if err := store.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"}); err != nil {
			t.Fatalf("create S3 test bucket: %v", err)
		}
	}
	return store
}

func resetPostgresStateTables(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect PostgreSQL for reset: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `DROP TABLE IF EXISTS ztfl_audit_events`); err != nil {
		t.Fatalf("drop PostgreSQL audit events table: %v", err)
	}
	if _, err := conn.Exec(ctx, `DROP TABLE IF EXISTS ztfl_coordinator_state`); err != nil {
		t.Fatalf("drop PostgreSQL coordinator state table: %v", err)
	}
	if _, err := conn.Exec(ctx, `DROP TABLE IF EXISTS ztfl_schema_migrations`); err != nil {
		t.Fatalf("drop PostgreSQL migration ledger: %v", err)
	}
}

func assertPostgresSnapshotEquivalent(t *testing.T, got, want StateSnapshot) {
	t.Helper()
	if got.Policy != want.Policy {
		t.Fatalf("loaded policy = %#v, want %#v", got.Policy, want.Policy)
	}
	if !proto.Equal(got.Model, want.Model) {
		t.Fatalf("loaded model = %v, want %v", got.Model, want.Model)
	}
	if len(got.Pending) != len(want.Pending) || got.Pending[0].NodeID != want.Pending[0].NodeID || got.Pending[0].UpdateID != want.Pending[0].UpdateID {
		t.Fatalf("loaded pending updates = %#v, want %#v", got.Pending, want.Pending)
	}
	if len(got.Registrations) != len(want.Registrations) || got.Registrations[0].RegistrationID != want.Registrations[0].RegistrationID {
		t.Fatalf("loaded registrations = %#v, want %#v", got.Registrations, want.Registrations)
	}
	if len(got.Nonces) != len(want.Nonces) || got.Nonces[0].Key != want.Nonces[0].Key {
		t.Fatalf("loaded nonces = %#v, want %#v", got.Nonces, want.Nonces)
	}
	if len(got.RateWindows) != len(want.RateWindows) || got.RateWindows[0].Count != want.RateWindows[0].Count {
		t.Fatalf("loaded rate windows = %#v, want %#v", got.RateWindows, want.RateWindows)
	}
}
