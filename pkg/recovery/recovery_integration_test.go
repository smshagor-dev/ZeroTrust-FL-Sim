package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	"github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/coordinator"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
)

func TestDisasterRecoveryBackupDestroyRestore(t *testing.T) {
	dsn := integrationEnv(t, "ZTFL_TEST_POSTGRES_DSN")
	endpoint := integrationEnv(t, "ZTFL_TEST_S3_ENDPOINT")
	bucket := integrationEnv(t, "ZTFL_TEST_S3_BUCKET")
	accessKey := integrationEnv(t, "ZTFL_TEST_S3_ACCESS_KEY_ID")
	secretKey := integrationEnv(t, "ZTFL_TEST_S3_SECRET_ACCESS_KEY")
	pgDump := integrationEnv(t, "ZTFL_TEST_PG_DUMP")
	pgRestore := integrationEnv(t, "ZTFL_TEST_PG_RESTORE")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	resetRecoveryDatabase(t, ctx, dsn)

	prefix := fmt.Sprintf("recovery-tests/%d", time.Now().UTC().UnixNano())
	client := recoveryMinioClient(t, endpoint, accessKey, secretKey)
	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		t.Fatalf("check recovery test bucket: %v", err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"}); err != nil {
			t.Fatalf("create recovery test bucket: %v", err)
		}
	}

	artifactConfig := coordinator.S3ArtifactStoreConfig{
		EndpointURL:       endpoint,
		Bucket:            bucket,
		Prefix:            prefix,
		Region:            "us-east-1",
		AccessKeyID:       accessKey,
		SecretAccessKey:   secretKey,
		AllowInsecureHTTP: true,
		ForcePathStyle:    true,
	}
	artifacts, err := coordinator.NewS3ModelArtifactStore(artifactConfig)
	if err != nil {
		t.Fatalf("create recovery source artifact store: %v", err)
	}

	payload := recoveryNPY([]float32{1.25, -2.5, 0.75})
	digest := sha256.Sum256(payload)
	now := time.Now().UTC()
	state := coordinator.StateSnapshot{
		Policy: coordinator.StatePolicy{
			LeaseTTL:            5 * time.Minute,
			MaxUpdateBytes:      8 << 20,
			MinUpdates:          2,
			MaxUpdatesPerMinute: 60,
			AggregationMethod:   "median",
		},
		Model: &flv1.GlobalModel{
			ModelVersion:   "round-3-recovery-test",
			RoundId:        3,
			WeightsPayload: payload,
			WeightsFormat:  "application/x-npy-f32",
			Sha256:         digest[:],
			CreatedAtUnix:  now.Unix(),
		},
		Registrations: []ztsecurity.Registration{
			{
				NodeID:                 "worker-recovery",
				Role:                   "edge-worker",
				CertificateFingerprint: "sha256:recovery-worker",
				RegistrationID:         "opaque-recovery-registration",
				ExpiresAt:              now.Add(time.Hour),
				Generation:             2,
			},
		},
	}

	store, err := coordinator.NewPostgresStateStoreWithArtifacts(ctx, dsn, artifacts)
	if err != nil {
		t.Fatalf("create recovery source state store: %v", err)
	}
	event := coordinator.AuditEvent{
		SchemaVersion: 1,
		OccurredAt:    now.Truncate(time.Microsecond),
		Type:          coordinator.AuditEventStateInitialized,
		Outcome:       "success",
		RoundID:       state.Model.GetRoundId(),
		ModelVersion:  state.Model.GetModelVersion(),
	}
	if err := store.CommitWithAudit(ctx, state, []coordinator.AuditEvent{event}); err != nil {
		store.Close()
		t.Fatalf("seed recovery source state: %v", err)
	}
	store.Close()

	bundleDir := filepath.Join(t.TempDir(), "bundle")
	backup, err := Backup(ctx, BackupConfig{
		PostgresDSN: dsn,
		Artifacts:   artifacts,
		OutputDir:   bundleDir,
		PgDumpPath:  pgDump,
	})
	if err != nil {
		t.Fatalf("create disaster recovery backup: %v", err)
	}
	if backup.Manifest.Artifact == nil || backup.Manifest.Audit.HeadSequence != 1 {
		t.Fatalf("unexpected recovery backup manifest: %#v", backup.Manifest)
	}

	// Destroy both authorities after the bundle is complete. The restore below
	// must reconstruct the state using only the bundle plus target credentials.
	resetRecoveryDatabase(t, ctx, dsn)
	if err := client.RemoveObject(ctx, backup.Manifest.Artifact.Bucket, backup.Manifest.Artifact.Key, minio.RemoveObjectOptions{}); err != nil {
		t.Fatalf("delete source recovery model artifact: %v", err)
	}
	if _, err := client.StatObject(ctx, backup.Manifest.Artifact.Bucket, backup.Manifest.Artifact.Key, minio.StatObjectOptions{}); err == nil {
		t.Fatal("source model artifact still exists after destructive fixture reset")
	}

	restoreArtifacts, err := coordinator.NewS3ModelArtifactStore(artifactConfig)
	if err != nil {
		t.Fatalf("create clean recovery target artifact store: %v", err)
	}
	restoreConfig := RestoreConfig{
		PostgresDSN:      dsn,
		Artifacts:        restoreArtifacts,
		InputDir:         bundleDir,
		PgRestorePath:    pgRestore,
		AllowDestructive: true,
	}

	// A dirty PostgreSQL target must fail before the artifact authority is
	// mutated. This proves validation order across the two recovery authorities.
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect dirty PostgreSQL target fixture: %v", err)
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE public.recovery_dirty_guard (id integer)`); err != nil {
		_ = conn.Close(ctx)
		t.Fatalf("create dirty PostgreSQL target fixture: %v", err)
	}
	if _, err := Restore(ctx, restoreConfig); err == nil {
		_ = conn.Close(ctx)
		t.Fatal("recovery restore accepted a dirty PostgreSQL target")
	}
	if _, err := client.StatObject(ctx, backup.Manifest.Artifact.Bucket, backup.Manifest.Artifact.Key, minio.StatObjectOptions{}); err == nil {
		_ = conn.Close(ctx)
		t.Fatal("recovery restore wrote the model artifact before rejecting the dirty PostgreSQL target")
	}
	if _, err := conn.Exec(ctx, `DROP TABLE public.recovery_dirty_guard`); err != nil {
		_ = conn.Close(ctx)
		t.Fatalf("remove dirty PostgreSQL target fixture: %v", err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatalf("close dirty PostgreSQL target fixture: %v", err)
	}

	// A dirty object namespace must fail before pg_restore mutates PostgreSQL.
	dirtyKey := prefix + "/dirty-marker"
	dirtyPayload := []byte("dirty")
	if _, err := client.PutObject(ctx, bucket, dirtyKey, bytes.NewReader(dirtyPayload), int64(len(dirtyPayload)), minio.PutObjectOptions{}); err != nil {
		t.Fatalf("create dirty S3 target fixture: %v", err)
	}
	if _, err := Restore(ctx, restoreConfig); err == nil {
		t.Fatal("recovery restore accepted a dirty S3 target namespace")
	}
	if relations := recoveryPublicRelations(t, ctx, dsn); relations != 0 {
		t.Fatalf("recovery restore mutated PostgreSQL before rejecting dirty S3 target: %d relations", relations)
	}
	if err := client.RemoveObject(ctx, bucket, dirtyKey, minio.RemoveObjectOptions{}); err != nil {
		t.Fatalf("remove dirty S3 target fixture: %v", err)
	}

	restored, err := Restore(ctx, restoreConfig)
	if err != nil {
		t.Fatalf("restore disaster recovery bundle: %v", err)
	}
	if restored.ModelVersion != state.Model.GetModelVersion() || restored.RoundID != state.Model.GetRoundId() || restored.AuditHead.Sequence != 1 {
		t.Fatalf("restored recovery result = %#v", restored)
	}

	verifiedStore, err := coordinator.NewPostgresStateStoreWithArtifacts(ctx, dsn, restoreArtifacts)
	if err != nil {
		t.Fatalf("open restored state for final verification: %v", err)
	}
	defer verifiedStore.Close()
	loaded, err := verifiedStore.Load(ctx)
	if err != nil {
		t.Fatalf("load restored state: %v", err)
	}
	if loaded.Model.GetModelVersion() != state.Model.GetModelVersion() || loaded.Model.GetRoundId() != state.Model.GetRoundId() {
		t.Fatalf("restored model = %q round %d", loaded.Model.GetModelVersion(), loaded.Model.GetRoundId())
	}
	if len(loaded.Registrations) != 1 || loaded.Registrations[0].Generation != 2 || loaded.Registrations[0].RegistrationID != "opaque-recovery-registration" {
		t.Fatalf("restored registration lifecycle = %#v", loaded.Registrations)
	}
}

func integrationEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Skipf("%s is not configured", name)
	}
	return value
}

func resetRecoveryDatabase(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect recovery PostgreSQL fixture: %v", err)
	}
	defer conn.Close(ctx)
	for _, table := range []string{"ztfl_audit_events", "ztfl_coordinator_state", "ztfl_schema_migrations"} {
		if _, err := conn.Exec(ctx, `DROP TABLE IF EXISTS `+table); err != nil {
			t.Fatalf("drop recovery fixture table %s: %v", table, err)
		}
	}
}

func recoveryPublicRelations(t *testing.T, ctx context.Context, dsn string) int {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect recovery PostgreSQL fixture: %v", err)
	}
	defer conn.Close(ctx)
	var count int
	if err := conn.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public'
		  AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
	`).Scan(&count); err != nil {
		t.Fatalf("count recovery public relations: %v", err)
	}
	return count
}

func recoveryMinioClient(t *testing.T, endpoint, accessKey, secretKey string) *minio.Client {
	t.Helper()
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		t.Fatalf("parse recovery S3 endpoint %q: %v", endpoint, err)
	}
	client, err := minio.New(parsed.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:       parsed.Scheme == "https",
		Region:       "us-east-1",
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		t.Fatalf("create recovery MinIO client: %v", err)
	}
	return client
}

func recoveryNPY(values []float32) []byte {
	header := fmt.Sprintf("{'descr': '<f4', 'fortran_order': False, 'shape': (%d,), }", len(values))
	padding := 16 - ((10 + len(header) + 1) % 16)
	if padding == 16 {
		padding = 0
	}
	for i := 0; i < padding; i++ {
		header += " "
	}
	header += "\n"
	payload := make([]byte, 10+len(header)+len(values)*4)
	copy(payload[:6], []byte("\x93NUMPY"))
	payload[6] = 1
	payload[7] = 0
	binary.LittleEndian.PutUint16(payload[8:10], uint16(len(header)))
	copy(payload[10:], header)
	body := payload[10+len(header):]
	for index, value := range values {
		binary.LittleEndian.PutUint32(body[index*4:index*4+4], math.Float32bits(value))
	}
	return payload
}
