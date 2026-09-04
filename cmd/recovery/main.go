package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/coordinator"
	"github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/recovery"
)

func main() {
	if len(os.Args) < 2 {
		usageAndExit("expected backup or restore subcommand")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	switch os.Args[1] {
	case "backup":
		if err := runBackup(ctx, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "recovery backup failed: %v\n", err)
			os.Exit(1)
		}
	case "restore":
		if err := runRestore(ctx, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "recovery restore failed: %v\n", err)
			os.Exit(1)
		}
	default:
		usageAndExit("unknown subcommand " + os.Args[1])
	}
}

func runBackup(ctx context.Context, args []string) error {
	set := flag.NewFlagSet("backup", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	postgresDSN := set.String("postgres-dsn", env("ZTFL_POSTGRES_DSN", ""), "PostgreSQL coordinator DSN")
	output := set.String("output", env("ZTFL_RECOVERY_OUTPUT", ""), "new recovery bundle directory")
	pgDump := set.String("pg-dump", env("ZTFL_PG_DUMP", "pg_dump"), "pg_dump executable")
	s3Flags := addS3Flags(set)
	if err := set.Parse(args); err != nil {
		return err
	}
	artifacts, err := artifactStoreFromFlags(s3Flags)
	if err != nil {
		return err
	}
	result, err := recovery.Backup(ctx, recovery.BackupConfig{
		PostgresDSN: *postgresDSN,
		Artifacts:   artifacts,
		OutputDir:   *output,
		PgDumpPath:  *pgDump,
	})
	if err != nil {
		return err
	}
	return printJSON(map[string]any{
		"operation":       "backup",
		"output":          *output,
		"model_version":   result.Manifest.Database.ModelVersion,
		"round_id":        result.Manifest.Database.RoundID,
		"audit_sequence":  result.Manifest.Audit.HeadSequence,
		"pg_dump_version": result.PgDumpVersion,
	})
}

func runRestore(ctx context.Context, args []string) error {
	set := flag.NewFlagSet("restore", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	postgresDSN := set.String("postgres-dsn", env("ZTFL_POSTGRES_DSN", ""), "clean PostgreSQL target DSN")
	input := set.String("input", env("ZTFL_RECOVERY_INPUT", ""), "recovery bundle directory")
	pgRestore := set.String("pg-restore", env("ZTFL_PG_RESTORE", "pg_restore"), "pg_restore executable")
	allowDestructive := set.Bool("allow-destructive", envBool("ZTFL_RECOVERY_ALLOW_DESTRUCTIVE", false), "explicitly approve restore into a clean target database")
	s3Flags := addS3Flags(set)
	if err := set.Parse(args); err != nil {
		return err
	}
	artifacts, err := artifactStoreFromFlags(s3Flags)
	if err != nil {
		return err
	}
	result, err := recovery.Restore(ctx, recovery.RestoreConfig{
		PostgresDSN:      *postgresDSN,
		Artifacts:        artifacts,
		InputDir:         *input,
		PgRestorePath:    *pgRestore,
		AllowDestructive: *allowDestructive,
	})
	if err != nil {
		return err
	}
	return printJSON(map[string]any{
		"operation":          "restore",
		"input":              *input,
		"model_version":      result.ModelVersion,
		"round_id":           result.RoundID,
		"audit_sequence":     result.AuditHead.Sequence,
		"pg_restore_version": result.PgRestoreVersion,
	})
}

type s3FlagSet struct {
	endpoint      *string
	bucket        *string
	prefix        *string
	region        *string
	allowInsecure *bool
	pathStyle     *bool
}

func addS3Flags(set *flag.FlagSet) s3FlagSet {
	return s3FlagSet{
		endpoint:      set.String("s3-endpoint", env("ZTFL_S3_ENDPOINT", ""), "S3-compatible endpoint URL"),
		bucket:        set.String("s3-bucket", env("ZTFL_S3_BUCKET", ""), "S3-compatible model artifact bucket"),
		prefix:        set.String("s3-prefix", env("ZTFL_S3_PREFIX", "models"), "S3 model artifact prefix"),
		region:        set.String("s3-region", env("ZTFL_S3_REGION", "us-east-1"), "S3 region"),
		allowInsecure: set.Bool("s3-allow-insecure-http", envBool("ZTFL_S3_ALLOW_INSECURE_HTTP", false), "allow HTTP for trusted local/test S3"),
		pathStyle:     set.Bool("s3-force-path-style", envBool("ZTFL_S3_FORCE_PATH_STYLE", false), "force path-style S3 addressing"),
	}
}

func artifactStoreFromFlags(flags s3FlagSet) (coordinator.ModelArtifactStore, error) {
	endpoint := strings.TrimSpace(*flags.endpoint)
	bucket := strings.TrimSpace(*flags.bucket)
	if endpoint == "" && bucket == "" {
		return nil, nil
	}
	accessKey := env("ZTFL_S3_ACCESS_KEY_ID", os.Getenv("AWS_ACCESS_KEY_ID"))
	secretKey := env("ZTFL_S3_SECRET_ACCESS_KEY", os.Getenv("AWS_SECRET_ACCESS_KEY"))
	if endpoint == "" || bucket == "" || accessKey == "" || secretKey == "" {
		return nil, errors.New("S3 recovery configuration requires endpoint, bucket, access key ID, and secret access key")
	}
	return coordinator.NewS3ModelArtifactStore(coordinator.S3ArtifactStoreConfig{
		EndpointURL:       endpoint,
		Bucket:            bucket,
		Prefix:            *flags.prefix,
		Region:            *flags.region,
		AccessKeyID:       accessKey,
		SecretAccessKey:   secretKey,
		SessionToken:      env("ZTFL_S3_SESSION_TOKEN", os.Getenv("AWS_SESSION_TOKEN")),
		AllowInsecureHTTP: *flags.allowInsecure,
		ForcePathStyle:    *flags.pathStyle,
	})
}

func env(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func usageAndExit(message string) {
	fmt.Fprintf(os.Stderr, "%s\nusage: ztfl-recovery <backup|restore> [flags]\n", message)
	os.Exit(2)
}
