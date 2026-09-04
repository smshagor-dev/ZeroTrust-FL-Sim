package recovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

func runPgDump(ctx context.Context, toolPath, dsn, snapshotID, outputPath string, serverVersionNum int) (string, error) {
	if strings.TrimSpace(snapshotID) == "" || strings.ContainsAny(snapshotID, " \t\r\n\x00") {
		return "", errors.New("PostgreSQL recovery snapshot identifier is invalid")
	}
	major, version, err := postgresToolVersion(ctx, toolPath, "pg_dump")
	if err != nil {
		return "", err
	}
	if err := requireCompatiblePostgresTool(major, serverVersionNum, "pg_dump"); err != nil {
		return "", err
	}
	safeDSN, password, err := commandPostgresDSN(dsn)
	if err != nil {
		return "", err
	}
	command := exec.CommandContext(
		ctx,
		toolPath,
		"--format=custom",
		"--no-owner",
		"--no-privileges",
		"--snapshot="+snapshotID,
		"--table=public.ztfl_coordinator_state",
		"--table=public.ztfl_schema_migrations",
		"--table=public.ztfl_audit_events",
		"--file="+outputPath,
		"--dbname="+safeDSN,
	)
	command.Env = postgresCommandEnv(password)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("pg_dump recovery snapshot failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return version, nil
}

func runPgRestore(ctx context.Context, toolPath, dsn, inputPath string, sourceServerVersionNum int) (string, error) {
	major, version, err := postgresToolVersion(ctx, toolPath, "pg_restore")
	if err != nil {
		return "", err
	}
	if err := requireCompatiblePostgresTool(major, sourceServerVersionNum, "pg_restore"); err != nil {
		return "", err
	}
	safeDSN, password, err := commandPostgresDSN(dsn)
	if err != nil {
		return "", err
	}
	command := exec.CommandContext(
		ctx,
		toolPath,
		"--exit-on-error",
		"--no-owner",
		"--no-privileges",
		"--dbname="+safeDSN,
		inputPath,
	)
	command.Env = postgresCommandEnv(password)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("pg_restore recovery bundle failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return version, nil
}

func postgresToolVersion(ctx context.Context, toolPath, label string) (int, string, error) {
	if strings.TrimSpace(toolPath) == "" {
		toolPath = label
	}
	command := exec.CommandContext(ctx, toolPath, "--version")
	output, err := command.Output()
	if err != nil {
		return 0, "", fmt.Errorf("read %s version: %w", label, err)
	}
	version := strings.TrimSpace(string(output))
	fields := strings.Fields(version)
	if len(fields) == 0 {
		return 0, "", fmt.Errorf("%s returned an empty version", label)
	}
	numeric := fields[len(fields)-1]
	majorText := strings.SplitN(numeric, ".", 2)[0]
	major, err := strconv.Atoi(majorText)
	if err != nil || major <= 0 {
		return 0, "", fmt.Errorf("parse %s version %q", label, version)
	}
	return major, version, nil
}

func requireCompatiblePostgresTool(toolMajor, serverVersionNum int, label string) error {
	if serverVersionNum <= 0 {
		return errors.New("PostgreSQL server version number is invalid")
	}
	serverMajor := serverVersionNum / 10000
	if serverMajor < 10 {
		serverMajor = serverVersionNum / 10000
	}
	if toolMajor < serverMajor {
		return fmt.Errorf("%s major version %d is older than PostgreSQL server major version %d", label, toolMajor, serverMajor)
	}
	return nil
}

func commandPostgresDSN(raw string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", fmt.Errorf("parse PostgreSQL DSN for recovery command: %w", err)
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return "", "", errors.New("recovery tooling requires a postgres:// or postgresql:// DSN")
	}
	if parsed.Host == "" || parsed.Path == "" {
		return "", "", errors.New("recovery PostgreSQL DSN requires host and database")
	}
	var password string
	if parsed.User != nil {
		username := parsed.User.Username()
		password, _ = parsed.User.Password()
		if username != "" {
			parsed.User = url.User(username)
		} else {
			parsed.User = nil
		}
	}
	return parsed.String(), password, nil
}

func postgresCommandEnv(password string) []string {
	environment := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "PGPASSWORD=") {
			continue
		}
		environment = append(environment, entry)
	}
	if password != "" {
		environment = append(environment, "PGPASSWORD="+password)
	}
	return environment
}

func ensureCleanPostgresTarget(ctx context.Context, dsn string) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect clean recovery target: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping clean recovery target: %w", err)
	}
	var publicTables int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM pg_catalog.pg_tables
		WHERE schemaname = 'public'
	`).Scan(&publicTables); err != nil {
		return fmt.Errorf("inspect recovery target tables: %w", err)
	}
	if publicTables != 0 {
		return fmt.Errorf("recovery target database is not clean: public schema contains %d tables", publicTables)
	}
	return nil
}
