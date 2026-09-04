package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/coordinator"
)

func main() {
	var (
		afterSequence = flag.Int64("after-sequence", 0, "export records after this verified audit sequence")
		limit         = flag.Int("limit", 1000, "maximum audit records to export (max 10000)")
		output        = flag.String("output", "-", "NDJSON output path; '-' writes to stdout")
	)
	flag.Parse()

	if *afterSequence < 0 {
		fmt.Fprintln(os.Stderr, "after-sequence must not be negative")
		os.Exit(2)
	}
	if *limit <= 0 || *limit > 10_000 {
		fmt.Fprintln(os.Stderr, "limit must be between 1 and 10000")
		os.Exit(2)
	}
	dsn := os.Getenv("ZTFL_POSTGRES_DSN")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "ZTFL_POSTGRES_DSN is required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := coordinator.NewPostgresStateStore(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open PostgreSQL audit store: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	records, err := store.ReadAuditEvents(ctx, *afterSequence, *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify PostgreSQL audit chain: %v\n", err)
		os.Exit(1)
	}

	writer, cleanup, err := auditOutput(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open audit export output: %v\n", err)
		os.Exit(1)
	}
	success := false
	defer func() { cleanup(success) }()
	if err := coordinator.ExportAuditNDJSON(writer, records); err != nil {
		fmt.Fprintf(os.Stderr, "export audit records: %v\n", err)
		os.Exit(1)
	}
	if syncer, ok := writer.(interface{ Sync() error }); ok {
		if err := syncer.Sync(); err != nil {
			fmt.Fprintf(os.Stderr, "sync audit export output: %v\n", err)
			os.Exit(1)
		}
	}
	if closer, ok := writer.(io.Closer); ok && writer != os.Stdout {
		if err := closer.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close audit export output: %v\n", err)
			os.Exit(1)
		}
	}
	success = true

	lastSequence := *afterSequence
	if len(records) > 0 {
		lastSequence = records[len(records)-1].Sequence
	}
	fmt.Fprintf(os.Stderr, "exported %d verified audit record(s); last_sequence=%d\n", len(records), lastSequence)
}

func auditOutput(path string) (io.Writer, func(bool), error) {
	if path == "-" {
		return os.Stdout, func(bool) {}, nil
	}
	if path == "" {
		return nil, nil, errors.New("output path must not be empty")
	}
	cleaned := filepath.Clean(path)
	file, err := os.OpenFile(cleaned, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func(success bool) {
		_ = file.Close()
		if !success {
			_ = os.Remove(cleaned)
		}
	}
	return file, cleanup, nil
}
