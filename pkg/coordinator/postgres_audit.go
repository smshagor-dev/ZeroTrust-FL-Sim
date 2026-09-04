package coordinator

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	"google.golang.org/protobuf/proto"
)

const postgresAuditLockKey int64 = 0x5A54464C41554454

type auditedStateStore interface {
	StateStore
	CommitWithAudit(context.Context, StateSnapshot, []AuditEvent) error
}

func (s *PostgresStateStore) CommitWithAudit(ctx context.Context, snapshot StateSnapshot, events []AuditEvent) error {
	if len(events) == 0 {
		return s.Commit(ctx, snapshot)
	}
	if s == nil || s.pool == nil {
		return errors.New("PostgreSQL state store is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateStateSnapshot(snapshot); err != nil {
		return fmt.Errorf("validate PostgreSQL coordinator state before audited commit: %w", err)
	}
	for index := range events {
		events[index].OccurredAt = normalizeAuditTime(events[index].OccurredAt)
		if err := validateAuditEvent(events[index]); err != nil {
			return fmt.Errorf("validate audit event %d before commit: %w", index, err)
		}
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
			return fmt.Errorf("persist global model artifact for audited state: %w", err)
		}
		if len(modelForStorage.GetSha256()) != len(ref.SHA256) || !bytes.Equal(modelForStorage.GetSha256(), ref.SHA256) {
			return errors.New("model artifact digest does not match validated global model digest")
		}
		artifactRef = &ref
		modelForStorage.WeightsPayload = nil
	}
	modelBytes, err := proto.Marshal(modelForStorage)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL global model for audited state: %w", err)
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
		return fmt.Errorf("begin PostgreSQL audited state transaction: %w", err)
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
		return fmt.Errorf("write PostgreSQL coordinator state in audited transaction: %w", err)
	}
	if err := appendAuditEventsTx(ctx, tx, events); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit PostgreSQL audited state transaction: %w", err)
	}
	return nil
}

func appendAuditEventsTx(ctx context.Context, tx pgx.Tx, events []AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, postgresAuditLockKey); err != nil {
		return fmt.Errorf("lock PostgreSQL audit chain: %w", err)
	}

	var (
		lastSequence int64
		previousHash []byte
	)
	err := tx.QueryRow(ctx, `
		SELECT sequence, event_hash
		FROM ztfl_audit_events
		ORDER BY sequence DESC
		LIMIT 1
	`).Scan(&lastSequence, &previousHash)
	if errors.Is(err, pgx.ErrNoRows) {
		lastSequence = 0
		previousHash = nil
	} else if err != nil {
		return fmt.Errorf("read PostgreSQL audit chain head: %w", err)
	}

	for index, rawEvent := range events {
		event, payload, err := canonicalAuditEvent(rawEvent)
		if err != nil {
			return fmt.Errorf("canonicalize audit event %d: %w", index, err)
		}
		sequence := lastSequence + 1
		eventID := auditEventID(sequence)
		eventHash, err := auditRecordHash(sequence, eventID, previousHash, event)
		if err != nil {
			return fmt.Errorf("hash audit event %d: %w", index, err)
		}
		var previous any
		if len(previousHash) > 0 {
			previous = previousHash
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO ztfl_audit_events (
				sequence, event_id, occurred_at, event_type, event_payload, previous_hash, event_hash
			) VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
		`, sequence, eventID, event.OccurredAt, event.Type, string(payload), previous, eventHash)
		if err != nil {
			return fmt.Errorf("append PostgreSQL audit event %s: %w", event.Type, err)
		}
		lastSequence = sequence
		previousHash = eventHash
	}
	return nil
}

func (s *PostgresStateStore) ReadAuditEvents(ctx context.Context, afterSequence int64, limit int) ([]AuditRecord, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("PostgreSQL state store is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if afterSequence < 0 {
		return nil, errors.New("audit cursor must not be negative")
	}
	if limit <= 0 {
		limit = 1000
	}
	if limit > maxAuditExportRows {
		return nil, fmt.Errorf("audit export limit exceeds %d rows", maxAuditExportRows)
	}

	var previousHash []byte
	if afterSequence > 0 {
		cursor, err := s.readAuditRecord(ctx, afterSequence)
		if err != nil {
			return nil, fmt.Errorf("read audit cursor %d: %w", afterSequence, err)
		}
		var cursorPrevious []byte
		if afterSequence > 1 {
			if err := s.pool.QueryRow(ctx, `SELECT event_hash FROM ztfl_audit_events WHERE sequence = $1`, afterSequence-1).Scan(&cursorPrevious); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, fmt.Errorf("audit chain is missing sequence %d", afterSequence-1)
				}
				return nil, fmt.Errorf("read audit cursor predecessor: %w", err)
			}
		}
		if err := verifyAuditRecords([]AuditRecord{cursor}, cursorPrevious, afterSequence-1); err != nil {
			return nil, fmt.Errorf("verify audit cursor: %w", err)
		}
		previousHash, err = hex.DecodeString(cursor.EventHash)
		if err != nil {
			return nil, fmt.Errorf("decode verified audit cursor hash: %w", err)
		}
	}

	rows, err := s.pool.Query(ctx, `
		SELECT sequence, event_id, occurred_at, event_type, event_payload, previous_hash, event_hash
		FROM ztfl_audit_events
		WHERE sequence > $1
		ORDER BY sequence
		LIMIT $2
	`, afterSequence, limit)
	if err != nil {
		return nil, fmt.Errorf("query PostgreSQL audit events: %w", err)
	}
	defer rows.Close()

	records := make([]AuditRecord, 0, limit)
	for rows.Next() {
		record, err := scanAuditRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate PostgreSQL audit events: %w", err)
	}
	if err := verifyAuditRecords(records, previousHash, afterSequence); err != nil {
		return nil, fmt.Errorf("verify PostgreSQL audit chain: %w", err)
	}
	return records, nil
}

func (s *PostgresStateStore) readAuditRecord(ctx context.Context, sequence int64) (AuditRecord, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT sequence, event_id, occurred_at, event_type, event_payload, previous_hash, event_hash
		FROM ztfl_audit_events
		WHERE sequence = $1
	`, sequence)
	record, err := scanAuditRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuditRecord{}, fmt.Errorf("audit sequence %d does not exist", sequence)
	}
	return record, err
}

type auditRowScanner interface {
	Scan(dest ...any) error
}

func scanAuditRecord(row auditRowScanner) (AuditRecord, error) {
	var (
		sequence     int64
		eventID      string
		occurredAt   time.Time
		eventType    string
		payload      []byte
		previousHash []byte
		eventHash    []byte
	)
	if err := row.Scan(&sequence, &eventID, &occurredAt, &eventType, &payload, &previousHash, &eventHash); err != nil {
		return AuditRecord{}, err
	}

	var event AuditEvent
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return AuditRecord{}, fmt.Errorf("decode PostgreSQL audit payload at sequence %d: %w", sequence, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return AuditRecord{}, fmt.Errorf("decode PostgreSQL audit payload at sequence %d: %w", sequence, err)
	}
	if !event.OccurredAt.Equal(occurredAt) {
		return AuditRecord{}, fmt.Errorf("audit occurred_at column disagrees with payload at sequence %d", sequence)
	}
	if event.Type != eventType {
		return AuditRecord{}, fmt.Errorf("audit event_type column disagrees with payload at sequence %d", sequence)
	}
	if len(eventHash) != 32 || (len(previousHash) != 0 && len(previousHash) != 32) {
		return AuditRecord{}, fmt.Errorf("audit hash length is invalid at sequence %d", sequence)
	}
	return AuditRecord{
		Sequence:     sequence,
		EventID:      eventID,
		Event:        event,
		PreviousHash: hex.EncodeToString(previousHash),
		EventHash:    hex.EncodeToString(eventHash),
	}, nil
}
