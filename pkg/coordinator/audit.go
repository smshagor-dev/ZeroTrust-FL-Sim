package coordinator

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	auditSchemaVersion = 1
	maxAuditExportRows = 10_000
	maxAuditRoundID    = uint64(1<<63 - 1)

	AuditEventStateInitialized = "coordinator.state.initialized"
	AuditEventStateRecovered   = "coordinator.state.recovered"
	AuditEventNodeRegistered   = "node.registered"
	AuditEventLeaseRenewed     = "node.lease.renewed"
	AuditEventUpdateAccepted   = "model.update.accepted"
	AuditEventRoundAggregated  = "model.round.aggregated"

	auditOutcomeSuccess = "success"
)

// AuditEvent is the secret-minimized, versioned payload persisted for a
// successful recovery-critical coordinator transition. It intentionally does
// not contain request nonces, JWTs, model/update payloads, private keys, or
// plaintext registration bearer identifiers.
type AuditEvent struct {
	SchemaVersion      int       `json:"schema_version"`
	OccurredAt         time.Time `json:"occurred_at"`
	Type               string    `json:"type"`
	Outcome            string    `json:"outcome"`
	NodeID             string    `json:"node_id,omitempty"`
	RegistrationIDHash string    `json:"registration_id_hash,omitempty"`
	UpdateID           string    `json:"update_id,omitempty"`
	UpdateSHA256       string    `json:"update_sha256,omitempty"`
	BaseModelVersion   string    `json:"base_model_version,omitempty"`
	RoundID            uint64    `json:"round_id"`
	ModelVersion       string    `json:"model_version,omitempty"`
	ModelSHA256        string    `json:"model_sha256,omitempty"`
	SampleCount        uint64    `json:"sample_count,omitempty"`
	PendingUpdates     int       `json:"pending_updates,omitempty"`
	Quorum             int       `json:"quorum,omitempty"`
	AggregationMethod  string    `json:"aggregation_method,omitempty"`
	LeaseExpiresUnix   int64     `json:"lease_expires_unix,omitempty"`
}

// AuditRecord is the exported append-only record. The event hash commits to
// the sequence, event ID, previous hash, and canonical AuditEvent payload.
type AuditRecord struct {
	Sequence     int64      `json:"sequence"`
	EventID      string     `json:"event_id"`
	Event        AuditEvent `json:"event"`
	PreviousHash string     `json:"previous_hash,omitempty"`
	EventHash    string     `json:"event_hash"`
}

type auditHashEnvelope struct {
	Sequence     int64      `json:"sequence"`
	EventID      string     `json:"event_id"`
	PreviousHash string     `json:"previous_hash,omitempty"`
	Event        AuditEvent `json:"event"`
}

func newAuditEvent(eventType string) AuditEvent {
	return AuditEvent{
		SchemaVersion: auditSchemaVersion,
		OccurredAt:    normalizeAuditTime(time.Now()),
		Type:          eventType,
		Outcome:       auditOutcomeSuccess,
	}
}

func normalizeAuditTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func hashAuditOpaqueIdentifier(value string) string {
	if value == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func modelAuditDigestHex(digest []byte) string {
	if len(digest) == 0 {
		return ""
	}
	return hex.EncodeToString(digest)
}

func validateAuditEvent(event AuditEvent) error {
	if event.SchemaVersion != auditSchemaVersion {
		return fmt.Errorf("unsupported audit schema version %d", event.SchemaVersion)
	}
	if event.OccurredAt.IsZero() {
		return errors.New("audit event occurred_at is required")
	}
	if !event.OccurredAt.Equal(normalizeAuditTime(event.OccurredAt)) {
		return errors.New("audit event occurred_at must be UTC microsecond precision")
	}
	if event.Outcome != auditOutcomeSuccess {
		return fmt.Errorf("unsupported audit outcome %q", event.Outcome)
	}
	if len(event.NodeID) > 256 || len(event.UpdateID) > 256 || len(event.BaseModelVersion) > 512 || len(event.ModelVersion) > 512 || len(event.AggregationMethod) > 64 {
		return errors.New("audit event contains an oversized identifier")
	}
	if event.RoundID > maxAuditRoundID {
		return errors.New("audit round_id exceeds PostgreSQL BIGINT range")
	}
	if event.SampleCount > maxReportedSampleCount {
		return fmt.Errorf("audit sample_count exceeds %d", maxReportedSampleCount)
	}
	if event.PendingUpdates < 0 || event.PendingUpdates > 1_000_000 || event.Quorum < 0 || event.Quorum > 1_000_000 {
		return errors.New("audit event contains an invalid pending/quorum count")
	}
	for name, value := range map[string]string{
		"registration_id_hash": event.RegistrationIDHash,
		"update_sha256":        event.UpdateSHA256,
		"model_sha256":         event.ModelSHA256,
	} {
		if value == "" {
			continue
		}
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size || value != strings.ToLower(value) {
			return fmt.Errorf("audit %s must be a lowercase 32-byte SHA-256 hex digest", name)
		}
	}

	switch event.Type {
	case AuditEventStateInitialized, AuditEventStateRecovered:
		if event.ModelVersion == "" {
			return errors.New("coordinator state audit event requires model_version")
		}
	case AuditEventNodeRegistered, AuditEventLeaseRenewed:
		if event.NodeID == "" || event.RegistrationIDHash == "" || event.LeaseExpiresUnix <= 0 {
			return errors.New("registration/lease audit event requires node, registration hash, and lease expiry")
		}
	case AuditEventUpdateAccepted:
		if event.NodeID == "" || event.RegistrationIDHash == "" || event.UpdateID == "" || event.UpdateSHA256 == "" || event.BaseModelVersion == "" || event.Quorum <= 0 {
			return errors.New("update audit event is missing required update metadata")
		}
	case AuditEventRoundAggregated:
		if event.NodeID == "" || event.ModelVersion == "" || event.ModelSHA256 == "" || event.Quorum <= 0 || event.AggregationMethod == "" {
			return errors.New("round aggregation audit event is missing required model metadata")
		}
		if _, err := normalizeAggregationMethod(event.AggregationMethod); err != nil {
			return fmt.Errorf("validate audit aggregation method: %w", err)
		}
	default:
		return fmt.Errorf("unsupported audit event type %q", event.Type)
	}
	return nil
}

func canonicalAuditEvent(event AuditEvent) (AuditEvent, []byte, error) {
	event.OccurredAt = normalizeAuditTime(event.OccurredAt)
	if err := validateAuditEvent(event); err != nil {
		return AuditEvent{}, nil, err
	}
	data, err := json.Marshal(event)
	if err != nil {
		return AuditEvent{}, nil, fmt.Errorf("encode canonical audit event: %w", err)
	}
	return event, data, nil
}

func auditRecordHash(sequence int64, eventID string, previousHash []byte, event AuditEvent) ([]byte, error) {
	if sequence <= 0 {
		return nil, errors.New("audit sequence must be positive")
	}
	if eventID != auditEventID(sequence) {
		return nil, fmt.Errorf("audit event ID %q does not match sequence %d", eventID, sequence)
	}
	if len(previousHash) != 0 && len(previousHash) != sha256.Size {
		return nil, errors.New("audit previous hash must be empty or 32 bytes")
	}
	canonicalEvent, _, err := canonicalAuditEvent(event)
	if err != nil {
		return nil, err
	}
	envelope := auditHashEnvelope{
		Sequence:     sequence,
		EventID:      eventID,
		PreviousHash: hex.EncodeToString(previousHash),
		Event:        canonicalEvent,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode audit hash envelope: %w", err)
	}
	digest := sha256.Sum256(data)
	return digest[:], nil
}

func auditEventID(sequence int64) string {
	return fmt.Sprintf("audit-%020d", sequence)
}

func verifyAuditRecords(records []AuditRecord, previousHash []byte, previousSequence int64) error {
	if previousSequence < 0 {
		return errors.New("audit previous sequence must not be negative")
	}
	if len(previousHash) != 0 && len(previousHash) != sha256.Size {
		return errors.New("audit previous hash must be empty or 32 bytes")
	}
	expectedPrevious := append([]byte(nil), previousHash...)
	expectedSequence := previousSequence + 1
	for _, record := range records {
		if record.Sequence != expectedSequence {
			return fmt.Errorf("audit sequence discontinuity: got %d, want %d", record.Sequence, expectedSequence)
		}
		if record.EventID != auditEventID(record.Sequence) {
			return fmt.Errorf("audit event ID %q does not match sequence %d", record.EventID, record.Sequence)
		}
		storedPrevious, err := decodeAuditHash(record.PreviousHash, true)
		if err != nil {
			return fmt.Errorf("decode audit previous hash at sequence %d: %w", record.Sequence, err)
		}
		if !bytes.Equal(storedPrevious, expectedPrevious) {
			return fmt.Errorf("audit previous-hash link mismatch at sequence %d", record.Sequence)
		}
		storedHash, err := decodeAuditHash(record.EventHash, false)
		if err != nil {
			return fmt.Errorf("decode audit event hash at sequence %d: %w", record.Sequence, err)
		}
		calculated, err := auditRecordHash(record.Sequence, record.EventID, storedPrevious, record.Event)
		if err != nil {
			return fmt.Errorf("validate audit record %d: %w", record.Sequence, err)
		}
		if !bytes.Equal(storedHash, calculated) {
			return fmt.Errorf("audit event hash mismatch at sequence %d", record.Sequence)
		}
		expectedPrevious = storedHash
		expectedSequence++
	}
	return nil
}

func decodeAuditHash(value string, allowEmpty bool) ([]byte, error) {
	if value == "" {
		if allowEmpty {
			return nil, nil
		}
		return nil, errors.New("hash is required")
	}
	if value != strings.ToLower(value) {
		return nil, errors.New("hash must use lowercase hex")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("hash must encode exactly 32 bytes")
	}
	return decoded, nil
}

func ExportAuditNDJSON(writer io.Writer, records []AuditRecord) error {
	if writer == nil {
		return errors.New("audit export writer is required")
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return fmt.Errorf("write audit NDJSON record %d: %w", record.Sequence, err)
		}
	}
	return nil
}
