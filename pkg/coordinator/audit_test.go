package coordinator

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestAuditEventValidationMinimizesRegistrationSecrets(t *testing.T) {
	secret := "registration-bearer-secret"
	event := AuditEvent{
		SchemaVersion:      auditSchemaVersion,
		OccurredAt:         normalizeAuditTime(time.Date(2026, 9, 4, 17, 30, 0, 123456000, time.UTC)),
		Type:               AuditEventNodeRegistered,
		Outcome:            auditOutcomeSuccess,
		NodeID:             "worker-a",
		RegistrationIDHash: hashAuditOpaqueIdentifier(secret),
		ModelVersion:       "bootstrap",
		LeaseExpiresUnix:   1_788_543_600,
	}
	if err := validateAuditEvent(event); err != nil {
		t.Fatalf("valid registration audit event rejected: %v", err)
	}
	if event.RegistrationIDHash == secret || strings.Contains(event.RegistrationIDHash, secret) {
		t.Fatal("registration audit metadata exposed the plaintext registration identifier")
	}

	plaintext := event
	plaintext.RegistrationIDHash = secret
	if err := validateAuditEvent(plaintext); err == nil {
		t.Fatal("plaintext registration identifier was accepted as an audit hash")
	}
}

func TestAuditRecordChainVerificationDetectsTampering(t *testing.T) {
	occurredAt := normalizeAuditTime(time.Date(2026, 9, 4, 17, 31, 0, 654321000, time.UTC))
	first := AuditEvent{
		SchemaVersion: auditSchemaVersion,
		OccurredAt:    occurredAt,
		Type:          AuditEventStateInitialized,
		Outcome:       auditOutcomeSuccess,
		ModelVersion:  "bootstrap",
	}
	firstHash, err := auditRecordHash(1, auditEventID(1), nil, first)
	if err != nil {
		t.Fatalf("hash first audit record: %v", err)
	}
	second := AuditEvent{
		SchemaVersion: auditSchemaVersion,
		OccurredAt:    occurredAt.Add(time.Microsecond),
		Type:          AuditEventStateRecovered,
		Outcome:       auditOutcomeSuccess,
		ModelVersion:  "bootstrap",
	}
	secondHash, err := auditRecordHash(2, auditEventID(2), firstHash, second)
	if err != nil {
		t.Fatalf("hash second audit record: %v", err)
	}

	records := []AuditRecord{
		{
			Sequence:  1,
			EventID:   auditEventID(1),
			Event:     first,
			EventHash: hex.EncodeToString(firstHash),
		},
		{
			Sequence:     2,
			EventID:      auditEventID(2),
			Event:        second,
			PreviousHash: hex.EncodeToString(firstHash),
			EventHash:    hex.EncodeToString(secondHash),
		},
	}
	if err := verifyAuditRecords(records, nil, 0); err != nil {
		t.Fatalf("valid audit chain rejected: %v", err)
	}

	tampered := append([]AuditRecord(nil), records...)
	tampered[1].Event.ModelVersion = "tampered"
	if err := verifyAuditRecords(tampered, nil, 0); err == nil {
		t.Fatal("tampered audit event payload was accepted")
	}

	brokenLink := append([]AuditRecord(nil), records...)
	brokenLink[1].PreviousHash = strings.Repeat("00", 32)
	if err := verifyAuditRecords(brokenLink, nil, 0); err == nil {
		t.Fatal("broken audit previous-hash link was accepted")
	}
}

func TestExportAuditNDJSONDoesNotExposeOpaqueRegistrationSecret(t *testing.T) {
	secret := "do-not-export-this-registration-id"
	event := AuditEvent{
		SchemaVersion:      auditSchemaVersion,
		OccurredAt:         normalizeAuditTime(time.Date(2026, 9, 4, 17, 32, 0, 0, time.UTC)),
		Type:               AuditEventLeaseRenewed,
		Outcome:            auditOutcomeSuccess,
		NodeID:             "worker-a",
		RegistrationIDHash: hashAuditOpaqueIdentifier(secret),
		ModelVersion:       "bootstrap",
		LeaseExpiresUnix:   1_788_543_660,
	}
	hash, err := auditRecordHash(1, auditEventID(1), nil, event)
	if err != nil {
		t.Fatalf("hash audit event: %v", err)
	}
	record := AuditRecord{
		Sequence:  1,
		EventID:   auditEventID(1),
		Event:     event,
		EventHash: hex.EncodeToString(hash),
	}
	if err := verifyAuditRecords([]AuditRecord{record}, nil, 0); err != nil {
		t.Fatalf("verify audit record before export: %v", err)
	}

	var output bytes.Buffer
	if err := ExportAuditNDJSON(&output, []AuditRecord{record}); err != nil {
		t.Fatalf("export audit NDJSON: %v", err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("audit export exposed the plaintext registration identifier")
	}
	if lines := strings.Count(strings.TrimSpace(output.String()), "\n") + 1; lines != 1 {
		t.Fatalf("audit export lines = %d, want 1", lines)
	}
}
