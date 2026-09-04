package coordinator

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
)

func TestRegistrationLifecycleAuditEventsMinimizeSecrets(t *testing.T) {
	snapshot := testStateSnapshot(t)
	rotationSecret := "new-registration-secret"
	rotation := rotationAuditEvent(
		&flv1.RotateRegistrationRequest{NodeId: "worker-a", RegistrationId: "old-secret"},
		&flv1.RotateRegistrationResponse{
			Accepted:             true,
			RegistrationId:       rotationSecret,
			LeaseExpiresUnix:     time.Now().UTC().Add(time.Hour).Unix(),
			CredentialGeneration: 2,
		},
		snapshot,
	)
	if err := validateAuditEvent(rotation); err != nil {
		t.Fatalf("rotation audit event rejected: %v", err)
	}
	encoded, err := json.Marshal(rotation)
	if err != nil {
		t.Fatalf("encode rotation audit event: %v", err)
	}
	if strings.Contains(string(encoded), rotationSecret) || strings.Contains(string(encoded), "old-secret") {
		t.Fatal("rotation audit event exposed a plaintext registration credential")
	}
	if rotation.CredentialGeneration != 2 {
		t.Fatalf("rotation generation = %d, want 2", rotation.CredentialGeneration)
	}

	revocation := revocationAuditEvent(
		&flv1.RevokeRegistrationRequest{
			NodeId:       "admin-a",
			TargetNodeId: "worker-a",
			Reason:       "sensitive operator note that must not enter audit payload",
		},
		&flv1.RevokeRegistrationResponse{
			Accepted:          true,
			TargetNodeId:      "worker-a",
			RevokedGeneration: 2,
			RevokedAtUnix:     time.Now().UTC().Unix(),
			BlockedUntilUnix:  time.Now().UTC().Add(time.Hour).Unix(),
		},
		snapshot,
	)
	if err := validateAuditEvent(revocation); err != nil {
		t.Fatalf("revocation audit event rejected: %v", err)
	}
	encoded, err = json.Marshal(revocation)
	if err != nil {
		t.Fatalf("encode revocation audit event: %v", err)
	}
	if strings.Contains(string(encoded), "sensitive operator note") {
		t.Fatal("revocation audit event exposed the operator reason")
	}
	if revocation.NodeID != "admin-a" || revocation.TargetNodeID != "worker-a" || revocation.CredentialGeneration != 2 {
		t.Fatalf("revocation audit metadata = %#v", revocation)
	}
}

func TestAuditLifecycleFieldsPreserveLegacyCanonicalJSON(t *testing.T) {
	event := AuditEvent{
		SchemaVersion:      auditSchemaVersion,
		OccurredAt:         normalizeAuditTime(time.Date(2026, 9, 4, 17, 30, 0, 123456000, time.UTC)),
		Type:               AuditEventNodeRegistered,
		Outcome:            auditOutcomeSuccess,
		NodeID:             "worker-a",
		RegistrationIDHash: hashAuditOpaqueIdentifier("legacy-secret"),
		RoundID:            0,
		ModelVersion:       "bootstrap",
		LeaseExpiresUnix:   1_788_543_600,
	}
	_, encoded, err := canonicalAuditEvent(event)
	if err != nil {
		t.Fatalf("canonicalize legacy audit event: %v", err)
	}
	payload := string(encoded)
	for _, forbidden := range []string{"credential_generation", "target_node_id", "blocked_until_unix"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("legacy canonical audit JSON unexpectedly contains %q: %s", forbidden, payload)
		}
	}
}
