package security

import (
	"strings"
	"testing"
	"time"
)

func TestRegistrationCredentialRotationInvalidatesOldCredential(t *testing.T) {
	identity := lifecycleIdentity("worker-a", "edge-worker", "sha256:worker-a")
	store := NewRegistrationStore()
	first, err := store.Register(identity, "registration-1", time.Hour)
	if err != nil {
		t.Fatalf("register initial credential: %v", err)
	}
	if first.Generation != 1 {
		t.Fatalf("initial generation = %d, want 1", first.Generation)
	}

	rotated, err := store.Rotate(identity, first.RegistrationID, "registration-2", time.Hour)
	if err != nil {
		t.Fatalf("rotate registration credential: %v", err)
	}
	if rotated.Generation != 2 {
		t.Fatalf("rotated generation = %d, want 2", rotated.Generation)
	}
	if _, err := store.Validate(identity, first.RegistrationID); err == nil {
		t.Fatal("old registration credential remained valid after rotation")
	}
	if _, err := store.Validate(identity, rotated.RegistrationID); err != nil {
		t.Fatalf("rotated registration credential rejected: %v", err)
	}
}

func TestRegistrationRecoveryReplacementRequiresSameBinding(t *testing.T) {
	identity := lifecycleIdentity("worker-a", "edge-worker", "sha256:worker-a")
	store := NewRegistrationStore()
	first, err := store.Register(identity, "registration-1", time.Hour)
	if err != nil {
		t.Fatalf("register initial credential: %v", err)
	}

	replacement, err := store.Register(identity, "registration-2", time.Hour)
	if err != nil {
		t.Fatalf("same-binding recovery registration: %v", err)
	}
	if replacement.Generation != first.Generation+1 {
		t.Fatalf("replacement generation = %d, want %d", replacement.Generation, first.Generation+1)
	}
	if _, err := store.Validate(identity, first.RegistrationID); err == nil {
		t.Fatal("recovery replacement did not invalidate the previous credential")
	}

	otherCertificate := lifecycleIdentity(identity.NodeID, identity.Role, "sha256:other")
	if _, err := store.Register(otherCertificate, "registration-3", time.Hour); err == nil {
		t.Fatal("active registration was replaced by a different certificate binding")
	}
	otherRole := lifecycleIdentity(identity.NodeID, "observer", identity.CertificateFingerprint)
	if _, err := store.Register(otherRole, "registration-4", time.Hour); err == nil {
		t.Fatal("active registration was replaced by a different role binding")
	}
}

func TestRegistrationRevocationSurvivesSnapshotAndBlocksReregistration(t *testing.T) {
	identity := lifecycleIdentity("worker-a", "edge-worker", "sha256:worker-a")
	store := NewRegistrationStore()
	registered, err := store.Register(identity, "registration-1", time.Hour)
	if err != nil {
		t.Fatalf("register identity: %v", err)
	}
	revoked, err := store.Revoke(identity.NodeID, "operator response")
	if err != nil {
		t.Fatalf("revoke registration: %v", err)
	}
	if revoked.RevokedAt.IsZero() || revoked.RevocationReason != "operator response" {
		t.Fatalf("revocation metadata = %#v", revoked)
	}
	if store.IsRegistered(identity) {
		t.Fatal("revoked registration remained authorized")
	}
	if _, err := store.Validate(identity, registered.RegistrationID); err == nil {
		t.Fatal("revoked registration credential remained valid")
	}
	if _, err := store.Register(identity, "registration-2", time.Hour); err == nil {
		t.Fatal("revoked identity bypassed tombstone through re-registration")
	}

	snapshot := store.Snapshot()
	if len(snapshot) != 1 || snapshot[0].RevokedAt.IsZero() {
		t.Fatalf("revocation tombstone missing from snapshot: %#v", snapshot)
	}
	recovered := NewRegistrationStore()
	if err := recovered.RestoreSnapshot(snapshot); err != nil {
		t.Fatalf("restore revoked registration snapshot: %v", err)
	}
	if recovered.IsRegistered(identity) {
		t.Fatal("revoked registration became authorized after restart recovery")
	}
	if _, err := recovered.Register(identity, "registration-3", time.Hour); err == nil {
		t.Fatal("recovered revocation tombstone allowed early re-registration")
	}
}

func TestExpiredRevocationAllowsCleanReenrollment(t *testing.T) {
	identity := lifecycleIdentity("worker-a", "edge-worker", "sha256:worker-a")
	store := NewRegistrationStore()
	err := store.RestoreSnapshot([]Registration{{
		NodeID:                 identity.NodeID,
		Role:                   identity.Role,
		CertificateFingerprint: identity.CertificateFingerprint,
		RegistrationID:         "revoked-registration",
		ExpiresAt:              time.Now().UTC().Add(-time.Minute),
		Generation:             7,
		RevokedAt:              time.Now().UTC().Add(-2 * time.Minute),
		RevocationReason:       "expired lease tombstone",
	}})
	if err != nil {
		t.Fatalf("restore expired revocation: %v", err)
	}
	if got := store.Snapshot(); len(got) != 0 {
		t.Fatalf("expired revocation survived recovery: %#v", got)
	}
	registered, err := store.Register(identity, "fresh-registration", time.Hour)
	if err != nil {
		t.Fatalf("re-enroll after revoked lease expiry: %v", err)
	}
	if registered.Generation != 1 {
		t.Fatalf("fresh generation after expired tombstone cleanup = %d, want 1", registered.Generation)
	}
}

func TestLegacyRegistrationSnapshotNormalizesGeneration(t *testing.T) {
	identity := lifecycleIdentity("worker-a", "edge-worker", "sha256:worker-a")
	store := NewRegistrationStore()
	if err := store.RestoreSnapshot([]Registration{{
		NodeID:                 identity.NodeID,
		Role:                   identity.Role,
		CertificateFingerprint: identity.CertificateFingerprint,
		RegistrationID:         "legacy-registration",
		ExpiresAt:              time.Now().UTC().Add(time.Hour),
	}}); err != nil {
		t.Fatalf("restore legacy registration: %v", err)
	}
	entry, err := store.Validate(identity, "legacy-registration")
	if err != nil {
		t.Fatalf("validate legacy registration: %v", err)
	}
	if entry.Generation != 1 {
		t.Fatalf("legacy generation = %d, want 1", entry.Generation)
	}
}

func TestRegistrationLifecycleSnapshotRejectsMalformedRevocation(t *testing.T) {
	identity := lifecycleIdentity("worker-a", "edge-worker", "sha256:worker-a")
	store := NewRegistrationStore()
	base := Registration{
		NodeID:                 identity.NodeID,
		Role:                   identity.Role,
		CertificateFingerprint: identity.CertificateFingerprint,
		RegistrationID:         "registration-1",
		ExpiresAt:              time.Now().UTC().Add(time.Hour),
		Generation:             1,
	}

	withReasonOnly := base
	withReasonOnly.RevocationReason = "reason-without-time"
	if err := store.RestoreSnapshot([]Registration{withReasonOnly}); err == nil {
		t.Fatal("revocation reason without timestamp was accepted")
	}
	withTimeOnly := base
	withTimeOnly.RevokedAt = time.Now().UTC()
	if err := store.RestoreSnapshot([]Registration{withTimeOnly}); err == nil {
		t.Fatal("revocation timestamp without reason was accepted")
	}
	tooLong := base
	tooLong.RevokedAt = time.Now().UTC()
	tooLong.RevocationReason = strings.Repeat("x", maxRegistrationRevocationReasonBytes+1)
	if err := store.RestoreSnapshot([]Registration{tooLong}); err == nil {
		t.Fatal("oversized revocation reason was accepted")
	}
}

func TestRegistrationLifecycleAuthorizationRules(t *testing.T) {
	rules := DefaultMethodRules()
	rotate := rules[MethodRotateRegistration]
	if !rotate.RequireRegistration || !containsRole(rotate.Roles, "edge-worker") || !containsRole(rotate.Roles, "observer") || !containsRole(rotate.Roles, "admin") {
		t.Fatalf("rotate rule = %#v", rotate)
	}
	revoke := rules[MethodRevokeRegistration]
	if !revoke.RequireRegistration || len(revoke.Roles) != 1 || revoke.Roles[0] != "admin" {
		t.Fatalf("revoke rule = %#v", revoke)
	}
}

func lifecycleIdentity(nodeID, role, fingerprint string) PeerIdentity {
	return PeerIdentity{NodeID: nodeID, Role: role, CertificateFingerprint: fingerprint}
}

func containsRole(roles []string, want string) bool {
	for _, role := range roles {
		if role == want {
			return true
		}
	}
	return false
}
