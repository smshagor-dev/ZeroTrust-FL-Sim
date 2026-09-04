package security

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

func (r *Registration) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("registration decode target is nil")
	}
	type registrationAlias Registration
	var decoded registrationAlias
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("decode registration lifecycle state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("registration lifecycle state contains trailing JSON values")
		}
		return fmt.Errorf("decode trailing registration lifecycle state: %w", err)
	}

	entry := normalizeLegacyRegistration(Registration(decoded))
	if strings.TrimSpace(entry.NodeID) == "" || strings.TrimSpace(entry.Role) == "" || strings.TrimSpace(entry.CertificateFingerprint) == "" || strings.TrimSpace(entry.RegistrationID) == "" {
		return errors.New("registration lifecycle state contains an incomplete identity binding")
	}
	if entry.ExpiresAt.IsZero() {
		return errors.New("registration lifecycle state has no lease expiry")
	}
	if len(entry.RevocationReason) > maxRegistrationRevocationReasonBytes {
		return fmt.Errorf("registration revocation reason exceeds %d bytes", maxRegistrationRevocationReasonBytes)
	}
	if entry.RevokedAt.IsZero() && entry.RevocationReason != "" {
		return errors.New("registration revocation reason requires a revocation timestamp")
	}
	if !entry.RevokedAt.IsZero() {
		if strings.TrimSpace(entry.RevocationReason) == "" {
			return errors.New("revoked registration requires a revocation reason")
		}
		if entry.RevokedAt.After(entry.ExpiresAt) {
			return errors.New("registration revocation timestamp is after lease expiry")
		}
	}
	*r = entry
	return nil
}
