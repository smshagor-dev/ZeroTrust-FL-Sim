package security

import (
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
)

// PQCMode controls which TLS 1.3 key-exchange groups are accepted.
//
// The preferred mode keeps classical fallback for interoperability while
// advertising Go's hybrid post-quantum groups. The required mode removes
// classical-only groups and rejects a completed handshake unless a supported
// post-quantum or hybrid group was negotiated.
type PQCMode string

const (
	PQCOff       PQCMode = "off"
	PQCPreferred PQCMode = "prefer"
	PQCRequired  PQCMode = "require"
)

func ParsePQCMode(value string) (PQCMode, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return PQCPreferred, nil
	}
	switch PQCMode(normalized) {
	case PQCOff, PQCPreferred, PQCRequired:
		return PQCMode(normalized), nil
	default:
		return "", fmt.Errorf("unsupported PQC mode %q; expected off, prefer, or require", value)
	}
}

func normalizePQCMode(mode PQCMode) (PQCMode, error) {
	return ParsePQCMode(string(mode))
}

// PQCCurvePreferences returns the explicit TLS 1.3 key-exchange policy used by
// the coordinator and Go clients. Hybrid groups combine a classical ECDHE
// contribution with ML-KEM so confidentiality does not depend on only one
// primitive family.
func PQCCurvePreferences(mode PQCMode) ([]tls.CurveID, error) {
	normalized, err := normalizePQCMode(mode)
	if err != nil {
		return nil, err
	}

	switch normalized {
	case PQCOff:
		return []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		}, nil
	case PQCPreferred:
		return []tls.CurveID{
			tls.X25519MLKEM768,
			tls.SecP256r1MLKEM768,
			tls.SecP384r1MLKEM1024,
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		}, nil
	case PQCRequired:
		return []tls.CurveID{
			tls.X25519MLKEM768,
			tls.SecP256r1MLKEM768,
			tls.SecP384r1MLKEM1024,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported PQC mode %q", normalized)
	}
}

// IsPostQuantumKeyExchange reports whether the negotiated TLS group contains
// an ML-KEM contribution (or is the pure ML-KEM-1024 group introduced in Go
// 1.27). The production policy currently prefers hybrid groups.
func IsPostQuantumKeyExchange(curve tls.CurveID) bool {
	switch curve {
	case tls.X25519MLKEM768,
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
		tls.MLKEM1024:
		return true
	default:
		return false
	}
}

func validatePQCConnection(mode PQCMode, state tls.ConnectionState) error {
	normalized, err := normalizePQCMode(mode)
	if err != nil {
		return err
	}
	if normalized != PQCRequired {
		return nil
	}
	if !IsPostQuantumKeyExchange(state.CurveID) {
		return fmt.Errorf("post-quantum TLS is required but negotiated key exchange %s is classical-only", state.CurveID)
	}
	return nil
}

// IsMLDSACertificate reports whether the X.509 leaf uses an ML-DSA public key.
func IsMLDSACertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	_, ok := cert.PublicKey.(*mldsa.PublicKey)
	return ok
}

func validatePQCIdentity(required bool, cert *x509.Certificate, peerLabel string) error {
	if !required {
		return nil
	}
	if cert == nil {
		return fmt.Errorf("%s certificate is missing", peerLabel)
	}
	if !IsMLDSACertificate(cert) {
		return fmt.Errorf("post-quantum %s identity is required but certificate public key is %T", peerLabel, cert.PublicKey)
	}
	return nil
}

func certificateLeaf(certificate tls.Certificate) (*x509.Certificate, error) {
	if certificate.Leaf != nil {
		return certificate.Leaf, nil
	}
	if len(certificate.Certificate) == 0 {
		return nil, fmt.Errorf("TLS certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse TLS leaf certificate: %w", err)
	}
	return leaf, nil
}
