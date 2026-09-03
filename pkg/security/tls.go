package security

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type PeerIdentity struct {
	NodeID                 string
	CommonName             string
	Role                   string
	URISAN                 string
	CertificateSerial      string
	CertificateFingerprint string
	Certificate            *x509.Certificate
}

type ServerTLSOptions struct {
	CertificateFile     string
	PrivateKeyFile      string
	ClientCAFile        string
	TrustDomain         string
	AllowedClientRoles  []string
	ClientSPKIPins      []string
	PQCMode             PQCMode
	RequirePQCIdentity  bool
}

type ClientTLSOptions struct {
	CertificateFile     string
	PrivateKeyFile      string
	RootCAFile          string
	ServerName          string
	TrustDomain         string
	ExpectedServerRole  string
	ServerSPKIPins      []string
	PQCMode             PQCMode
	RequirePQCIdentity  bool
}

func ServerTransportCredentials(opts ServerTLSOptions) (credentials.TransportCredentials, error) {
	cfg, err := ServerTLSConfig(opts)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(cfg), nil
}

func ClientTransportCredentials(opts ClientTLSOptions) (credentials.TransportCredentials, error) {
	cfg, err := ClientTLSConfig(opts)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(cfg), nil
}

func ServerTLSConfig(opts ServerTLSOptions) (*tls.Config, error) {
	if opts.TrustDomain == "" {
		opts.TrustDomain = DefaultTrustDomain
	}
	if len(opts.AllowedClientRoles) == 0 {
		opts.AllowedClientRoles = []string{"edge-worker", "observer", "admin"}
	}
	pqcMode, err := normalizePQCMode(opts.PQCMode)
	if err != nil {
		return nil, err
	}
	curvePreferences, err := PQCCurvePreferences(pqcMode)
	if err != nil {
		return nil, err
	}

	certificate, err := tls.LoadX509KeyPair(opts.CertificateFile, opts.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	if opts.RequirePQCIdentity {
		leaf, err := certificateLeaf(certificate)
		if err != nil {
			return nil, err
		}
		if err := validatePQCIdentity(true, leaf, "server"); err != nil {
			return nil, err
		}
	}
	clientCAs, err := LoadCertificatePool(opts.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("load client CA: %w", err)
	}

	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{certificate},
		ClientCAs:        clientCAs,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		CurvePreferences: curvePreferences,
	}
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if err := validatePQCConnection(pqcMode, state); err != nil {
			return err
		}
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errors.New("client certificate was not verified")
		}
		if err := validatePQCIdentity(opts.RequirePQCIdentity, state.PeerCertificates[0], "client"); err != nil {
			return err
		}
		identity, err := ClientIdentityFromCertificate(state.PeerCertificates[0], opts.TrustDomain)
		if err != nil {
			return err
		}
		if !stringAllowed(identity.Role, opts.AllowedClientRoles) {
			return fmt.Errorf("client certificate role %q is not allowed", identity.Role)
		}
		if err := verifySPKIPin(state.PeerCertificates[0], opts.ClientSPKIPins); err != nil {
			return fmt.Errorf("verify client certificate pin: %w", err)
		}
		return nil
	}
	return cfg, nil
}

func ClientTLSConfig(opts ClientTLSOptions) (*tls.Config, error) {
	if opts.TrustDomain == "" {
		opts.TrustDomain = DefaultTrustDomain
	}
	if opts.ExpectedServerRole == "" {
		opts.ExpectedServerRole = "coordinator"
	}
	if strings.TrimSpace(opts.ServerName) == "" {
		return nil, errors.New("TLS server name is required")
	}
	pqcMode, err := normalizePQCMode(opts.PQCMode)
	if err != nil {
		return nil, err
	}
	curvePreferences, err := PQCCurvePreferences(pqcMode)
	if err != nil {
		return nil, err
	}

	certificate, err := tls.LoadX509KeyPair(opts.CertificateFile, opts.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	if opts.RequirePQCIdentity {
		leaf, err := certificateLeaf(certificate)
		if err != nil {
			return nil, err
		}
		if err := validatePQCIdentity(true, leaf, "client"); err != nil {
			return nil, err
		}
	}
	rootCAs, err := LoadCertificatePool(opts.RootCAFile)
	if err != nil {
		return nil, fmt.Errorf("load root CA: %w", err)
	}

	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{certificate},
		RootCAs:          rootCAs,
		ServerName:       opts.ServerName,
		CurvePreferences: curvePreferences,
	}
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if err := validatePQCConnection(pqcMode, state); err != nil {
			return err
		}
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errors.New("server certificate was not verified")
		}
		if err := validatePQCIdentity(opts.RequirePQCIdentity, state.PeerCertificates[0], "server"); err != nil {
			return err
		}
		if err := ValidateServerCertificate(
			state.PeerCertificates[0],
			opts.TrustDomain,
			opts.ServerName,
			opts.ExpectedServerRole,
		); err != nil {
			return err
		}
		if err := verifySPKIPin(state.PeerCertificates[0], opts.ServerSPKIPins); err != nil {
			return fmt.Errorf("verify server certificate pin: %w", err)
		}
		return nil
	}
	return cfg, nil
}

func LoadCertificatePool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate pool %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(data); !ok {
		return nil, fmt.Errorf("no valid certificates found in %s", path)
	}
	return pool, nil
}

func ClientIdentityFromCertificate(cert *x509.Certificate, trustDomain string) (PeerIdentity, error) {
	if cert == nil {
		return PeerIdentity{}, errors.New("client certificate is missing")
	}
	if trustDomain == "" {
		trustDomain = DefaultTrustDomain
	}
	commonName := strings.TrimSpace(cert.Subject.CommonName)
	if commonName == "" {
		return PeerIdentity{}, errors.New("client certificate common name is required")
	}
	role, err := certificateRole(cert)
	if err != nil {
		return PeerIdentity{}, err
	}
	expectedURI := fmt.Sprintf("spiffe://%s/node/%s", trustDomain, commonName)
	if !certificateHasURI(cert, expectedURI) {
		return PeerIdentity{}, fmt.Errorf("client certificate URI SAN must contain %q", expectedURI)
	}
	return buildPeerIdentity(cert, commonName, role, expectedURI), nil
}

func ValidateServerCertificate(cert *x509.Certificate, trustDomain, serverName, expectedRole string) error {
	if cert == nil {
		return errors.New("server certificate is missing")
	}
	if trustDomain == "" {
		trustDomain = DefaultTrustDomain
	}
	commonName := strings.TrimSpace(cert.Subject.CommonName)
	if commonName == "" || commonName != serverName {
		return fmt.Errorf("server certificate common name %q does not match expected %q", commonName, serverName)
	}
	if err := cert.VerifyHostname(serverName); err != nil {
		return fmt.Errorf("server certificate SAN validation failed: %w", err)
	}
	role, err := certificateRole(cert)
	if err != nil {
		return err
	}
	if role != expectedRole {
		return fmt.Errorf("server certificate role %q does not match expected %q", role, expectedRole)
	}
	expectedURI := fmt.Sprintf("spiffe://%s/coordinator/%s", trustDomain, serverName)
	if !certificateHasURI(cert, expectedURI) {
		return fmt.Errorf("server certificate URI SAN must contain %q", expectedURI)
	}
	return nil
}

func PeerIdentityFromContext(ctx context.Context, trustDomain string) (PeerIdentity, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return PeerIdentity{}, errors.New("gRPC peer authentication information is missing")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return PeerIdentity{}, errors.New("gRPC peer is not authenticated with TLS")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.PeerCertificates) == 0 {
		return PeerIdentity{}, errors.New("gRPC peer certificate was not verified")
	}
	return ClientIdentityFromCertificate(tlsInfo.State.PeerCertificates[0], trustDomain)
}

func SPKIPin(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("certificate is missing")
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal subject public key info: %w", err)
	}
	sum := sha256.Sum256(spki)
	return "sha256/" + base64.StdEncoding.EncodeToString(sum[:]), nil
}

func verifySPKIPin(cert *x509.Certificate, allowedPins []string) error {
	if len(allowedPins) == 0 {
		return nil
	}
	actual, err := SPKIPin(cert)
	if err != nil {
		return err
	}
	for _, pin := range allowedPins {
		if strings.TrimSpace(pin) == actual {
			return nil
		}
	}
	return fmt.Errorf("certificate SPKI pin %q is not trusted", actual)
}

func certificateRole(cert *x509.Certificate) (string, error) {
	var role string
	for _, unit := range cert.Subject.OrganizationalUnit {
		if !strings.HasPrefix(unit, "role:") {
			continue
		}
		candidate := strings.TrimSpace(strings.TrimPrefix(unit, "role:"))
		if candidate == "" {
			return "", errors.New("certificate contains an empty role OU")
		}
		if role != "" && role != candidate {
			return "", errors.New("certificate contains multiple role OUs")
		}
		role = candidate
	}
	if role == "" {
		return "", errors.New("certificate role OU is required")
	}
	return role, nil
}

func certificateHasURI(cert *x509.Certificate, expected string) bool {
	for _, uri := range cert.URIs {
		if uri != nil && uri.String() == expected {
			return true
		}
	}
	return false
}

func buildPeerIdentity(cert *x509.Certificate, nodeID, role, uriSAN string) PeerIdentity {
	fingerprint := sha256.Sum256(cert.Raw)
	return PeerIdentity{
		NodeID:                 nodeID,
		CommonName:             cert.Subject.CommonName,
		Role:                   role,
		URISAN:                 uriSAN,
		CertificateSerial:      cert.SerialNumber.Text(16),
		CertificateFingerprint: hex.EncodeToString(fingerprint[:]),
		Certificate:            cert,
	}
}

func stringAllowed(value string, allowed []string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
