package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultTrustDomain = "zerotrust-fl.local"

type DevelopmentClient struct {
	NodeID string
	Role   string
}

type DevelopmentPKIConfig struct {
	OutputDir   string
	TrustDomain string
	ServerName  string
	Issuer      string
	Audience    string
	TokenTTL    time.Duration
	Clients     []DevelopmentClient
}

type ClientArtifacts struct {
	CertificateFile string
	PrivateKeyFile  string
	TokenFile       string
}

type DevelopmentPKIArtifacts struct {
	CACertificateFile        string
	CAPrivateKeyFile         string
	ServerCertificateFile    string
	ServerPrivateKeyFile     string
	JWTSigningPrivateKeyFile string
	JWTSigningPublicKeyFile  string
	Clients                  map[string]ClientArtifacts
}

func GenerateDevelopmentPKI(cfg DevelopmentPKIConfig) (*DevelopmentPKIArtifacts, error) {
	if strings.TrimSpace(cfg.OutputDir) == "" {
		return nil, errors.New("output directory is required")
	}
	if cfg.TrustDomain == "" {
		cfg.TrustDomain = DefaultTrustDomain
	}
	if cfg.ServerName == "" {
		cfg.ServerName = "coordinator.local"
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "zerotrust-fl-sim"
	}
	if cfg.Audience == "" {
		cfg.Audience = "zerotrust-fl-services"
	}
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = 24 * time.Hour
	}
	if len(cfg.Clients) == 0 {
		cfg.Clients = []DevelopmentClient{
			{NodeID: "edge-worker-01", Role: "edge-worker"},
			{NodeID: "observer-01", Role: "observer"},
		}
	}
	if err := validateDNSLikeValue(cfg.TrustDomain, "trust domain"); err != nil {
		return nil, err
	}
	if err := validateDNSLikeValue(cfg.ServerName, "server name"); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(cfg.OutputDir, 0o700); err != nil {
		return nil, fmt.Errorf("create PKI directory: %w", err)
	}

	now := time.Now().UTC()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	caSerial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   "ZeroTrust-FL-Sim Local CA",
			Organization: []string{"ZeroTrust-FL-Sim"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("parse generated CA certificate: %w", err)
	}

	artifacts := &DevelopmentPKIArtifacts{
		CACertificateFile:        filepath.Join(cfg.OutputDir, "ca.crt"),
		CAPrivateKeyFile:         filepath.Join(cfg.OutputDir, "ca.key"),
		ServerCertificateFile:    filepath.Join(cfg.OutputDir, "server.crt"),
		ServerPrivateKeyFile:     filepath.Join(cfg.OutputDir, "server.key"),
		JWTSigningPrivateKeyFile: filepath.Join(cfg.OutputDir, "jwt_signing_private.pem"),
		JWTSigningPublicKeyFile:  filepath.Join(cfg.OutputDir, "jwt_signing_public.pem"),
		Clients:                  make(map[string]ClientArtifacts, len(cfg.Clients)),
	}

	if err := writeCertificate(artifacts.CACertificateFile, caDER); err != nil {
		return nil, err
	}
	if err := writePrivateKey(artifacts.CAPrivateKeyFile, caPrivate); err != nil {
		return nil, err
	}

	serverURI, err := url.Parse(fmt.Sprintf("spiffe://%s/coordinator/%s", cfg.TrustDomain, cfg.ServerName))
	if err != nil {
		return nil, fmt.Errorf("build server URI SAN: %w", err)
	}
	serverTemplate, err := leafCertificateTemplate(
		now,
		cfg.ServerName,
		"coordinator",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)
	if err != nil {
		return nil, err
	}
	serverTemplate.DNSNames = uniqueStrings([]string{cfg.ServerName, "localhost"})
	serverTemplate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	serverTemplate.URIs = []*url.URL{serverURI}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, serverPublic, caPrivate)
	if err != nil {
		return nil, fmt.Errorf("create server certificate: %w", err)
	}
	if err := writeCertificate(artifacts.ServerCertificateFile, serverDER); err != nil {
		return nil, err
	}
	if err := writePrivateKey(artifacts.ServerPrivateKeyFile, serverPrivate); err != nil {
		return nil, err
	}

	jwtPublic, jwtPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate JWT signing key: %w", err)
	}
	if err := writePrivateKey(artifacts.JWTSigningPrivateKeyFile, jwtPrivate); err != nil {
		return nil, err
	}
	if err := writePublicKey(artifacts.JWTSigningPublicKeyFile, jwtPublic); err != nil {
		return nil, err
	}

	for _, client := range cfg.Clients {
		if err := validateIdentityPart(client.NodeID, "client node ID"); err != nil {
			return nil, err
		}
		if err := validateIdentityPart(client.Role, "client role"); err != nil {
			return nil, err
		}

		clientURI, err := url.Parse(fmt.Sprintf("spiffe://%s/node/%s", cfg.TrustDomain, client.NodeID))
		if err != nil {
			return nil, fmt.Errorf("build client URI SAN: %w", err)
		}
		clientTemplate, err := leafCertificateTemplate(
			now,
			client.NodeID,
			client.Role,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		)
		if err != nil {
			return nil, err
		}
		clientTemplate.URIs = []*url.URL{clientURI}

		clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate client key for %s: %w", client.NodeID, err)
		}
		clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, clientPublic, caPrivate)
		if err != nil {
			return nil, fmt.Errorf("create client certificate for %s: %w", client.NodeID, err)
		}

		clientArtifacts := ClientArtifacts{
			CertificateFile: filepath.Join(cfg.OutputDir, client.NodeID+".crt"),
			PrivateKeyFile:  filepath.Join(cfg.OutputDir, client.NodeID+".key"),
			TokenFile:       filepath.Join(cfg.OutputDir, client.NodeID+".jwt"),
		}
		if err := writeCertificate(clientArtifacts.CertificateFile, clientDER); err != nil {
			return nil, err
		}
		if err := writePrivateKey(clientArtifacts.PrivateKeyFile, clientPrivate); err != nil {
			return nil, err
		}
		token, err := IssueToken(jwtPrivate, cfg.Issuer, cfg.Audience, client.NodeID, client.Role, cfg.TokenTTL)
		if err != nil {
			return nil, fmt.Errorf("issue token for %s: %w", client.NodeID, err)
		}
		if err := os.WriteFile(clientArtifacts.TokenFile, []byte(token+"\n"), 0o600); err != nil {
			return nil, fmt.Errorf("write token for %s: %w", client.NodeID, err)
		}
		artifacts.Clients[client.NodeID] = clientArtifacts
	}

	return artifacts, nil
}

func leafCertificateTemplate(now time.Time, commonName, role string, usages []x509.ExtKeyUsage) (*x509.Certificate, error) {
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{"ZeroTrust-FL-Sim"},
			OrganizationalUnit: []string{"role:" + role},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usages,
	}, nil
}

func writeCertificate(path string, der []byte) error {
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if data == nil {
		return errors.New("encode certificate PEM")
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write certificate %s: %w", path, err)
	}
	return nil
}

func writePrivateKey(path string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if data == nil {
		return errors.New("encode private key PEM")
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write private key %s: %w", path, err)
	}
	return nil
}

func writePublicKey(path string, key ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if data == nil {
		return errors.New("encode public key PEM")
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write public key %s: %w", path, err)
	}
	return nil
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial number: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func validateIdentityPart(value, label string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s is required", label)
	}
	if strings.ContainsAny(value, "/:\\ \t\r\n") {
		return fmt.Errorf("%s contains unsupported characters", label)
	}
	return nil
}

func validateDNSLikeValue(value, label string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s is required", label)
	}
	if strings.ContainsAny(value, "/ \\ \t\r\n") {
		return fmt.Errorf("%s contains unsupported characters", label)
	}
	return nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
