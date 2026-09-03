package tests

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztclient "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/client"
	"github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/coordinator"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestZeroTrustTransportAndAuthorization(t *testing.T) {
	h := newSecurityHarness(t)

	t.Run("valid client certificate and token can register", func(t *testing.T) {
		client := h.newClient(t, "edge-worker-01", "")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := client.Coordinator.RegisterNode(ctx, &flv1.RegisterNodeRequest{
			NodeId:                "edge-worker-01",
			CertificateCommonName: "edge-worker-01",
			Hardware: &flv1.HardwareProfile{
				Architecture:    "amd64",
				OperatingSystem: "test",
				LogicalCpus:     4,
				MemoryBytes:     8 << 30,
			},
		})
		if err != nil {
			t.Fatalf("RegisterNode() error = %v", err)
		}
		if !resp.GetAccepted() || resp.GetRegistrationId() == "" {
			t.Fatalf("RegisterNode() response = %#v", resp)
		}
		if resp.GetAssignedRole() != "edge-worker" {
			t.Fatalf("assigned role = %q, want edge-worker", resp.GetAssignedRole())
		}
	})

	t.Run("client without certificate is rejected during TLS handshake", func(t *testing.T) {
		roots, err := ztsecurity.LoadCertificatePool(h.artifacts.CACertificateFile)
		if err != nil {
			t.Fatal(err)
		}
		cfg := &tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			RootCAs:    roots,
			ServerName: h.serverName,
		}
		conn, err := tls.Dial("tcp", h.address, cfg)
		if err == nil {
			_ = conn.Close()
			t.Fatal("TLS handshake unexpectedly succeeded without a client certificate")
		}
	})

	t.Run("client certificate from untrusted CA is rejected", func(t *testing.T) {
		rogueDir := t.TempDir()
		rogue, err := ztsecurity.GenerateDevelopmentPKI(ztsecurity.DevelopmentPKIConfig{
			OutputDir:   rogueDir,
			TrustDomain: h.trustDomain,
			ServerName:  h.serverName,
			Issuer:      h.issuer,
			Audience:    h.audience,
			Clients: []ztsecurity.DevelopmentClient{
				{NodeID: "rogue-worker-01", Role: "edge-worker"},
			},
		})
		if err != nil {
			t.Fatalf("GenerateDevelopmentPKI() rogue error = %v", err)
		}
		rogueClient := rogue.Clients["rogue-worker-01"]
		cert, err := tls.LoadX509KeyPair(rogueClient.CertificateFile, rogueClient.PrivateKeyFile)
		if err != nil {
			t.Fatal(err)
		}
		roots, err := ztsecurity.LoadCertificatePool(h.artifacts.CACertificateFile)
		if err != nil {
			t.Fatal(err)
		}
		cfg := &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			RootCAs:      roots,
			ServerName:   h.serverName,
			Certificates: []tls.Certificate{cert},
		}
		conn, err := tls.Dial("tcp", h.address, cfg)
		if err == nil {
			_ = conn.Close()
			t.Fatal("TLS handshake unexpectedly succeeded with a certificate from an untrusted CA")
		}
	})

	t.Run("unregistered edge worker cannot submit update", func(t *testing.T) {
		client := h.newClient(t, "edge-worker-02", "")
		payload := []byte("local-model-update")
		digest := sha256.Sum256(payload)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := client.Coordinator.SubmitLocalUpdate(ctx, &flv1.SubmitLocalUpdateRequest{
			NodeId:           "edge-worker-02",
			RegistrationId:   "not-registered",
			RoundId:          0,
			BaseModelVersion: "bootstrap",
			WeightsPayload:   payload,
			WeightsFormat:    "application/x-zerotrust-tensors-v1",
			UpdateSha256:     digest[:],
			Metrics: &flv1.LocalUpdateMetrics{
				DynamicEpochs: 1,
				Loss:          0.5,
				GradientNorms: []float64{0.25},
				SampleCount:   32,
			},
		})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("SubmitLocalUpdate() code = %v, want PermissionDenied; err=%v", status.Code(err), err)
		}
	})

	t.Run("registered observer cannot submit a local update", func(t *testing.T) {
		client := h.newClient(t, "observer-01", "")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		registration, err := client.Coordinator.RegisterNode(ctx, &flv1.RegisterNodeRequest{
			NodeId:                "observer-01",
			CertificateCommonName: "observer-01",
			Hardware:              &flv1.HardwareProfile{Architecture: "amd64"},
		})
		if err != nil {
			t.Fatalf("RegisterNode() error = %v", err)
		}

		payload := []byte("observer-update")
		digest := sha256.Sum256(payload)
		_, err = client.Coordinator.SubmitLocalUpdate(ctx, &flv1.SubmitLocalUpdateRequest{
			NodeId:           "observer-01",
			RegistrationId:   registration.GetRegistrationId(),
			RoundId:          0,
			BaseModelVersion: "bootstrap",
			WeightsPayload:   payload,
			WeightsFormat:    "application/x-zerotrust-tensors-v1",
			UpdateSha256:     digest[:],
			Metrics: &flv1.LocalUpdateMetrics{
				DynamicEpochs: 1,
				Loss:          0.5,
				GradientNorms: []float64{0.25},
				SampleCount:   32,
			},
		})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("SubmitLocalUpdate() code = %v, want PermissionDenied; err=%v", status.Code(err), err)
		}
	})

	t.Run("certificate and RBAC token role mismatch is permission denied", func(t *testing.T) {
		privateKeyPEM, err := os.ReadFile(h.artifacts.JWTSigningPrivateKeyFile)
		if err != nil {
			t.Fatal(err)
		}
		privateKey, err := ztsecurity.ParseEd25519PrivateKeyPEM(privateKeyPEM)
		if err != nil {
			t.Fatal(err)
		}
		mismatchedToken, err := ztsecurity.IssueToken(
			privateKey,
			h.issuer,
			h.audience,
			"edge-worker-01",
			"admin",
			10*time.Minute,
		)
		if err != nil {
			t.Fatal(err)
		}
		client := h.newClient(t, "edge-worker-01", mismatchedToken)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err = client.Coordinator.RegisterNode(ctx, &flv1.RegisterNodeRequest{
			NodeId:                "edge-worker-01",
			CertificateCommonName: "edge-worker-01",
			Hardware:              &flv1.HardwareProfile{Architecture: "amd64"},
		})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("RegisterNode() code = %v, want PermissionDenied; err=%v", status.Code(err), err)
		}
	})

	t.Run("tampered token is unauthenticated", func(t *testing.T) {
		token := h.readToken(t, "edge-worker-02")
		if strings.HasSuffix(token, "A") {
			token = token[:len(token)-1] + "B"
		} else {
			token = token[:len(token)-1] + "A"
		}
		client := h.newClient(t, "edge-worker-02", token)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := client.Coordinator.RegisterNode(ctx, &flv1.RegisterNodeRequest{
			NodeId:                "edge-worker-02",
			CertificateCommonName: "edge-worker-02",
			Hardware:              &flv1.HardwareProfile{Architecture: "amd64"},
		})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("RegisterNode() code = %v, want Unauthenticated; err=%v", status.Code(err), err)
		}
	})
}

type securityHarness struct {
	address     string
	serverName  string
	trustDomain string
	issuer      string
	audience    string
	artifacts   *ztsecurity.DevelopmentPKIArtifacts
}

func newSecurityHarness(t *testing.T) *securityHarness {
	t.Helper()

	const (
		serverName  = "coordinator.local"
		trustDomain = ztsecurity.DefaultTrustDomain
		issuer      = "zerotrust-fl-sim-test"
		audience    = "zerotrust-fl-test-services"
	)

	artifacts, err := ztsecurity.GenerateDevelopmentPKI(ztsecurity.DevelopmentPKIConfig{
		OutputDir:   t.TempDir(),
		TrustDomain: trustDomain,
		ServerName:  serverName,
		Issuer:      issuer,
		Audience:    audience,
		TokenTTL:    30 * time.Minute,
		Clients: []ztsecurity.DevelopmentClient{
			{NodeID: "edge-worker-01", Role: "edge-worker"},
			{NodeID: "edge-worker-02", Role: "edge-worker"},
			{NodeID: "observer-01", Role: "observer"},
		},
	})
	if err != nil {
		t.Fatalf("GenerateDevelopmentPKI() error = %v", err)
	}

	transportCreds, err := ztsecurity.ServerTransportCredentials(ztsecurity.ServerTLSOptions{
		CertificateFile:    artifacts.ServerCertificateFile,
		PrivateKeyFile:     artifacts.ServerPrivateKeyFile,
		ClientCAFile:       artifacts.CACertificateFile,
		TrustDomain:        trustDomain,
		AllowedClientRoles: []string{"edge-worker", "observer", "admin"},
	})
	if err != nil {
		t.Fatalf("ServerTransportCredentials() error = %v", err)
	}
	verifier, err := ztsecurity.NewTokenVerifierFromPEMFile(
		artifacts.JWTSigningPublicKeyFile,
		issuer,
		audience,
		5*time.Second,
	)
	if err != nil {
		t.Fatalf("NewTokenVerifierFromPEMFile() error = %v", err)
	}
	registry := ztsecurity.NewRegistrationStore()
	authorizer, err := ztsecurity.NewAuthorizer(trustDomain, verifier, registry)
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	service, err := coordinator.NewService(registry, coordinator.Config{LeaseTTL: time.Minute})
	if err != nil {
		t.Fatalf("coordinator.NewService() error = %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	server := grpc.NewServer(
		grpc.Creds(transportCreds),
		grpc.ChainUnaryInterceptor(authorizer.UnaryServerInterceptor()),
		grpc.ChainStreamInterceptor(authorizer.StreamServerInterceptor()),
	)
	flv1.RegisterCoordinatorServiceServer(server, service)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	return &securityHarness{
		address:     listener.Addr().String(),
		serverName:  serverName,
		trustDomain: trustDomain,
		issuer:      issuer,
		audience:    audience,
		artifacts:   artifacts,
	}
}

func (h *securityHarness) newClient(t *testing.T, nodeID, tokenOverride string) *ztclient.Client {
	t.Helper()
	artifacts, ok := h.artifacts.Clients[nodeID]
	if !ok {
		t.Fatalf("missing client artifacts for %s", nodeID)
	}
	token := tokenOverride
	if token == "" {
		token = h.readToken(t, nodeID)
	}
	client, err := ztclient.New(ztclient.Config{
		Address: h.address,
		TLS: ztsecurity.ClientTLSOptions{
			CertificateFile:    artifacts.CertificateFile,
			PrivateKeyFile:     artifacts.PrivateKeyFile,
			RootCAFile:         h.artifacts.CACertificateFile,
			ServerName:         h.serverName,
			TrustDomain:        h.trustDomain,
			ExpectedServerRole: "coordinator",
		},
		Token: token,
	})
	if err != nil {
		t.Fatalf("client.New() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func (h *securityHarness) readToken(t *testing.T, nodeID string) string {
	t.Helper()
	artifacts := h.artifacts.Clients[nodeID]
	data, err := os.ReadFile(artifacts.TokenFile)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}
