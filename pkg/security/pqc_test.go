package security

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestPQCCurvePreferences(t *testing.T) {
	required, err := PQCCurvePreferences(PQCRequired)
	if err != nil {
		t.Fatal(err)
	}
	if len(required) == 0 {
		t.Fatal("required PQC policy returned no key-exchange groups")
	}
	for _, curve := range required {
		if !IsPostQuantumKeyExchange(curve) {
			t.Fatalf("required PQC policy contains classical-only group %s", curve)
		}
	}

	off, err := PQCCurvePreferences(PQCOff)
	if err != nil {
		t.Fatal(err)
	}
	for _, curve := range off {
		if IsPostQuantumKeyExchange(curve) {
			t.Fatalf("PQC-off policy unexpectedly contains %s", curve)
		}
	}
}

func TestRequiredPQCMutualTLSWithMLDSA(t *testing.T) {
	artifacts, err := GenerateDevelopmentPKI(DevelopmentPKIConfig{
		OutputDir:            t.TempDir(),
		TrustDomain:          DefaultTrustDomain,
		ServerName:           "coordinator.local",
		CertificateAlgorithm: CertificateAlgorithmMLDSA65,
		Clients: []DevelopmentClient{
			{NodeID: "edge-worker-01", Role: "edge-worker"},
		},
	})
	if err != nil {
		t.Fatalf("GenerateDevelopmentPKI() error = %v", err)
	}
	if artifacts.CertificateAlgorithm != CertificateAlgorithmMLDSA65 {
		t.Fatalf("certificate algorithm = %q, want %q", artifacts.CertificateAlgorithm, CertificateAlgorithmMLDSA65)
	}

	clientArtifacts := artifacts.Clients["edge-worker-01"]
	serverConfig, err := ServerTLSConfig(ServerTLSOptions{
		CertificateFile:    artifacts.ServerCertificateFile,
		PrivateKeyFile:     artifacts.ServerPrivateKeyFile,
		ClientCAFile:       artifacts.CACertificateFile,
		TrustDomain:        DefaultTrustDomain,
		AllowedClientRoles: []string{"edge-worker"},
		PQCMode:            PQCRequired,
		RequirePQCIdentity: true,
	})
	if err != nil {
		t.Fatalf("ServerTLSConfig() error = %v", err)
	}
	clientConfig, err := ClientTLSConfig(ClientTLSOptions{
		CertificateFile:    clientArtifacts.CertificateFile,
		PrivateKeyFile:     clientArtifacts.PrivateKeyFile,
		RootCAFile:         artifacts.CACertificateFile,
		ServerName:         "coordinator.local",
		TrustDomain:        DefaultTrustDomain,
		ExpectedServerRole: "coordinator",
		PQCMode:            PQCRequired,
		RequirePQCIdentity: true,
	})
	if err != nil {
		t.Fatalf("ClientTLSConfig() error = %v", err)
	}

	clientState, serverState, err := handshakeTLSConfigs(serverConfig, clientConfig)
	if err != nil {
		t.Fatalf("required PQC handshake failed: %v", err)
	}
	if !IsPostQuantumKeyExchange(clientState.CurveID) {
		t.Fatalf("client negotiated classical-only key exchange %s", clientState.CurveID)
	}
	if clientState.CurveID != serverState.CurveID {
		t.Fatalf("client curve %s != server curve %s", clientState.CurveID, serverState.CurveID)
	}
	if len(clientState.PeerCertificates) == 0 || !IsMLDSACertificate(clientState.PeerCertificates[0]) {
		t.Fatal("client did not authenticate an ML-DSA server certificate")
	}
	if len(serverState.PeerCertificates) == 0 || !IsMLDSACertificate(serverState.PeerCertificates[0]) {
		t.Fatal("server did not authenticate an ML-DSA client certificate")
	}
}

func TestRequiredPQCRejectsClassicalOnlyPeer(t *testing.T) {
	artifacts, err := GenerateDevelopmentPKI(DevelopmentPKIConfig{
		OutputDir:   t.TempDir(),
		TrustDomain: DefaultTrustDomain,
		ServerName:  "coordinator.local",
		Clients: []DevelopmentClient{
			{NodeID: "edge-worker-01", Role: "edge-worker"},
		},
	})
	if err != nil {
		t.Fatalf("GenerateDevelopmentPKI() error = %v", err)
	}

	clientArtifacts := artifacts.Clients["edge-worker-01"]
	serverConfig, err := ServerTLSConfig(ServerTLSOptions{
		CertificateFile:    artifacts.ServerCertificateFile,
		PrivateKeyFile:     artifacts.ServerPrivateKeyFile,
		ClientCAFile:       artifacts.CACertificateFile,
		TrustDomain:        DefaultTrustDomain,
		AllowedClientRoles: []string{"edge-worker"},
		PQCMode:            PQCRequired,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := ClientTLSConfig(ClientTLSOptions{
		CertificateFile:    clientArtifacts.CertificateFile,
		PrivateKeyFile:     clientArtifacts.PrivateKeyFile,
		RootCAFile:         artifacts.CACertificateFile,
		ServerName:         "coordinator.local",
		TrustDomain:        DefaultTrustDomain,
		ExpectedServerRole: "coordinator",
		PQCMode:            PQCOff,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := handshakeTLSConfigs(serverConfig, clientConfig); err == nil {
		t.Fatal("PQC-required server unexpectedly accepted a classical-only client")
	}
}

func handshakeTLSConfigs(serverConfig, clientConfig *tls.Config) (tls.ConnectionState, tls.ConnectionState, error) {
	serverRaw, clientRaw := net.Pipe()
	defer serverRaw.Close()
	defer clientRaw.Close()

	deadline := time.Now().Add(5 * time.Second)
	_ = serverRaw.SetDeadline(deadline)
	_ = clientRaw.SetDeadline(deadline)

	serverConn := tls.Server(serverRaw, serverConfig)
	clientConn := tls.Client(clientRaw, clientConfig)
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- serverConn.Handshake()
	}()

	clientErr := clientConn.Handshake()
	serverErr := <-serverErrors
	if clientErr != nil || serverErr != nil {
		return tls.ConnectionState{}, tls.ConnectionState{}, fmt.Errorf("client=%v server=%v", clientErr, serverErr)
	}
	return clientConn.ConnectionState(), serverConn.ConnectionState(), nil
}
