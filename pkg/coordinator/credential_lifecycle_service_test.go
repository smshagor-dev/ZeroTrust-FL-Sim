package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net/url"
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestRotateRegistrationRPCRejectsOldCredentialAndReplay(t *testing.T) {
	registry := ztsecurity.NewRegistrationStore()
	service, err := NewService(registry, Config{})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	authorizer, privateKey := lifecycleAuthorizer(t, registry)
	identity, ctx := lifecycleAuthorizedPeer(t, privateKey, "worker-a", "edge-worker")
	entry, err := registry.Register(identity, "registration-1", time.Hour)
	if err != nil {
		t.Fatalf("seed registration: %v", err)
	}

	nonce := []byte("rotate-nonce-0001")
	responseAny, err := invokeLifecycleRPC(
		authorizer,
		ctx,
		ztsecurity.MethodRotateRegistration,
		&flv1.RotateRegistrationRequest{
			NodeId:         identity.NodeID,
			RegistrationId: entry.RegistrationID,
			Security:       lifecycleSecurityMetadata(nonce),
		},
		func(handlerCtx context.Context, req any) (any, error) {
			return service.RotateRegistration(handlerCtx, req.(*flv1.RotateRegistrationRequest))
		},
	)
	if err != nil {
		t.Fatalf("rotate registration RPC: %v", err)
	}
	response := responseAny.(*flv1.RotateRegistrationResponse)
	if !response.GetAccepted() || response.GetCredentialGeneration() != 2 || response.GetRegistrationId() == entry.RegistrationID {
		t.Fatalf("rotation response = %#v", response)
	}
	if _, err := registry.Validate(identity, entry.RegistrationID); err == nil {
		t.Fatal("old credential remained valid after rotate RPC")
	}

	_, err = invokeLifecycleRPC(
		authorizer,
		ctx,
		ztsecurity.MethodRotateRegistration,
		&flv1.RotateRegistrationRequest{
			NodeId:         identity.NodeID,
			RegistrationId: response.GetRegistrationId(),
			Security:       lifecycleSecurityMetadata(nonce),
		},
		func(handlerCtx context.Context, req any) (any, error) {
			return service.RotateRegistration(handlerCtx, req.(*flv1.RotateRegistrationRequest))
		},
	)
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("replayed rotation nonce error = %v, want AlreadyExists", err)
	}
}

func TestAdminRevokeRegistrationBlocksAccessAndReregistration(t *testing.T) {
	registry := ztsecurity.NewRegistrationStore()
	service, err := NewService(registry, Config{})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	authorizer, privateKey := lifecycleAuthorizer(t, registry)
	adminIdentity, adminCtx := lifecycleAuthorizedPeer(t, privateKey, "admin-a", "admin")
	workerIdentity, workerCtx := lifecycleAuthorizedPeer(t, privateKey, "worker-a", "edge-worker")
	adminEntry, err := registry.Register(adminIdentity, "admin-registration", time.Hour)
	if err != nil {
		t.Fatalf("seed admin registration: %v", err)
	}
	workerEntry, err := registry.Register(workerIdentity, "worker-registration", time.Hour)
	if err != nil {
		t.Fatalf("seed worker registration: %v", err)
	}
	service.pending[workerIdentity.NodeID] = pendingUpdate{NodeID: workerIdentity.NodeID, UpdateID: "pending", Values: []float32{1}, SampleCount: 1}
	service.rates[workerIdentity.NodeID] = updateRateWindow{StartedAt: time.Now().UTC(), Count: 1}

	responseAny, err := invokeLifecycleRPC(
		authorizer,
		adminCtx,
		ztsecurity.MethodRevokeRegistration,
		&flv1.RevokeRegistrationRequest{
			NodeId:         adminIdentity.NodeID,
			RegistrationId: adminEntry.RegistrationID,
			TargetNodeId:   workerIdentity.NodeID,
			Reason:         "compromised runtime credential",
			Security:       lifecycleSecurityMetadata([]byte("revoke-nonce-0001")),
		},
		func(handlerCtx context.Context, req any) (any, error) {
			return service.RevokeRegistration(handlerCtx, req.(*flv1.RevokeRegistrationRequest))
		},
	)
	if err != nil {
		t.Fatalf("revoke registration RPC: %v", err)
	}
	response := responseAny.(*flv1.RevokeRegistrationResponse)
	if !response.GetAccepted() || response.GetTargetNodeId() != workerIdentity.NodeID || response.GetRevokedGeneration() != workerEntry.Generation {
		t.Fatalf("revocation response = %#v", response)
	}
	if registry.IsRegistered(workerIdentity) {
		t.Fatal("revoked worker remained registered")
	}
	if _, ok := service.pending[workerIdentity.NodeID]; ok {
		t.Fatal("revocation left a compromised pending model update")
	}
	if _, ok := service.rates[workerIdentity.NodeID]; ok {
		t.Fatal("revocation left target rate-window state")
	}

	_, err = invokeLifecycleRPC(
		authorizer,
		workerCtx,
		ztsecurity.MethodGetGlobalModel,
		&flv1.GetGlobalModelRequest{NodeId: workerIdentity.NodeID, RegistrationId: workerEntry.RegistrationID},
		func(handlerCtx context.Context, req any) (any, error) {
			return service.GetGlobalModel(handlerCtx, req.(*flv1.GetGlobalModelRequest))
		},
	)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked model access error = %v, want PermissionDenied", err)
	}

	_, err = invokeLifecycleRPC(
		authorizer,
		workerCtx,
		ztsecurity.MethodRegisterNode,
		&flv1.RegisterNodeRequest{
			NodeId:                workerIdentity.NodeID,
			CertificateCommonName: workerIdentity.CommonName,
			Hardware:              &flv1.HardwareProfile{Architecture: "test"},
		},
		func(handlerCtx context.Context, req any) (any, error) {
			return service.RegisterNode(handlerCtx, req.(*flv1.RegisterNodeRequest))
		},
	)
	if err == nil {
		t.Fatal("revoked worker bypassed lease tombstone through RegisterNode")
	}
}

func lifecycleAuthorizer(t *testing.T, registry *ztsecurity.RegistrationStore) (*ztsecurity.Authorizer, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate JWT test key: %v", err)
	}
	verifier, err := ztsecurity.NewTokenVerifier(publicKey, "ztfl-test", "ztfl-services", 0)
	if err != nil {
		t.Fatalf("create token verifier: %v", err)
	}
	authorizer, err := ztsecurity.NewAuthorizer(ztsecurity.DefaultTrustDomain, verifier, registry)
	if err != nil {
		t.Fatalf("create authorizer: %v", err)
	}
	return authorizer, privateKey
}

func lifecycleAuthorizedPeer(t *testing.T, privateKey ed25519.PrivateKey, nodeID, role string) (ztsecurity.PeerIdentity, context.Context) {
	t.Helper()
	uri, err := url.Parse("spiffe://" + ztsecurity.DefaultTrustDomain + "/node/" + nodeID)
	if err != nil {
		t.Fatalf("build identity URI: %v", err)
	}
	cert := &x509.Certificate{
		Raw:          []byte("test-cert:" + nodeID + ":" + role),
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         nodeID,
			OrganizationalUnit: []string{"role:" + role},
		},
		URIs: []*url.URL{uri},
	}
	fingerprint := sha256.Sum256(cert.Raw)
	identity := ztsecurity.PeerIdentity{
		NodeID:                 nodeID,
		CommonName:             nodeID,
		Role:                   role,
		URISAN:                 uri.String(),
		CertificateSerial:      cert.SerialNumber.Text(16),
		CertificateFingerprint: hex.EncodeToString(fingerprint[:]),
		Certificate:            cert,
	}
	token, err := ztsecurity.IssueToken(privateKey, "ztfl-test", "ztfl-services", nodeID, role, time.Hour)
	if err != nil {
		t.Fatalf("issue test token: %v", err)
	}
	tlsInfo := credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: tlsInfo})
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
	return identity, ctx
}

func lifecycleSecurityMetadata(nonce []byte) *flv1.SecurityMetadata {
	return &flv1.SecurityMetadata{IssuedAtUnix: time.Now().UTC().Unix(), Nonce: append([]byte(nil), nonce...)}
}

func invokeLifecycleRPC(
	authorizer *ztsecurity.Authorizer,
	ctx context.Context,
	method string,
	req any,
	handler grpc.UnaryHandler,
) (any, error) {
	return authorizer.UnaryServerInterceptor()(ctx, req, &grpc.UnaryServerInfo{FullMethod: method}, handler)
}
