package security

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	MethodRegisterNode      = "/zerotrust.fl.v1.CoordinatorService/RegisterNode"
	MethodHeartbeat         = "/zerotrust.fl.v1.CoordinatorService/Heartbeat"
	MethodGetGlobalModel    = "/zerotrust.fl.v1.CoordinatorService/GetGlobalModel"
	MethodSubmitLocalUpdate = "/zerotrust.fl.v1.CoordinatorService/SubmitLocalUpdate"
	MethodHealthCheck       = "/grpc.health.v1.Health/Check"
	MethodHealthWatch       = "/grpc.health.v1.Health/Watch"
)

type MethodRule struct {
	Roles               []string
	RequireRegistration bool
}

type Registration struct {
	NodeID                 string
	Role                   string
	CertificateFingerprint string
	RegistrationID         string
	ExpiresAt              time.Time
}

type RegistrationStore struct {
	mu      sync.RWMutex
	entries map[string]Registration
}

func NewRegistrationStore() *RegistrationStore {
	return &RegistrationStore{entries: make(map[string]Registration)}
}

func (s *RegistrationStore) Register(identity PeerIdentity, registrationID string, lease time.Duration) (Registration, error) {
	if s == nil {
		return Registration{}, errors.New("registration store is nil")
	}
	if registrationID == "" {
		return Registration{}, errors.New("registration ID is required")
	}
	if lease <= 0 {
		return Registration{}, errors.New("registration lease must be positive")
	}
	entry := Registration{
		NodeID:                 identity.NodeID,
		Role:                   identity.Role,
		CertificateFingerprint: identity.CertificateFingerprint,
		RegistrationID:         registrationID,
		ExpiresAt:              time.Now().UTC().Add(lease),
	}
	s.mu.Lock()
	s.entries[identity.NodeID] = entry
	s.mu.Unlock()
	return entry, nil
}

func (s *RegistrationStore) Validate(identity PeerIdentity, registrationID string) (Registration, error) {
	if s == nil {
		return Registration{}, errors.New("registration store is nil")
	}
	s.mu.RLock()
	entry, ok := s.entries[identity.NodeID]
	s.mu.RUnlock()
	if !ok {
		return Registration{}, errors.New("node is not registered")
	}
	if time.Now().UTC().After(entry.ExpiresAt) {
		return Registration{}, errors.New("node registration has expired")
	}
	if subtle.ConstantTimeCompare([]byte(entry.RegistrationID), []byte(registrationID)) != 1 {
		return Registration{}, errors.New("registration ID does not match")
	}
	if subtle.ConstantTimeCompare([]byte(entry.CertificateFingerprint), []byte(identity.CertificateFingerprint)) != 1 {
		return Registration{}, errors.New("registration certificate binding does not match")
	}
	if entry.Role != identity.Role {
		return Registration{}, errors.New("registration role binding does not match")
	}
	return entry, nil
}

func (s *RegistrationStore) IsRegistered(identity PeerIdentity) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	entry, ok := s.entries[identity.NodeID]
	s.mu.RUnlock()
	if !ok || time.Now().UTC().After(entry.ExpiresAt) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(entry.CertificateFingerprint), []byte(identity.CertificateFingerprint)) == 1 && entry.Role == identity.Role
}

func (s *RegistrationStore) Refresh(identity PeerIdentity, registrationID string, lease time.Duration) (Registration, error) {
	entry, err := s.Validate(identity, registrationID)
	if err != nil {
		return Registration{}, err
	}
	if lease <= 0 {
		return Registration{}, errors.New("registration lease must be positive")
	}
	entry.ExpiresAt = time.Now().UTC().Add(lease)
	s.mu.Lock()
	s.entries[identity.NodeID] = entry
	s.mu.Unlock()
	return entry, nil
}

type Authorizer struct {
	TrustDomain string
	Verifier    *TokenVerifier
	Registry    *RegistrationStore
	Rules       map[string]MethodRule
}

func NewAuthorizer(trustDomain string, verifier *TokenVerifier, registry *RegistrationStore) (*Authorizer, error) {
	if verifier == nil {
		return nil, errors.New("token verifier is required")
	}
	if registry == nil {
		return nil, errors.New("registration store is required")
	}
	if trustDomain == "" {
		trustDomain = DefaultTrustDomain
	}
	return &Authorizer{
		TrustDomain: trustDomain,
		Verifier:    verifier,
		Registry:    registry,
		Rules:       DefaultMethodRules(),
	}, nil
}

func DefaultMethodRules() map[string]MethodRule {
	return map[string]MethodRule{
		MethodRegisterNode: {
			Roles:               []string{"edge-worker", "observer", "admin"},
			RequireRegistration: false,
		},
		MethodHeartbeat: {
			Roles:               []string{"edge-worker", "observer", "admin"},
			RequireRegistration: true,
		},
		MethodGetGlobalModel: {
			Roles:               []string{"edge-worker", "observer", "admin"},
			RequireRegistration: true,
		},
		MethodSubmitLocalUpdate: {
			Roles:               []string{"edge-worker", "admin"},
			RequireRegistration: true,
		},
		MethodHealthCheck: {
			Roles:               []string{"edge-worker", "observer", "admin"},
			RequireRegistration: false,
		},
		MethodHealthWatch: {
			Roles:               []string{"edge-worker", "observer", "admin"},
			RequireRegistration: false,
		},
	}
}

func (a *Authorizer) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		authorizedContext, err := a.authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(authorizedContext, req)
	}
}

func (a *Authorizer) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		authorizedContext, err := a.authorize(stream.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, &authorizedServerStream{ServerStream: stream, ctx: authorizedContext})
	}
}

func (a *Authorizer) authorize(ctx context.Context, fullMethod string) (context.Context, error) {
	if a == nil || a.Verifier == nil || a.Registry == nil {
		return nil, status.Error(codes.Internal, "authorization middleware is not configured")
	}

	rule, ok := a.Rules[fullMethod]
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "RPC is not permitted by policy")
	}

	identity, err := PeerIdentityFromContext(ctx, a.TrustDomain)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "verified client certificate is required")
	}

	rawToken, err := bearerTokenFromIncomingContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	claims, err := a.Verifier.Verify(rawToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "bearer token is invalid")
	}

	if claims.Subject != identity.NodeID || claims.NodeID != identity.NodeID {
		return nil, status.Error(codes.PermissionDenied, "token identity is not bound to the client certificate")
	}
	if claims.Role != identity.Role {
		return nil, status.Error(codes.PermissionDenied, "token role is not bound to the client certificate")
	}
	if !stringAllowed(identity.Role, rule.Roles) {
		return nil, status.Errorf(codes.PermissionDenied, "role %q cannot invoke %s", identity.Role, fullMethod)
	}
	if rule.RequireRegistration && !a.Registry.IsRegistered(identity) {
		return nil, status.Error(codes.PermissionDenied, "node must register before invoking this RPC")
	}

	ctx = context.WithValue(ctx, peerIdentityContextKey{}, identity)
	ctx = context.WithValue(ctx, tokenClaimsContextKey{}, claims)
	return ctx, nil
}

func AuthorizedPeerIdentity(ctx context.Context) (PeerIdentity, bool) {
	identity, ok := ctx.Value(peerIdentityContextKey{}).(PeerIdentity)
	return identity, ok
}

func AuthorizedTokenClaims(ctx context.Context) (*TokenClaims, bool) {
	claims, ok := ctx.Value(tokenClaimsContextKey{}).(*TokenClaims)
	return claims, ok
}

func bearerTokenFromIncomingContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("authorization metadata is required")
	}
	values := md.Get("authorization")
	if len(values) != 1 {
		return "", errors.New("exactly one authorization header is required")
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", errors.New("authorization header must use Bearer authentication")
	}
	return parts[1], nil
}

type peerIdentityContextKey struct{}
type tokenClaimsContextKey struct{}

type authorizedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authorizedServerStream) Context() context.Context { return s.ctx }

func (r MethodRule) String() string {
	return fmt.Sprintf("roles=%v require_registration=%t", r.Roles, r.RequireRegistration)
}
