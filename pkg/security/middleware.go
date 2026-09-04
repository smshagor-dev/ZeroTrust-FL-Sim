package security

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	MethodRegisterNode       = "/zerotrust.fl.v1.CoordinatorService/RegisterNode"
	MethodHeartbeat          = "/zerotrust.fl.v1.CoordinatorService/Heartbeat"
	MethodGetGlobalModel     = "/zerotrust.fl.v1.CoordinatorService/GetGlobalModel"
	MethodSubmitLocalUpdate  = "/zerotrust.fl.v1.CoordinatorService/SubmitLocalUpdate"
	MethodRotateRegistration = "/zerotrust.fl.v1.CoordinatorService/RotateRegistration"
	MethodRevokeRegistration = "/zerotrust.fl.v1.CoordinatorService/RevokeRegistration"
	MethodHealthCheck        = "/grpc.health.v1.Health/Check"
	MethodHealthWatch        = "/grpc.health.v1.Health/Watch"

	maxRegistrationRevocationReasonBytes = 256
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
	Generation             uint64
	RevokedAt              time.Time
	RevocationReason       string
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
	if strings.TrimSpace(identity.NodeID) == "" || strings.TrimSpace(identity.Role) == "" || strings.TrimSpace(identity.CertificateFingerprint) == "" {
		return Registration{}, errors.New("registration identity binding is incomplete")
	}
	if registrationID == "" {
		return Registration{}, errors.New("registration ID is required")
	}
	if lease <= 0 {
		return Registration{}, errors.New("registration lease must be positive")
	}

	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	generation := uint64(1)
	if existing, ok := s.entries[identity.NodeID]; ok {
		existing = normalizeLegacyRegistration(existing)
		if now.Before(existing.ExpiresAt) {
			if !existing.RevokedAt.IsZero() {
				return Registration{}, errors.New("node registration is revoked until the current lease expires")
			}
			if existing.Role != identity.Role || subtle.ConstantTimeCompare([]byte(existing.CertificateFingerprint), []byte(identity.CertificateFingerprint)) != 1 {
				return Registration{}, errors.New("active registration is bound to a different certificate or role")
			}
		}
		if existing.Generation == ^uint64(0) {
			return Registration{}, errors.New("registration credential generation is exhausted")
		}
		generation = existing.Generation + 1
	}

	entry := Registration{
		NodeID:                 identity.NodeID,
		Role:                   identity.Role,
		CertificateFingerprint: identity.CertificateFingerprint,
		RegistrationID:         registrationID,
		ExpiresAt:              now.Add(lease),
		Generation:             generation,
	}
	s.entries[identity.NodeID] = entry
	return entry, nil
}

func (s *RegistrationStore) Validate(identity PeerIdentity, registrationID string) (Registration, error) {
	if s == nil {
		return Registration{}, errors.New("registration store is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[identity.NodeID]
	if !ok {
		return Registration{}, errors.New("node is not registered")
	}
	entry = normalizeLegacyRegistration(entry)
	if err := validateRegistrationEntry(entry, identity, registrationID, time.Now().UTC()); err != nil {
		return Registration{}, err
	}
	return entry, nil
}

func (s *RegistrationStore) IsRegistered(identity PeerIdentity) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[identity.NodeID]
	if !ok {
		return false
	}
	entry = normalizeLegacyRegistration(entry)
	now := time.Now().UTC()
	return now.Before(entry.ExpiresAt) &&
		entry.RevokedAt.IsZero() &&
		subtle.ConstantTimeCompare([]byte(entry.CertificateFingerprint), []byte(identity.CertificateFingerprint)) == 1 &&
		entry.Role == identity.Role
}

func (s *RegistrationStore) Refresh(identity PeerIdentity, registrationID string, lease time.Duration) (Registration, error) {
	if s == nil {
		return Registration{}, errors.New("registration store is nil")
	}
	if lease <= 0 {
		return Registration{}, errors.New("registration lease must be positive")
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[identity.NodeID]
	if !ok {
		return Registration{}, errors.New("node is not registered")
	}
	entry = normalizeLegacyRegistration(entry)
	if err := validateRegistrationEntry(entry, identity, registrationID, now); err != nil {
		return Registration{}, err
	}
	entry.ExpiresAt = now.Add(lease)
	s.entries[identity.NodeID] = entry
	return entry, nil
}

func (s *RegistrationStore) Rotate(identity PeerIdentity, currentRegistrationID, nextRegistrationID string, lease time.Duration) (Registration, error) {
	if s == nil {
		return Registration{}, errors.New("registration store is nil")
	}
	if strings.TrimSpace(nextRegistrationID) == "" {
		return Registration{}, errors.New("next registration ID is required")
	}
	if currentRegistrationID == nextRegistrationID {
		return Registration{}, errors.New("next registration ID must differ from the current credential")
	}
	if lease <= 0 {
		return Registration{}, errors.New("registration lease must be positive")
	}

	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[identity.NodeID]
	if !ok {
		return Registration{}, errors.New("node is not registered")
	}
	entry = normalizeLegacyRegistration(entry)
	if err := validateRegistrationEntry(entry, identity, currentRegistrationID, now); err != nil {
		return Registration{}, err
	}
	if entry.Generation == ^uint64(0) {
		return Registration{}, errors.New("registration credential generation is exhausted")
	}
	entry.RegistrationID = nextRegistrationID
	entry.Generation++
	entry.ExpiresAt = now.Add(lease)
	entry.RevokedAt = time.Time{}
	entry.RevocationReason = ""
	s.entries[identity.NodeID] = entry
	return entry, nil
}

func (s *RegistrationStore) Revoke(nodeID, reason string) (Registration, error) {
	if s == nil {
		return Registration{}, errors.New("registration store is nil")
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return Registration{}, errors.New("target node ID is required")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return Registration{}, errors.New("registration revocation reason is required")
	}
	if len(reason) > maxRegistrationRevocationReasonBytes {
		return Registration{}, fmt.Errorf("registration revocation reason exceeds %d bytes", maxRegistrationRevocationReasonBytes)
	}

	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[nodeID]
	if !ok {
		return Registration{}, errors.New("target node is not registered")
	}
	entry = normalizeLegacyRegistration(entry)
	if !now.Before(entry.ExpiresAt) {
		delete(s.entries, nodeID)
		return Registration{}, errors.New("target node registration has expired")
	}
	if !entry.RevokedAt.IsZero() {
		return entry, nil
	}
	entry.RevokedAt = now
	entry.RevocationReason = reason
	s.entries[nodeID] = entry
	return entry, nil
}

func (s *RegistrationStore) Snapshot() []Registration {
	if s == nil {
		return nil
	}
	now := time.Now().UTC()
	s.mu.RLock()
	entries := make([]Registration, 0, len(s.entries))
	for _, entry := range s.entries {
		entry = normalizeLegacyRegistration(entry)
		if !now.Before(entry.ExpiresAt) {
			continue
		}
		entries = append(entries, entry)
	}
	s.mu.RUnlock()
	sort.Slice(entries, func(i, j int) bool { return entries[i].NodeID < entries[j].NodeID })
	return entries
}

func (s *RegistrationStore) RestoreSnapshot(entries []Registration) error {
	if s == nil {
		return errors.New("registration store is nil")
	}
	now := time.Now().UTC()
	restored := make(map[string]Registration, len(entries))
	for _, rawEntry := range entries {
		entry := normalizeLegacyRegistration(rawEntry)
		if strings.TrimSpace(entry.NodeID) == "" || strings.TrimSpace(entry.Role) == "" || strings.TrimSpace(entry.CertificateFingerprint) == "" || strings.TrimSpace(entry.RegistrationID) == "" {
			return errors.New("registration snapshot contains an incomplete identity binding")
		}
		if entry.ExpiresAt.IsZero() {
			return fmt.Errorf("registration snapshot for %q has no expiry", entry.NodeID)
		}
		if entry.Generation == 0 {
			return fmt.Errorf("registration snapshot for %q has no credential generation", entry.NodeID)
		}
		if len(entry.RevocationReason) > maxRegistrationRevocationReasonBytes {
			return fmt.Errorf("registration snapshot for %q has an oversized revocation reason", entry.NodeID)
		}
		if entry.RevokedAt.IsZero() && entry.RevocationReason != "" {
			return fmt.Errorf("registration snapshot for %q has a revocation reason without a revocation timestamp", entry.NodeID)
		}
		if !entry.RevokedAt.IsZero() {
			if strings.TrimSpace(entry.RevocationReason) == "" {
				return fmt.Errorf("registration snapshot for %q is revoked without a reason", entry.NodeID)
			}
			if entry.RevokedAt.After(entry.ExpiresAt) {
				return fmt.Errorf("registration snapshot for %q was revoked after lease expiry", entry.NodeID)
			}
		}
		if _, exists := restored[entry.NodeID]; exists {
			return fmt.Errorf("registration snapshot contains duplicate node %q", entry.NodeID)
		}
		if !now.Before(entry.ExpiresAt) {
			continue
		}
		restored[entry.NodeID] = entry
	}
	s.mu.Lock()
	s.entries = restored
	s.mu.Unlock()
	return nil
}

func normalizeLegacyRegistration(entry Registration) Registration {
	if entry.Generation == 0 {
		entry.Generation = 1
	}
	return entry
}

func validateRegistrationEntry(entry Registration, identity PeerIdentity, registrationID string, now time.Time) error {
	if !now.Before(entry.ExpiresAt) {
		return errors.New("node registration has expired")
	}
	if !entry.RevokedAt.IsZero() {
		return errors.New("node registration is revoked")
	}
	if subtle.ConstantTimeCompare([]byte(entry.RegistrationID), []byte(registrationID)) != 1 {
		return errors.New("registration ID does not match")
	}
	if subtle.ConstantTimeCompare([]byte(entry.CertificateFingerprint), []byte(identity.CertificateFingerprint)) != 1 {
		return errors.New("registration certificate binding does not match")
	}
	if entry.Role != identity.Role {
		return errors.New("registration role binding does not match")
	}
	return nil
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
		MethodRotateRegistration: {
			Roles:               []string{"edge-worker", "observer", "admin"},
			RequireRegistration: true,
		},
		MethodRevokeRegistration: {
			Roles:               []string{"admin"},
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
