package coordinator

import (
	"context"
	"strings"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Service) RotateRegistration(ctx context.Context, req *flv1.RotateRegistrationRequest) (*flv1.RotateRegistrationResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "registration rotation request is required")
	}
	identity, err := requireIdentityAndRegistration(ctx, s.registry, req.GetNodeId(), req.GetRegistrationId())
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if err := validateSecurityMetadata(req.GetSecurity(), now); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	nextRegistrationID, err := secureIdentifier(24)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not create replacement registration credential")
	}

	s.roundMu.Lock()
	defer s.roundMu.Unlock()
	if _, err := s.registry.Validate(identity, req.GetRegistrationId()); err != nil {
		return nil, status.Error(codes.PermissionDenied, "registration was revoked, rotated, or expired before rotation")
	}
	if !s.acceptNonceLocked(req.GetNodeId(), req.GetSecurity().GetNonce(), now) {
		return nil, status.Error(codes.AlreadyExists, "request nonce was already used")
	}
	entry, err := s.registry.Rotate(identity, req.GetRegistrationId(), nextRegistrationID, s.leaseTTL)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "registration could not be rotated")
	}
	return &flv1.RotateRegistrationResponse{
		Accepted:             true,
		RegistrationId:       entry.RegistrationID,
		LeaseExpiresUnix:     entry.ExpiresAt.Unix(),
		CredentialGeneration: entry.Generation,
	}, nil
}

func (s *Service) RevokeRegistration(ctx context.Context, req *flv1.RevokeRegistrationRequest) (*flv1.RevokeRegistrationResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "registration revocation request is required")
	}
	identity, err := requireIdentityAndRegistration(ctx, s.registry, req.GetNodeId(), req.GetRegistrationId())
	if err != nil {
		return nil, err
	}
	if identity.Role != "admin" {
		return nil, status.Error(codes.PermissionDenied, "only an admin identity may revoke registrations")
	}
	if strings.TrimSpace(req.GetTargetNodeId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "target_node_id is required")
	}
	now := time.Now().UTC()
	if err := validateSecurityMetadata(req.GetSecurity(), now); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	s.roundMu.Lock()
	defer s.roundMu.Unlock()
	if _, err := s.registry.Validate(identity, req.GetRegistrationId()); err != nil {
		return nil, status.Error(codes.PermissionDenied, "admin registration was revoked, rotated, or expired before revocation")
	}
	if !s.acceptNonceLocked(req.GetNodeId(), req.GetSecurity().GetNonce(), now) {
		return nil, status.Error(codes.AlreadyExists, "request nonce was already used")
	}
	entry, err := s.registry.Revoke(req.GetTargetNodeId(), req.GetReason())
	if err != nil {
		return nil, mapRegistrationRevocationError(err)
	}

	delete(s.pending, entry.NodeID)
	delete(s.rates, entry.NodeID)
	return &flv1.RevokeRegistrationResponse{
		Accepted:          true,
		TargetNodeId:      entry.NodeID,
		RevokedGeneration: entry.Generation,
		RevokedAtUnix:     entry.RevokedAt.Unix(),
		BlockedUntilUnix:  entry.ExpiresAt.Unix(),
	}, nil
}

func mapRegistrationRevocationError(err error) error {
	message := err.Error()
	switch {
	case strings.Contains(message, "reason"), strings.Contains(message, "target node ID"):
		return status.Error(codes.InvalidArgument, message)
	case strings.Contains(message, "not registered"), strings.Contains(message, "expired"):
		return status.Error(codes.NotFound, "target registration is not active")
	default:
		return status.Error(codes.PermissionDenied, "registration could not be revoked")
	}
}
