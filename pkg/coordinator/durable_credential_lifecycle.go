package coordinator

import (
	"context"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
)

func (s *DurableService) RotateRegistration(ctx context.Context, req *flv1.RotateRegistrationRequest) (*flv1.RotateRegistrationResponse, error) {
	s.persistenceMu.Lock()
	defer s.persistenceMu.Unlock()

	before := s.captureSnapshot()
	response, err := s.service.RotateRegistration(ctx, req)
	if err != nil {
		return nil, err
	}
	after := s.captureSnapshot()
	events := []AuditEvent{rotationAuditEvent(req, response, after)}
	if err := s.commitOrRollbackTransition(ctx, before, after, "registration-credential-rotation", events); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *DurableService) RevokeRegistration(ctx context.Context, req *flv1.RevokeRegistrationRequest) (*flv1.RevokeRegistrationResponse, error) {
	s.persistenceMu.Lock()
	defer s.persistenceMu.Unlock()

	before := s.captureSnapshot()
	response, err := s.service.RevokeRegistration(ctx, req)
	if err != nil {
		return nil, err
	}
	after := s.captureSnapshot()
	events := []AuditEvent{revocationAuditEvent(req, response, after)}
	if err := s.commitOrRollbackTransition(ctx, before, after, "registration-revocation", events); err != nil {
		return nil, err
	}
	return response, nil
}

func rotationAuditEvent(req *flv1.RotateRegistrationRequest, response *flv1.RotateRegistrationResponse, snapshot StateSnapshot) AuditEvent {
	event := stateAuditEvent(AuditEventCredentialRotated, snapshot)
	event.NodeID = req.GetNodeId()
	event.RegistrationIDHash = hashAuditOpaqueIdentifier(response.GetRegistrationId())
	event.LeaseExpiresUnix = response.GetLeaseExpiresUnix()
	event.CredentialGeneration = response.GetCredentialGeneration()
	return event
}

func revocationAuditEvent(req *flv1.RevokeRegistrationRequest, response *flv1.RevokeRegistrationResponse, snapshot StateSnapshot) AuditEvent {
	event := stateAuditEvent(AuditEventRegistrationRevoked, snapshot)
	event.NodeID = req.GetNodeId()
	event.TargetNodeID = response.GetTargetNodeId()
	event.CredentialGeneration = response.GetRevokedGeneration()
	event.BlockedUntilUnix = response.GetBlockedUntilUnix()
	return event
}
