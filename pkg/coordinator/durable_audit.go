package coordinator

import (
	"context"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *DurableService) commitOrRollbackTransition(
	ctx context.Context,
	before StateSnapshot,
	after StateSnapshot,
	operation string,
	events []AuditEvent,
) error {
	var commitErr error
	if audited, ok := s.store.(auditedStateStore); ok {
		commitErr = audited.CommitWithAudit(ctx, after, events)
	} else {
		commitErr = s.store.Commit(ctx, after)
	}
	if commitErr == nil {
		return nil
	}

	if restoreErr := s.restoreSnapshot(before); restoreErr != nil {
		return status.Errorf(codes.Internal, "durable %s commit failed and in-memory rollback failed: %v", operation, restoreErr)
	}
	var rollbackErr error
	if audited, ok := s.store.(auditedStateStore); ok {
		rollbackErr = audited.CommitWithAudit(context.Background(), before, nil)
	} else {
		rollbackErr = s.store.Commit(context.Background(), before)
	}
	if rollbackErr != nil {
		return status.Errorf(codes.Internal, "durable %s commit failed and persistent rollback failed: %v", operation, rollbackErr)
	}
	return status.Errorf(codes.Internal, "durable %s commit failed; previous state restored", operation)
}

func (s *DurableService) commitCurrentStateWithAudit(ctx context.Context, events []AuditEvent) error {
	snapshot := s.captureSnapshot()
	if audited, ok := s.store.(auditedStateStore); ok {
		return audited.CommitWithAudit(ctx, snapshot, events)
	}
	return s.store.Commit(ctx, snapshot)
}

func stateAuditEvent(eventType string, snapshot StateSnapshot) AuditEvent {
	event := newAuditEvent(eventType)
	if snapshot.Model != nil {
		event.RoundID = snapshot.Model.GetRoundId()
		event.ModelVersion = snapshot.Model.GetModelVersion()
		event.ModelSHA256 = modelAuditDigestHex(snapshot.Model.GetSha256())
	}
	return event
}

func registrationAuditEvent(req *flv1.RegisterNodeRequest, response *flv1.RegisterNodeResponse, snapshot StateSnapshot) AuditEvent {
	event := stateAuditEvent(AuditEventNodeRegistered, snapshot)
	event.NodeID = req.GetNodeId()
	event.RegistrationIDHash = hashAuditOpaqueIdentifier(response.GetRegistrationId())
	event.LeaseExpiresUnix = response.GetLeaseExpiresUnix()
	return event
}

func heartbeatAuditEvent(req *flv1.HeartbeatRequest, response *flv1.HeartbeatResponse, snapshot StateSnapshot) AuditEvent {
	event := stateAuditEvent(AuditEventLeaseRenewed, snapshot)
	event.NodeID = req.GetNodeId()
	event.RegistrationIDHash = hashAuditOpaqueIdentifier(req.GetRegistrationId())
	event.LeaseExpiresUnix = response.GetLeaseExpiresUnix()
	return event
}

func (s *DurableService) updateAuditEvents(
	req *flv1.SubmitLocalUpdateRequest,
	response *flv1.SubmitLocalUpdateResponse,
	before StateSnapshot,
	after StateSnapshot,
) []AuditEvent {
	accepted := newAuditEvent(AuditEventUpdateAccepted)
	accepted.NodeID = req.GetNodeId()
	accepted.RegistrationIDHash = hashAuditOpaqueIdentifier(req.GetRegistrationId())
	accepted.UpdateID = response.GetUpdateId()
	accepted.UpdateSHA256 = modelAuditDigestHex(req.GetUpdateSha256())
	accepted.BaseModelVersion = req.GetBaseModelVersion()
	accepted.RoundID = req.GetRoundId()
	accepted.ModelVersion = response.GetCurrentModelVersion()
	if req.GetMetrics() != nil {
		accepted.SampleCount = req.GetMetrics().GetSampleCount()
	}
	accepted.PendingUpdates = len(after.Pending)
	accepted.Quorum = s.service.minUpdates

	events := []AuditEvent{accepted}
	if before.Model != nil && after.Model != nil && after.Model.GetRoundId() > before.Model.GetRoundId() {
		aggregated := stateAuditEvent(AuditEventRoundAggregated, after)
		aggregated.NodeID = req.GetNodeId()
		aggregated.Quorum = s.service.minUpdates
		aggregated.AggregationMethod = s.service.aggregationMethod
		events = append(events, aggregated)
	}
	return events
}
