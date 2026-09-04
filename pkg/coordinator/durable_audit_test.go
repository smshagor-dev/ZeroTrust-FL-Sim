package coordinator

import (
	"crypto/sha256"
	"testing"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
)

func TestUpdateAuditEventsIncludeAcceptedUpdateAndRoundAggregation(t *testing.T) {
	service := &DurableService{service: &Service{minUpdates: 2, aggregationMethod: "median"}}
	updateDigest := sha256.Sum256([]byte("worker-update"))
	modelDigest := sha256.Sum256([]byte("aggregated-model"))
	registrationID := "opaque-registration-bearer"

	req := &flv1.SubmitLocalUpdateRequest{
		NodeId:           "worker-a",
		RegistrationId:   registrationID,
		RoundId:          7,
		BaseModelVersion: "round-7-base",
		UpdateSha256:     updateDigest[:],
		Metrics: &flv1.LocalUpdateMetrics{
			SampleCount: 64,
		},
	}
	response := &flv1.SubmitLocalUpdateResponse{
		Accepted:            true,
		UpdateId:            "update-1",
		CurrentModelVersion: "round-8-aggregated",
	}
	before := StateSnapshot{Model: &flv1.GlobalModel{ModelVersion: "round-7-base", RoundId: 7}}
	after := StateSnapshot{Model: &flv1.GlobalModel{
		ModelVersion: "round-8-aggregated",
		RoundId:      8,
		Sha256:       modelDigest[:],
	}}

	events := service.updateAuditEvents(req, response, before, after)
	if len(events) != 2 {
		t.Fatalf("audit events = %d, want accepted update + round aggregation", len(events))
	}
	if events[0].Type != AuditEventUpdateAccepted || events[1].Type != AuditEventRoundAggregated {
		t.Fatalf("audit event types = %q, %q", events[0].Type, events[1].Type)
	}
	for index, event := range events {
		if err := validateAuditEvent(event); err != nil {
			t.Fatalf("audit event %d rejected: %v", index, err)
		}
	}
	if events[0].RegistrationIDHash == registrationID || events[0].RegistrationIDHash == "" {
		t.Fatal("accepted-update audit event did not hash the registration identifier")
	}
	if events[0].UpdateSHA256 != modelAuditDigestHex(updateDigest[:]) || events[0].SampleCount != 64 || events[0].Quorum != 2 {
		t.Fatalf("accepted-update audit metadata = %#v", events[0])
	}
	if events[1].RoundID != 8 || events[1].ModelSHA256 != modelAuditDigestHex(modelDigest[:]) || events[1].AggregationMethod != "median" {
		t.Fatalf("round-aggregation audit metadata = %#v", events[1])
	}
}
