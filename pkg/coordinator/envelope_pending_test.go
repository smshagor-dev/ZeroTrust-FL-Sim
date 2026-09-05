package coordinator

import (
	"bytes"
	"testing"
)

func TestPendingBootstrapSchemaUsesAcceptedVectorLength(t *testing.T) {
	core := &Service{pending: map[string]pendingUpdate{
		"worker-1": {Values: []float32{1, 2, 3}},
		"worker-2": {Values: []float32{4, 5, 6}},
	}}
	service := &EnvelopeService{inner: core, modelID: "classifier"}

	actual, found, err := service.pendingSchemaDigest()
	if err != nil {
		t.Fatalf("pending schema: %v", err)
	}
	if !found {
		t.Fatal("expected pending schema")
	}
	manifest := manifestForElementCount(3)
	expected := modelSchemaDigest(manifest)
	if !bytes.Equal(actual, expected[:]) {
		t.Fatalf("pending schema = %x, want %x", actual, expected)
	}
}

func TestPendingBootstrapSchemaDetectsRecoveredMixedLengths(t *testing.T) {
	core := &Service{pending: map[string]pendingUpdate{
		"worker-1": {Values: []float32{1, 2, 3}},
		"worker-2": {Values: []float32{4, 5, 6, 7}},
	}}
	service := &EnvelopeService{inner: core, modelID: "classifier"}

	if _, _, err := service.pendingSchemaDigest(); err == nil {
		t.Fatal("expected mixed pending vector lengths to fail closed")
	}
}
