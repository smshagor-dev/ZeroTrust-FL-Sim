package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type envelopeTestService struct {
	flv1.UnimplementedCoordinatorServiceServer
	model     *flv1.GlobalModel
	submitted bool
}

func (s *envelopeTestService) GetGlobalModel(context.Context, *flv1.GetGlobalModelRequest) (*flv1.GlobalModel, error) {
	return s.model, nil
}

func (s *envelopeTestService) SubmitLocalUpdate(context.Context, *flv1.SubmitLocalUpdateRequest) (*flv1.SubmitLocalUpdateResponse, error) {
	s.submitted = true
	return &flv1.SubmitLocalUpdateResponse{Accepted: true, UpdateId: "update-1"}, nil
}

func TestEnvelopeDecoratesGlobalModel(t *testing.T) {
	payload := mustEnvelopePayload(t, []float32{1, 2, 3})
	digest := sha256.Sum256(payload)
	inner := &envelopeTestService{model: &flv1.GlobalModel{
		ModelVersion:   "round-1",
		RoundId:        1,
		WeightsPayload: payload,
		WeightsFormat:  networkWeightsFormat,
		Sha256:         digest[:],
	}}
	service, err := NewEnvelopeService(inner, "classifier")
	if err != nil {
		t.Fatalf("create envelope service: %v", err)
	}

	model, err := service.GetGlobalModel(context.Background(), &flv1.GetGlobalModelRequest{})
	if err != nil {
		t.Fatalf("get global model: %v", err)
	}
	if model.GetProtocolVersion() != ModelProtocolVersion {
		t.Fatalf("protocol version = %d, want %d", model.GetProtocolVersion(), ModelProtocolVersion)
	}
	if model.GetModelId() != "classifier" {
		t.Fatalf("model id = %q", model.GetModelId())
	}
	if len(model.GetSchemaSha256()) != sha256.Size {
		t.Fatalf("schema digest length = %d", len(model.GetSchemaSha256()))
	}
	if len(model.GetTensorManifest()) != 1 {
		t.Fatalf("manifest entries = %d", len(model.GetTensorManifest()))
	}
	entry := model.GetTensorManifest()[0]
	if entry.GetName() != flatTensorName || entry.GetDtype() != float32DType || entry.GetElementCount() != 3 {
		t.Fatalf("unexpected manifest: %+v", entry)
	}
	if len(entry.GetDimensions()) != 1 || entry.GetDimensions()[0] != 3 {
		t.Fatalf("unexpected dimensions: %v", entry.GetDimensions())
	}
}

func TestModelSchemaDigestMatchesCrossLanguageVector(t *testing.T) {
	manifest := []*flv1.TensorManifestEntry{{
		Name:         flatTensorName,
		Dtype:        float32DType,
		Dimensions:   []uint64{3},
		ElementCount: 3,
	}}
	digest := modelSchemaDigest(manifest)
	const expected = "cff606025d8af83f907bc6d4c6b82000e3c22b67d16bf8a3e9999f816c1c5e64"
	if actual := hex.EncodeToString(digest[:]); actual != expected {
		t.Fatalf("schema digest = %s, want %s", actual, expected)
	}
}

func TestEnvelopeDecoratesBootstrapWithoutInventingSchema(t *testing.T) {
	inner := &envelopeTestService{model: &flv1.GlobalModel{
		ModelVersion:  "bootstrap",
		WeightsFormat: networkWeightsFormat,
	}}
	service, err := NewEnvelopeService(inner, DefaultModelID)
	if err != nil {
		t.Fatal(err)
	}
	model, err := service.GetGlobalModel(context.Background(), &flv1.GetGlobalModelRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if model.GetProtocolVersion() != ModelProtocolVersion || model.GetModelId() != DefaultModelID {
		t.Fatalf("bootstrap identity not populated: %+v", model)
	}
	if len(model.GetSchemaSha256()) != 0 || len(model.GetTensorManifest()) != 0 {
		t.Fatal("payload-free bootstrap model must not advertise a tensor schema")
	}
}

func TestEnvelopeRejectsMalformedUpdateMetadata(t *testing.T) {
	payload := mustEnvelopePayload(t, []float32{0.25, -0.5, 0.75})
	manifest, err := manifestForPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	schema := modelSchemaDigest(manifest)
	service, err := NewEnvelopeService(&envelopeTestService{}, "classifier")
	if err != nil {
		t.Fatal(err)
	}

	valid := func() *flv1.SubmitLocalUpdateRequest {
		return &flv1.SubmitLocalUpdateRequest{
			WeightsPayload:   payload,
			WeightsFormat:    networkWeightsFormat,
			ProtocolVersion:  ModelProtocolVersion,
			ModelId:          "classifier",
			SchemaSha256:     schema[:],
			TensorManifest:   cloneManifest(manifest),
			BaseModelVersion: "bootstrap",
		}
	}

	tests := []struct {
		name   string
		mutate func(*flv1.SubmitLocalUpdateRequest)
		code   codes.Code
	}{
		{"protocol version", func(req *flv1.SubmitLocalUpdateRequest) { req.ProtocolVersion = 99 }, codes.InvalidArgument},
		{"model id", func(req *flv1.SubmitLocalUpdateRequest) { req.ModelId = "other" }, codes.FailedPrecondition},
		{"schema digest", func(req *flv1.SubmitLocalUpdateRequest) { req.SchemaSha256 = make([]byte, sha256.Size) }, codes.InvalidArgument},
		{"manifest dimensions", func(req *flv1.SubmitLocalUpdateRequest) { req.TensorManifest[0].Dimensions[0]++ }, codes.InvalidArgument},
		{"manifest dtype", func(req *flv1.SubmitLocalUpdateRequest) { req.TensorManifest[0].Dtype = "float64" }, codes.InvalidArgument},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := valid()
			test.mutate(req)
			err := service.validateUpdateEnvelope(req)
			if status.Code(err) != test.code {
				t.Fatalf("code = %s, want %s; err=%v", status.Code(err), test.code, err)
			}
		})
	}
}

func TestEnvelopeRejectsUpdateSchemaDifferentFromCurrentModel(t *testing.T) {
	currentPayload := mustEnvelopePayload(t, []float32{1, 2, 3})
	currentDigest := sha256.Sum256(currentPayload)
	inner := &envelopeTestService{model: &flv1.GlobalModel{
		ModelVersion:   "round-1",
		RoundId:        1,
		WeightsPayload: currentPayload,
		WeightsFormat:  networkWeightsFormat,
		Sha256:         currentDigest[:],
	}}
	service, err := NewEnvelopeService(inner, "classifier")
	if err != nil {
		t.Fatal(err)
	}

	req := validEnvelopeRequest(t, "classifier", "round-1", []float32{1, 2, 3, 4})
	_, err = service.SubmitLocalUpdate(context.Background(), req)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %s, want %s; err=%v", status.Code(err), codes.FailedPrecondition, err)
	}
	if inner.submitted {
		t.Fatal("schema-mismatched update reached the wrapped coordinator")
	}
}

func TestEnvelopeAllowsBootstrapToBindFirstSchema(t *testing.T) {
	inner := &envelopeTestService{model: &flv1.GlobalModel{
		ModelVersion:  "bootstrap",
		RoundId:       0,
		WeightsFormat: networkWeightsFormat,
	}}
	service, err := NewEnvelopeService(inner, "classifier")
	if err != nil {
		t.Fatal(err)
	}

	req := validEnvelopeRequest(t, "classifier", "bootstrap", []float32{1, 2, 3})
	response, err := service.SubmitLocalUpdate(context.Background(), req)
	if err != nil {
		t.Fatalf("submit bootstrap update: %v", err)
	}
	if !response.GetAccepted() || !inner.submitted {
		t.Fatal("valid first-schema update was not delegated")
	}
}

func validEnvelopeRequest(t *testing.T, modelID, baseVersion string, values []float32) *flv1.SubmitLocalUpdateRequest {
	t.Helper()
	payload := mustEnvelopePayload(t, values)
	manifest, err := manifestForPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	schema := modelSchemaDigest(manifest)
	return &flv1.SubmitLocalUpdateRequest{
		NodeId:           "worker-1",
		RegistrationId:   "registration-1",
		RoundId:          0,
		BaseModelVersion: baseVersion,
		WeightsPayload:   payload,
		WeightsFormat:    networkWeightsFormat,
		ProtocolVersion:  ModelProtocolVersion,
		ModelId:          modelID,
		SchemaSha256:     schema[:],
		TensorManifest:   cloneManifest(manifest),
	}
}

func cloneManifest(entries []*flv1.TensorManifestEntry) []*flv1.TensorManifestEntry {
	cloned := make([]*flv1.TensorManifestEntry, len(entries))
	for index, entry := range entries {
		cloned[index] = &flv1.TensorManifestEntry{
			Name:         entry.GetName(),
			Dtype:        entry.GetDtype(),
			Dimensions:   append([]uint64(nil), entry.GetDimensions()...),
			ElementCount: entry.GetElementCount(),
		}
	}
	return cloned
}

func mustEnvelopePayload(t *testing.T, values []float32) []byte {
	t.Helper()
	payload, err := encodeNPYFloat32(values)
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	return payload
}
