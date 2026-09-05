package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	// ModelProtocolVersion is the first stable network model-envelope version.
	ModelProtocolVersion uint32 = 1
	// DefaultModelID is used when operators do not provide an explicit model ID.
	DefaultModelID = "global-model"

	flatTensorName = "flat_weights"
	float32DType   = "float32"
)

var schemaDomainV1 = []byte("ztfl-model-schema-v1\x00")

// EnvelopeService adds the stable v1 model envelope to an existing coordinator
// implementation without changing its authentication, aggregation, or durable
// state semantics. It is intentionally a network-boundary adapter so legacy
// durable protobuf records remain recoverable while all newly served models and
// submitted updates use an explicit protocol/model/schema identity.
type EnvelopeService struct {
	flv1.UnimplementedCoordinatorServiceServer

	inner   flv1.CoordinatorServiceServer
	modelID string
}

// NewEnvelopeService wraps a coordinator service with model-envelope validation.
func NewEnvelopeService(inner flv1.CoordinatorServiceServer, modelID string) (*EnvelopeService, error) {
	if inner == nil {
		return nil, errors.New("coordinator service is required")
	}
	modelID = strings.TrimSpace(modelID)
	if modelID == "" {
		return nil, errors.New("model id is required")
	}
	if len(modelID) > 256 {
		return nil, errors.New("model id exceeds 256 bytes")
	}
	if strings.ContainsAny(modelID, "\x00\r\n") {
		return nil, errors.New("model id contains control characters")
	}
	return &EnvelopeService{inner: inner, modelID: modelID}, nil
}

func (s *EnvelopeService) RegisterNode(ctx context.Context, req *flv1.RegisterNodeRequest) (*flv1.RegisterNodeResponse, error) {
	return s.inner.RegisterNode(ctx, req)
}

func (s *EnvelopeService) Heartbeat(ctx context.Context, req *flv1.HeartbeatRequest) (*flv1.HeartbeatResponse, error) {
	return s.inner.Heartbeat(ctx, req)
}

func (s *EnvelopeService) GetGlobalModel(ctx context.Context, req *flv1.GetGlobalModelRequest) (*flv1.GlobalModel, error) {
	model, err := s.inner.GetGlobalModel(ctx, req)
	if err != nil {
		return nil, err
	}
	decorated, err := s.decorateGlobalModel(model)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid coordinator model envelope source: %v", err)
	}
	return decorated, nil
}

func (s *EnvelopeService) SubmitLocalUpdate(ctx context.Context, req *flv1.SubmitLocalUpdateRequest) (*flv1.SubmitLocalUpdateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "local update request is required")
	}
	if err := s.validateUpdateEnvelope(req); err != nil {
		return nil, err
	}

	// Compare the submitted schema with the current authoritative global model.
	// A payload-free bootstrap model has no bound schema yet; the first valid
	// update establishes the vector schema and subsequent rounds must match it.
	current, err := s.inner.GetGlobalModel(ctx, &flv1.GetGlobalModelRequest{
		NodeId:            req.GetNodeId(),
		RegistrationId:    req.GetRegistrationId(),
		KnownModelVersion: req.GetBaseModelVersion(),
		Security:          req.GetSecurity(),
	})
	if err != nil {
		return nil, err
	}
	current, err = s.decorateGlobalModel(current)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid current model envelope: %v", err)
	}
	if len(current.GetSchemaSha256()) > 0 && !bytes.Equal(current.GetSchemaSha256(), req.GetSchemaSha256()) {
		return nil, status.Error(codes.FailedPrecondition, "update schema does not match current global model schema")
	}

	return s.inner.SubmitLocalUpdate(ctx, req)
}

func (s *EnvelopeService) RotateRegistration(ctx context.Context, req *flv1.RotateRegistrationRequest) (*flv1.RotateRegistrationResponse, error) {
	return s.inner.RotateRegistration(ctx, req)
}

func (s *EnvelopeService) RevokeRegistration(ctx context.Context, req *flv1.RevokeRegistrationRequest) (*flv1.RevokeRegistrationResponse, error) {
	return s.inner.RevokeRegistration(ctx, req)
}

func (s *EnvelopeService) decorateGlobalModel(model *flv1.GlobalModel) (*flv1.GlobalModel, error) {
	if model == nil {
		return nil, errors.New("global model is nil")
	}
	decorated := proto.Clone(model).(*flv1.GlobalModel)
	decorated.ProtocolVersion = ModelProtocolVersion
	decorated.ModelId = s.modelID

	payload := decorated.GetWeightsPayload()
	if len(payload) == 0 {
		decorated.SchemaSha256 = nil
		decorated.TensorManifest = nil
		return decorated, nil
	}
	if decorated.GetWeightsFormat() != networkWeightsFormat {
		return nil, fmt.Errorf("weights_format must be %q", networkWeightsFormat)
	}
	payloadDigest := sha256.Sum256(payload)
	if len(decorated.GetSha256()) != sha256.Size || !bytes.Equal(payloadDigest[:], decorated.GetSha256()) {
		return nil, errors.New("global model payload SHA-256 digest is invalid")
	}

	manifest, err := manifestForPayload(payload)
	if err != nil {
		return nil, err
	}
	schemaDigest := modelSchemaDigest(manifest)
	decorated.TensorManifest = manifest
	decorated.SchemaSha256 = schemaDigest[:]
	return decorated, nil
}

func (s *EnvelopeService) validateUpdateEnvelope(req *flv1.SubmitLocalUpdateRequest) error {
	if req.GetProtocolVersion() != ModelProtocolVersion {
		return status.Errorf(codes.InvalidArgument, "protocol_version must be %d", ModelProtocolVersion)
	}
	if req.GetModelId() != s.modelID {
		return status.Errorf(codes.FailedPrecondition, "model_id %q does not match coordinator model %q", req.GetModelId(), s.modelID)
	}
	if len(req.GetSchemaSha256()) != sha256.Size {
		return status.Error(codes.InvalidArgument, "schema_sha256 must contain a 32-byte SHA-256 digest")
	}
	manifest, err := manifestForPayload(req.GetWeightsPayload())
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid update tensor schema: %v", err)
	}
	if !manifestEqual(manifest, req.GetTensorManifest()) {
		return status.Error(codes.InvalidArgument, "tensor_manifest does not match the submitted weights payload")
	}
	expectedSchema := modelSchemaDigest(manifest)
	if !bytes.Equal(expectedSchema[:], req.GetSchemaSha256()) {
		return status.Error(codes.InvalidArgument, "schema_sha256 does not match tensor_manifest")
	}
	return nil
}

func manifestForPayload(payload []byte) ([]*flv1.TensorManifestEntry, error) {
	values, err := decodeNPYFloat32(payload)
	if err != nil {
		return nil, fmt.Errorf("decode float32 NPY payload: %w", err)
	}
	if len(values) == 0 {
		return nil, errors.New("tensor payload must not be empty")
	}
	elements := uint64(len(values))
	return []*flv1.TensorManifestEntry{{
		Name:         flatTensorName,
		Dtype:        float32DType,
		Dimensions:   []uint64{elements},
		ElementCount: elements,
	}}, nil
}

func manifestEqual(expected, actual []*flv1.TensorManifestEntry) bool {
	if len(expected) != len(actual) {
		return false
	}
	for index := range expected {
		left, right := expected[index], actual[index]
		if left == nil || right == nil || left.GetName() != right.GetName() || left.GetDtype() != right.GetDtype() || left.GetElementCount() != right.GetElementCount() {
			return false
		}
		if len(left.GetDimensions()) != len(right.GetDimensions()) {
			return false
		}
		for dimension := range left.GetDimensions() {
			if left.GetDimensions()[dimension] != right.GetDimensions()[dimension] {
				return false
			}
		}
	}
	return true
}

// modelSchemaDigest hashes a length-delimited canonical representation. The
// same byte encoding is implemented by the Python SDK so schema identities are
// deterministic across languages and independent of protobuf serialization.
func modelSchemaDigest(manifest []*flv1.TensorManifestEntry) [sha256.Size]byte {
	hasher := sha256.New()
	_, _ = hasher.Write(schemaDomainV1)
	writeUint32(hasher, uint32(len(manifest)))
	for _, entry := range manifest {
		writeString(hasher, entry.GetName())
		writeString(hasher, entry.GetDtype())
		writeUint32(hasher, uint32(len(entry.GetDimensions())))
		for _, dimension := range entry.GetDimensions() {
			writeUint64(hasher, dimension)
		}
		writeUint64(hasher, entry.GetElementCount())
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}

type byteWriter interface {
	Write([]byte) (int, error)
}

func writeString(writer byteWriter, value string) {
	writeUint32(writer, uint32(len(value)))
	_, _ = writer.Write([]byte(value))
}

func writeUint32(writer byteWriter, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func writeUint64(writer byteWriter, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}
