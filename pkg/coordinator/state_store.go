package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/protobuf/proto"
)

const (
	coordinatorStateSchemaVersion = 1
	maxCoordinatorStateBytes      = 256 << 20
)

var ErrStateNotFound = errors.New("coordinator state not found")

type PersistedUpdate struct {
	NodeID      string    `json:"node_id"`
	UpdateID    string    `json:"update_id"`
	Values      []float32 `json:"values"`
	SampleCount uint64    `json:"sample_count"`
}

type StateSnapshot struct {
	Model         *flv1.GlobalModel
	Pending       []PersistedUpdate
	Registrations []ztsecurity.Registration
}

type StateStore interface {
	Load(context.Context) (StateSnapshot, error)
	Commit(context.Context, StateSnapshot) error
}

type FileStateStore struct {
	path string
	mu   sync.Mutex
}

type diskState struct {
	SchemaVersion int                       `json:"schema_version"`
	ModelProto    []byte                    `json:"model_proto"`
	Pending       []PersistedUpdate         `json:"pending_updates"`
	Registrations []ztsecurity.Registration `json:"registrations"`
}

func NewFileStateStore(path string) (*FileStateStore, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, errors.New("coordinator state file path is required")
	}
	cleaned := filepath.Clean(trimmed)
	if cleaned == "." || filepath.Base(cleaned) == "." {
		return nil, errors.New("coordinator state file path must reference a file")
	}
	return &FileStateStore{path: cleaned}, nil
}

func (s *FileStateStore) Load(ctx context.Context) (StateSnapshot, error) {
	if s == nil {
		return StateSnapshot{}, errors.New("state store is nil")
	}
	if err := ctx.Err(); err != nil {
		return StateSnapshot{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	info, err := os.Lstat(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return StateSnapshot{}, ErrStateNotFound
		}
		return StateSnapshot{}, fmt.Errorf("inspect coordinator state file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return StateSnapshot{}, errors.New("coordinator state file must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return StateSnapshot{}, errors.New("coordinator state path must be a regular file")
	}
	if info.Size() > maxCoordinatorStateBytes {
		return StateSnapshot{}, fmt.Errorf("coordinator state file exceeds %d bytes", maxCoordinatorStateBytes)
	}

	file, err := os.Open(s.path)
	if err != nil {
		return StateSnapshot{}, fmt.Errorf("open coordinator state file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxCoordinatorStateBytes+1))
	if err != nil {
		return StateSnapshot{}, fmt.Errorf("read coordinator state file: %w", err)
	}
	if len(data) > maxCoordinatorStateBytes {
		return StateSnapshot{}, fmt.Errorf("coordinator state file exceeds %d bytes", maxCoordinatorStateBytes)
	}

	var encoded diskState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&encoded); err != nil {
		return StateSnapshot{}, fmt.Errorf("decode coordinator state: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return StateSnapshot{}, err
	}
	if encoded.SchemaVersion != coordinatorStateSchemaVersion {
		return StateSnapshot{}, fmt.Errorf("unsupported coordinator state schema version %d", encoded.SchemaVersion)
	}
	if len(encoded.ModelProto) == 0 {
		return StateSnapshot{}, errors.New("coordinator state is missing the global model")
	}

	model := &flv1.GlobalModel{}
	if err := proto.Unmarshal(encoded.ModelProto, model); err != nil {
		return StateSnapshot{}, fmt.Errorf("decode persisted global model: %w", err)
	}
	snapshot := StateSnapshot{
		Model:         model,
		Pending:       clonePersistedUpdates(encoded.Pending),
		Registrations: append([]ztsecurity.Registration(nil), encoded.Registrations...),
	}
	if err := validateStateSnapshot(snapshot); err != nil {
		return StateSnapshot{}, fmt.Errorf("validate coordinator state: %w", err)
	}
	return cloneStateSnapshot(snapshot), nil
}

func (s *FileStateStore) Commit(ctx context.Context, snapshot StateSnapshot) error {
	if s == nil {
		return errors.New("state store is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateStateSnapshot(snapshot); err != nil {
		return fmt.Errorf("validate coordinator state before commit: %w", err)
	}

	modelBytes, err := proto.Marshal(snapshot.Model)
	if err != nil {
		return fmt.Errorf("encode global model for coordinator state: %w", err)
	}
	pending := clonePersistedUpdates(snapshot.Pending)
	registrations := append([]ztsecurity.Registration(nil), snapshot.Registrations...)
	sort.Slice(pending, func(i, j int) bool { return pending[i].NodeID < pending[j].NodeID })
	sort.Slice(registrations, func(i, j int) bool { return registrations[i].NodeID < registrations[j].NodeID })
	encoded := diskState{
		SchemaVersion: coordinatorStateSchemaVersion,
		ModelProto:    modelBytes,
		Pending:       pending,
		Registrations: registrations,
	}
	data, err := json.MarshalIndent(encoded, "", "  ")
	if err != nil {
		return fmt.Errorf("encode coordinator state: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxCoordinatorStateBytes {
		return fmt.Errorf("coordinator state exceeds %d bytes", maxCoordinatorStateBytes)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if info, err := os.Lstat(s.path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("coordinator state file must not be a symbolic link")
		}
		if !info.Mode().IsRegular() {
			return errors.New("coordinator state path must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect coordinator state file: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create coordinator state directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".coordinator-state-*")
	if err != nil {
		return fmt.Errorf("create temporary coordinator state file: %w", err)
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		_ = temp.Close()
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()

	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("set coordinator state file permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("write coordinator state: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync coordinator state: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close coordinator state: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, s.path); err != nil {
		return fmt.Errorf("atomically replace coordinator state: %w", err)
	}
	removeTemp = false

	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open coordinator state directory for sync: %w", err)
	}
	defer dirHandle.Close()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("sync coordinator state directory: %w", err)
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("coordinator state contains trailing JSON values")
		}
		return fmt.Errorf("decode trailing coordinator state data: %w", err)
	}
	return nil
}

func validateStateSnapshot(snapshot StateSnapshot) error {
	if snapshot.Model == nil {
		return errors.New("global model is required")
	}
	if strings.TrimSpace(snapshot.Model.GetModelVersion()) == "" {
		return errors.New("global model version is required")
	}
	if snapshot.Model.GetWeightsFormat() != networkWeightsFormat {
		return fmt.Errorf("global model weights_format must be %q", networkWeightsFormat)
	}

	expectedVectorLength := 0
	if payload := snapshot.Model.GetWeightsPayload(); len(payload) > 0 {
		values, err := decodeNPYFloat32(payload)
		if err != nil {
			return fmt.Errorf("decode global model payload: %w", err)
		}
		expectedVectorLength = len(values)
		digest := sha256.Sum256(payload)
		if len(snapshot.Model.GetSha256()) != sha256.Size || !bytes.Equal(digest[:], snapshot.Model.GetSha256()) {
			return errors.New("global model SHA-256 digest does not match payload")
		}
	} else if len(snapshot.Model.GetSha256()) != 0 {
		return errors.New("global model without payload must not contain a SHA-256 digest")
	}

	seenUpdates := make(map[string]struct{}, len(snapshot.Pending))
	pendingVectorLength := expectedVectorLength
	for _, update := range snapshot.Pending {
		if strings.TrimSpace(update.NodeID) == "" || strings.TrimSpace(update.UpdateID) == "" {
			return errors.New("pending updates require node_id and update_id")
		}
		if _, exists := seenUpdates[update.NodeID]; exists {
			return fmt.Errorf("duplicate pending update for node %q", update.NodeID)
		}
		seenUpdates[update.NodeID] = struct{}{}
		if update.SampleCount == 0 || update.SampleCount > maxReportedSampleCount {
			return fmt.Errorf("pending update for %q has invalid sample count", update.NodeID)
		}
		if len(update.Values) == 0 {
			return fmt.Errorf("pending update for %q has an empty vector", update.NodeID)
		}
		if pendingVectorLength == 0 {
			pendingVectorLength = len(update.Values)
		}
		if len(update.Values) != pendingVectorLength {
			return errors.New("pending update vector lengths do not match")
		}
		for _, value := range update.Values {
			converted := float64(value)
			if math.IsNaN(converted) || math.IsInf(converted, 0) {
				return fmt.Errorf("pending update for %q contains non-finite values", update.NodeID)
			}
		}
	}

	seenRegistrations := make(map[string]struct{}, len(snapshot.Registrations))
	for _, registration := range snapshot.Registrations {
		if strings.TrimSpace(registration.NodeID) == "" || strings.TrimSpace(registration.Role) == "" || strings.TrimSpace(registration.CertificateFingerprint) == "" || strings.TrimSpace(registration.RegistrationID) == "" {
			return errors.New("persisted registration is missing a required binding")
		}
		if registration.ExpiresAt.IsZero() {
			return fmt.Errorf("persisted registration for %q has no expiry", registration.NodeID)
		}
		if _, exists := seenRegistrations[registration.NodeID]; exists {
			return fmt.Errorf("duplicate persisted registration for node %q", registration.NodeID)
		}
		seenRegistrations[registration.NodeID] = struct{}{}
	}
	return nil
}

func cloneStateSnapshot(snapshot StateSnapshot) StateSnapshot {
	cloned := StateSnapshot{
		Pending:       clonePersistedUpdates(snapshot.Pending),
		Registrations: append([]ztsecurity.Registration(nil), snapshot.Registrations...),
	}
	if snapshot.Model != nil {
		cloned.Model = proto.Clone(snapshot.Model).(*flv1.GlobalModel)
	}
	return cloned
}

func clonePersistedUpdates(updates []PersistedUpdate) []PersistedUpdate {
	cloned := make([]PersistedUpdate, len(updates))
	for index, update := range updates {
		cloned[index] = PersistedUpdate{
			NodeID:      update.NodeID,
			UpdateID:    update.UpdateID,
			Values:      append([]float32(nil), update.Values...),
			SampleCount: update.SampleCount,
		}
	}
	return cloned
}
