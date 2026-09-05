package coordinator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	defaultExperimentID = "default"
	maxExperimentIDLen  = 256
)

// ExperimentConfig is the immutable runtime identity supplied when a durable
// coordinator is opened. ConfigSHA256 may fingerprint a wider orchestration
// manifest (dataset, partitioning, seeds, privacy and threat configuration)
// without duplicating those schemas in the Go coordinator.
type ExperimentConfig struct {
	ID           string
	ConfigSHA256 string
}

// ExperimentMetadata is persisted with the recovery policy. CreatedAt is set
// once when durable state is initialized and the persisted value remains
// authoritative after restart and disaster recovery.
type ExperimentMetadata struct {
	ID           string    `json:"id"`
	ConfigSHA256 string    `json:"config_sha256"`
	CreatedAt    time.Time `json:"created_at"`
}

func newExperimentMetadata(cfg ExperimentConfig, policy StatePolicy, now time.Time) (ExperimentMetadata, error) {
	id := strings.TrimSpace(cfg.ID)
	if id == "" {
		id = defaultExperimentID
	}
	if err := validateExperimentID(id); err != nil {
		return ExperimentMetadata{}, err
	}

	configDigest := strings.TrimSpace(cfg.ConfigSHA256)
	if configDigest == "" {
		computed, err := coordinatorVisibleExperimentDigest(policy)
		if err != nil {
			return ExperimentMetadata{}, err
		}
		configDigest = computed
	}
	if err := validateExperimentConfigDigest(configDigest); err != nil {
		return ExperimentMetadata{}, err
	}

	metadata := ExperimentMetadata{
		ID:           id,
		ConfigSHA256: configDigest,
		CreatedAt:    normalizeExperimentTime(now),
	}
	if err := validateExperimentMetadata(metadata); err != nil {
		return ExperimentMetadata{}, err
	}
	return metadata, nil
}

func coordinatorVisibleExperimentDigest(policy StatePolicy) (string, error) {
	type coordinatorIdentity struct {
		SchemaVersion       int           `json:"schema_version"`
		LeaseTTLNS          time.Duration `json:"lease_ttl_ns"`
		MaxUpdateBytes      int           `json:"max_update_bytes"`
		MinUpdates          int           `json:"min_updates"`
		MaxUpdatesPerMinute int           `json:"max_updates_per_minute"`
		AggregationMethod   string        `json:"aggregation_method"`
	}

	payload := coordinatorIdentity{
		SchemaVersion:       1,
		LeaseTTLNS:          policy.LeaseTTL,
		MaxUpdateBytes:      policy.MaxUpdateBytes,
		MinUpdates:          policy.MinUpdates,
		MaxUpdatesPerMinute: policy.MaxUpdatesPerMinute,
		AggregationMethod:   policy.AggregationMethod,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode coordinator-visible experiment configuration: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validateExperimentMetadata(metadata ExperimentMetadata) error {
	if err := validateExperimentID(metadata.ID); err != nil {
		return err
	}
	if err := validateExperimentConfigDigest(metadata.ConfigSHA256); err != nil {
		return err
	}
	if metadata.CreatedAt.IsZero() || metadata.CreatedAt.Location() != time.UTC || !metadata.CreatedAt.Equal(normalizeExperimentTime(metadata.CreatedAt)) {
		return errors.New("experiment created_at must use UTC microsecond precision")
	}
	return nil
}

func validateExperimentID(id string) error {
	if id == "" || id != strings.TrimSpace(id) {
		return errors.New("experiment id is required and must not contain surrounding whitespace")
	}
	if len(id) > maxExperimentIDLen {
		return fmt.Errorf("experiment id exceeds %d bytes", maxExperimentIDLen)
	}
	if strings.ContainsAny(id, "\x00\r\n") {
		return errors.New("experiment id contains control characters")
	}
	return nil
}

func validateExperimentConfigDigest(value string) error {
	if value == "" || value != strings.ToLower(value) {
		return errors.New("experiment config SHA-256 must be lowercase hexadecimal")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("experiment config SHA-256 must encode exactly 32 bytes")
	}
	return nil
}

func sameExperimentIdentity(left, right ExperimentMetadata) bool {
	return left.ID == right.ID && left.ConfigSHA256 == right.ConfigSHA256
}

func experimentMetadataMissing(metadata ExperimentMetadata) bool {
	return metadata.ID == "" && metadata.ConfigSHA256 == "" && metadata.CreatedAt.IsZero()
}

func normalizeExperimentTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func legacyExperimentValidationPlaceholder() ExperimentMetadata {
	return ExperimentMetadata{
		ID:           "legacy-v1-validation",
		ConfigSHA256: strings.Repeat("0", sha256.Size*2),
		CreatedAt:    time.Unix(1, 0).UTC(),
	}
}
