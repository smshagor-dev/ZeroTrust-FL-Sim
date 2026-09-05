package coordinator

import (
	"path/filepath"
	"testing"

	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
)

func TestDurableServiceRejectsExperimentConfigDigestDrift(t *testing.T) {
	store, err := NewFileStateStore(filepath.Join(t.TempDir(), "coordinator-state.json"))
	if err != nil {
		t.Fatalf("create state store: %v", err)
	}

	initial := ExperimentConfig{
		ID:           "experiment-config-drift",
		ConfigSHA256: "6666666666666666666666666666666666666666666666666666666666666666",
	}
	if _, err := NewDurableServiceWithExperiment(ztsecurity.NewRegistrationStore(), Config{}, store, initial); err != nil {
		t.Fatalf("initialize durable experiment: %v", err)
	}

	drifted := ExperimentConfig{
		ID:           initial.ID,
		ConfigSHA256: "7777777777777777777777777777777777777777777777777777777777777777",
	}
	if _, err := NewDurableServiceWithExperiment(ztsecurity.NewRegistrationStore(), Config{}, store, drifted); err == nil {
		t.Fatal("durable service accepted experiment configuration digest drift")
	}
}

func TestExperimentConfigDigestValidationFailsClosed(t *testing.T) {
	for _, digest := range []string{
		"",
		"ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD",
		"1234",
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
	} {
		if err := validateExperimentConfigDigest(digest); err == nil {
			t.Fatalf("invalid experiment configuration digest %q was accepted", digest)
		}
	}
}
