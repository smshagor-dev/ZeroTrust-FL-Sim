package coordinator

import (
	"context"
	"errors"
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
	"google.golang.org/protobuf/proto"
)

type failOnceStateStore struct {
	failed  bool
	commits []StateSnapshot
}

func (s *failOnceStateStore) Load(context.Context) (StateSnapshot, error) {
	return StateSnapshot{}, ErrStateNotFound
}

func (s *failOnceStateStore) Commit(_ context.Context, snapshot StateSnapshot) error {
	if !s.failed {
		s.failed = true
		return errors.New("injected durable write failure")
	}
	s.commits = append(s.commits, cloneStateSnapshot(snapshot))
	return nil
}

func newRollbackTestDurableService(t *testing.T, service *Service, store StateStore) *DurableService {
	t.Helper()
	durable := &DurableService{service: service, store: store}
	experiment, err := newExperimentMetadata(ExperimentConfig{}, durable.basePolicy(), time.Now())
	if err != nil {
		t.Fatalf("initialize rollback test experiment metadata: %v", err)
	}
	durable.experiment = experiment
	return durable
}

func TestCommitOrRollbackRestoresPreviousStateInMemoryAndStore(t *testing.T) {
	base, err := NewService(ztsecurity.NewRegistrationStore(), Config{})
	if err != nil {
		t.Fatalf("create coordinator service: %v", err)
	}
	store := &failOnceStateStore{}
	durable := newRollbackTestDurableService(t, base, store)
	before := durable.captureSnapshot()

	base.modelMu.Lock()
	base.model = &flv1.GlobalModel{
		ModelVersion:  "transient-uncommitted",
		RoundId:       1,
		WeightsFormat: networkWeightsFormat,
		CreatedAtUnix: before.Model.GetCreatedAtUnix() + 1,
	}
	base.modelMu.Unlock()

	if err := durable.commitOrRollback(context.Background(), before, "test"); err == nil {
		t.Fatal("injected durable write failure was acknowledged")
	}
	if !proto.Equal(base.currentModel(), before.Model) {
		t.Fatalf("in-memory model was not rolled back: got %v want %v", base.currentModel(), before.Model)
	}
	if len(store.commits) != 1 {
		t.Fatalf("persistent rollback commits = %d, want 1", len(store.commits))
	}
	if !proto.Equal(store.commits[0].Model, before.Model) {
		t.Fatalf("persistent rollback model = %v, want %v", store.commits[0].Model, before.Model)
	}
}
