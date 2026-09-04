package coordinator

import (
	"math"
	"testing"

	ztsecurity "github.com/smshagor-dev/ZeroTrust-FL-Sim/pkg/security"
)

func TestServiceDefaultsToMedianAggregation(t *testing.T) {
	service, err := NewService(ztsecurity.NewRegistrationStore(), Config{})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if service.aggregationMethod != "median" {
		t.Fatalf("aggregation method = %q, want median", service.aggregationMethod)
	}
}

func TestMedianAggregationRejectsSingleExtremeOutlier(t *testing.T) {
	updates := map[string]pendingUpdate{
		"a": {NodeID: "a", Values: []float32{1.0, 1.0}, SampleCount: 10},
		"b": {NodeID: "b", Values: []float32{1.2, 0.8}, SampleCount: 10},
		"m": {NodeID: "m", Values: []float32{100.0, -100.0}, SampleCount: 10_000_000},
	}
	got, err := aggregatePendingUpdates(updates, 2, "median", 0.2)
	if err != nil {
		t.Fatalf("aggregatePendingUpdates() error = %v", err)
	}
	if math.Abs(float64(got[0]-1.2)) > 1e-6 || math.Abs(float64(got[1]-0.8)) > 1e-6 {
		t.Fatalf("median result = %v, want [1.2 0.8]", got)
	}
}

func TestTrimmedMeanDropsCoordinateExtremes(t *testing.T) {
	updates := map[string]pendingUpdate{
		"a": {Values: []float32{1.0}, SampleCount: 1},
		"b": {Values: []float32{1.1}, SampleCount: 1},
		"c": {Values: []float32{1.2}, SampleCount: 1},
		"d": {Values: []float32{100.0}, SampleCount: 1},
		"e": {Values: []float32{-100.0}, SampleCount: 1},
	}
	got, err := aggregatePendingUpdates(updates, 1, "trimmed_mean", 0.2)
	if err != nil {
		t.Fatalf("aggregatePendingUpdates() error = %v", err)
	}
	if math.Abs(float64(got[0]-1.1)) > 1e-6 {
		t.Fatalf("trimmed mean result = %v, want about 1.1", got)
	}
}

func TestWeightedMeanRemainsExplicitTrustedMode(t *testing.T) {
	updates := map[string]pendingUpdate{
		"small": {Values: []float32{1.0}, SampleCount: 1},
		"large": {Values: []float32{3.0}, SampleCount: 3},
	}
	got, err := aggregatePendingUpdates(updates, 1, "weighted_mean", 0.2)
	if err != nil {
		t.Fatalf("aggregatePendingUpdates() error = %v", err)
	}
	if math.Abs(float64(got[0]-2.5)) > 1e-6 {
		t.Fatalf("weighted mean result = %v, want 2.5", got)
	}
}
