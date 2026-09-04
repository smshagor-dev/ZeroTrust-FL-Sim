package coordinator

import (
	"testing"
	"time"

	flv1 "github.com/smshagor-dev/ZeroTrust-FL-Sim/gen/go/zerotrust/fl/v1"
)

func TestNormalizeAggregationMethodDefaultsToMedian(t *testing.T) {
	method, err := normalizeAggregationMethod("")
	if err != nil {
		t.Fatalf("normalize aggregation method: %v", err)
	}
	if method != "median" {
		t.Fatalf("default method = %q, want median", method)
	}
}

func TestMedianAggregationRejectsOutlier(t *testing.T) {
	updates := map[string]pendingUpdate{
		"a": {Values: []float32{1, 1}, SampleCount: 10},
		"b": {Values: []float32{2, 2}, SampleCount: 10},
		"c": {Values: []float32{1000, -1000}, SampleCount: 10},
	}
	got, err := aggregatePendingUpdates(updates, 2, "median")
	if err != nil {
		t.Fatalf("aggregate median: %v", err)
	}
	if got[0] != 2 || got[1] != 1 {
		t.Fatalf("median = %v, want [2 1]", got)
	}
}

func TestWeightedMeanIsExplicitTrustedMode(t *testing.T) {
	updates := map[string]pendingUpdate{
		"a": {Values: []float32{0}, SampleCount: 1},
		"b": {Values: []float32{10}, SampleCount: 3},
	}
	got, err := aggregatePendingUpdates(updates, 1, "weighted_mean")
	if err != nil {
		t.Fatalf("aggregate weighted mean: %v", err)
	}
	if got[0] != 7.5 {
		t.Fatalf("weighted mean = %v, want 7.5", got[0])
	}
}

func TestSecurityMetadataRequiresFreshNonce(t *testing.T) {
	now := time.Now().UTC()
	valid := &flv1.SecurityMetadata{
		IssuedAtUnix: now.Unix(),
		Nonce:        []byte("0123456789abcdef"),
	}
	if err := validateSecurityMetadata(valid, now); err != nil {
		t.Fatalf("valid metadata rejected: %v", err)
	}

	stale := &flv1.SecurityMetadata{
		IssuedAtUnix: now.Add(-3 * time.Minute).Unix(),
		Nonce:        []byte("0123456789abcdef"),
	}
	if err := validateSecurityMetadata(stale, now); err == nil {
		t.Fatal("stale metadata was accepted")
	}

	shortNonce := &flv1.SecurityMetadata{
		IssuedAtUnix: now.Unix(),
		Nonce:        []byte("short"),
	}
	if err := validateSecurityMetadata(shortNonce, now); err == nil {
		t.Fatal("short nonce was accepted")
	}
}

func TestNonceReplayCacheRejectsReuse(t *testing.T) {
	now := time.Now().UTC()
	s := &Service{nonces: make(map[string]time.Time)}
	nonce := []byte("0123456789abcdef")
	if !s.acceptNonceLocked("worker-a", nonce, now) {
		t.Fatal("first nonce use was rejected")
	}
	if s.acceptNonceLocked("worker-a", nonce, now.Add(time.Second)) {
		t.Fatal("replayed nonce was accepted")
	}
	if !s.acceptNonceLocked("worker-b", nonce, now.Add(time.Second)) {
		t.Fatal("same nonce should be scoped independently per worker")
	}
}
