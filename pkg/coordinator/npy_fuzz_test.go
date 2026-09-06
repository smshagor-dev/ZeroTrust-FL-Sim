package coordinator

import (
	"math"
	"testing"
)

func FuzzDecodeNPYFloat32(f *testing.F) {
	valid, err := encodeNPYFloat32([]float32{0, 1, -2.5, 3.25})
	if err != nil {
		f.Fatalf("create seed payload: %v", err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte("\x93NUMPY"))

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 1<<20 {
			t.Skip()
		}

		values, err := decodeNPYFloat32(payload)
		if err != nil {
			return
		}
		if len(values) == 0 {
			t.Fatal("decoder accepted an empty model vector")
		}
		for _, value := range values {
			if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
				t.Fatal("decoder accepted a non-finite model value")
			}
		}

		roundTrip, err := encodeNPYFloat32(values)
		if err != nil {
			t.Fatalf("re-encode accepted vector: %v", err)
		}
		again, err := decodeNPYFloat32(roundTrip)
		if err != nil {
			t.Fatalf("decode round-trip payload: %v", err)
		}
		if len(again) != len(values) {
			t.Fatalf("round-trip vector length changed: %d != %d", len(again), len(values))
		}
		for index := range values {
			if math.Float32bits(values[index]) != math.Float32bits(again[index]) {
				t.Fatalf("round-trip value changed at index %d", index)
			}
		}
	})
}
