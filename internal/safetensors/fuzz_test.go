package safetensors_test

import (
	"bytes"
	"testing"

	"github.com/t3bik/modelvet/internal/safetensors"
)

// FuzzScanSafetensors proves the scanner never panics on any input.
// Seeds are kept well under the Go fuzzer 100 MiB shared-memory cap.
func FuzzScanSafetensors(f *testing.F) {
	b := newST().addTensor("w", "F32", []int64{4}, 0, 16)
	f.Add(b.build(16))
	f.Add(withBadJSON())
	// Use the small seed (triggers ST-HEADERLEN-001); the large variant that
	// triggers ST-HEADERLEN-002 is not suitable as a fuzz seed because it
	// exceeds the 100 MiB fuzzer shared-memory cap.
	f.Add(withDoSHeaderLenFuzzSeed())
	f.Add([]byte{}) // empty

	f.Fuzz(func(t *testing.T, data []byte) {
		s := safetensors.New()
		_, _ = s.Scan(bytes.NewReader(data), int64(len(data)))
	})
}
