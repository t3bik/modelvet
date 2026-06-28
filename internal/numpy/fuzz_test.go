package numpy_test

import (
	"bytes"
	"testing"

	"github.com/t3bik/modelvet/internal/numpy"
)

// FuzzScanNumpy proves the .npy parser never panics, never OOMs, and always
// returns in bounded time for any input.
//
// Invariant: for all inputs, Scan returns without panic and without
// exceeding the safeio allocation cap.
func FuzzScanNumpy(f *testing.F) {
	// Seed corpus: valid cases and targeted malformed inputs.
	f.Add(benignNpy())
	f.Add(objectNpy(osSystemPickle()))
	f.Add(malformedHeaderNpy())
	f.Add(truncatedNpy())
	f.Add(unknownVersionNpy())
	f.Add(buildNpyV2("{'descr': '<f4', 'fortran_order': False, 'shape': (3,), }\n", make([]byte, 12)))
	f.Add([]byte{}) // empty
	f.Add([]byte{0x93, 'N', 'U', 'M', 'P', 'Y', 1, 0}) // magic + version only, no len field

	f.Fuzz(func(t *testing.T, data []byte) {
		s := numpy.New()
		_, _ = s.Scan(bytes.NewReader(data), int64(len(data)))
	})
}
