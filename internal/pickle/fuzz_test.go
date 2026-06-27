package pickle_test

import (
	"bytes"
	"testing"

	"github.com/t3bik/modelvet/internal/pickle"
)

// FuzzScanPickle proves the opcode walker never panics on any input.
func FuzzScanPickle(f *testing.F) {
	f.Add(benignPickle())
	f.Add(osSystemGadget())
	f.Add(truncatedPickle())
	f.Add(unknownOpcodePickle())
	f.Add(zipOf(benignPickle()))
	f.Add([]byte{}) // empty

	f.Fuzz(func(t *testing.T, data []byte) {
		s := pickle.New()
		_, _ = s.Scan(bytes.NewReader(data), int64(len(data)))
	})
}
