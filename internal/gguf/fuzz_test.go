package gguf_test

import (
	"bytes"
	"testing"

	"github.com/t3bik/modelvet/internal/gguf"
)

// FuzzScanGGUF proves that the GGUF scanner never panics and always returns
// without OOM on any input. The invariant: Scan returns (no panic).
func FuzzScanGGUF(f *testing.F) {
	b := newGGUF()
	f.Add(b.build())
	f.Add(b.withKVType(99))
	f.Add(b.withOffsetPastEOF())
	f.Add(b.withDimOverflow())
	f.Add(b.withHugeString())
	f.Add(b.withHugeKVCount(^uint64(0)))
	f.Add([]byte{}) // empty

	f.Fuzz(func(t *testing.T, data []byte) {
		s := gguf.New()
		// INVARIANT: must not panic; we do not care about the return values.
		_, _ = s.Scan(bytes.NewReader(data), int64(len(data)))
	})
}
