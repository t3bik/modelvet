package safeio_test

// safeio_extra_test.go — QA-authored additional tests for safeio.
// These cover boundary/overflow cases and function paths not hit by the
// developer's existing safeio_test.go.

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"github.com/t3bik/modelvet/internal/safeio"
)

// ─── Table-driven overflow-safe bounds check ─────────────────────────────────

func TestBytes_overflowTable(t *testing.T) {
	tests := []struct {
		name    string
		size    int64
		off     int64
		n       int64
		wantErr error
	}{
		{
			name: "exactly at end (off=0, n=size)",
			size: 10, off: 0, n: 10,
			wantErr: nil,
		},
		{
			name: "one byte past end",
			size: 10, off: 0, n: 11,
			wantErr: safeio.ErrOutOfBounds,
		},
		{
			name: "off+n exactly equals size",
			size: 8, off: 4, n: 4,
			wantErr: nil,
		},
		{
			name: "off+n one past size",
			size: 8, off: 4, n: 5,
			wantErr: safeio.ErrOutOfBounds,
		},
		{
			name: "off at maximum valid position",
			size: 10, off: 10, n: 0,
			wantErr: nil, // 0-byte read at exact end is valid
		},
		{
			name: "off beyond size",
			size: 10, off: 11, n: 0,
			wantErr: safeio.ErrOutOfBounds,
		},
		{
			name: "negative offset",
			size: 10, off: -1, n: 1,
			wantErr: safeio.ErrOutOfBounds,
		},
		{
			// This is the overflow-safety test: if we did off+n naively with
			// math.MaxInt64 values this would wrap. The implementation uses
			// n > size-off to avoid it.
			name:    "near-MaxInt64 off — overflow-safe check",
			size:    8, off: math.MaxInt64 - 1, n: 2,
			wantErr: safeio.ErrOutOfBounds,
		},
		{
			name: "maxInt64 n — overflow-safe check",
			size: 8, off: 0, n: math.MaxInt64,
			wantErr: safeio.ErrAllocTooLarge, // n > maxAlloc (256 MiB) fires first
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.size)
			r := safeio.NewReader(bytes.NewReader(data), tt.size, 256<<20)
			_, err := r.Bytes(tt.off, tt.n)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Bytes(%d, %d) on size=%d: unexpected error %v", tt.off, tt.n, tt.size, err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Bytes(%d, %d) on size=%d: got %v, want %v", tt.off, tt.n, tt.size, err, tt.wantErr)
				}
			}
		})
	}
}

// ─── MulU64 table ────────────────────────────────────────────────────────────

func TestMulU64_table(t *testing.T) {
	tests := []struct {
		name   string
		a, b   uint64
		wantP  uint64
		wantOK bool
	}{
		{"1*1", 1, 1, 1, true},
		{"0*0", 0, 0, 0, true},
		{"maxuint64*2 overflow", math.MaxUint64, 2, 0, false},
		{"maxuint64*maxuint64 overflow", math.MaxUint64, math.MaxUint64, 0, false},
		{"1<<32 * 1<<32 overflow", 1 << 32, 1 << 32, 0, false},
		{"1<<32 * (1<<32-1) ok", 1 << 32, (1 << 32) - 1, (1 << 32) * ((1 << 32) - 1), true},
		{"1*maxuint64", 1, math.MaxUint64, math.MaxUint64, true},
		{"maxuint64*1", math.MaxUint64, 1, math.MaxUint64, true},
		{"0*maxuint64", 0, math.MaxUint64, 0, true},
		{"maxuint64*0", math.MaxUint64, 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := safeio.MulU64(tt.a, tt.b)
			if ok != tt.wantOK {
				t.Fatalf("MulU64(%d, %d): ok=%v want %v", tt.a, tt.b, ok, tt.wantOK)
			}
			if ok && got != tt.wantP {
				t.Fatalf("MulU64(%d, %d): product=%d want %d", tt.a, tt.b, got, tt.wantP)
			}
		})
	}
}

// ─── NewReader panics on maxAlloc<=0 ─────────────────────────────────────────

func TestNewReader_zeroMaxAllocPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for maxAlloc=0")
		}
	}()
	safeio.NewReader(bytes.NewReader([]byte{1}), 1, 0)
}

func TestNewReader_negativeMaxAllocPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for maxAlloc=-1")
		}
	}()
	safeio.NewReader(bytes.NewReader([]byte{1}), 1, -1)
}

// ─── Size() accessor ─────────────────────────────────────────────────────────

func TestReader_Size(t *testing.T) {
	data := make([]byte, 42)
	r := safeio.NewReader(bytes.NewReader(data), 42, 256<<20)
	if r.Size() != 42 {
		t.Fatalf("Size() = %d, want 42", r.Size())
	}
}

// ─── U32/U64 at valid offsets near end ───────────────────────────────────────

func TestU32_atLastPosition(t *testing.T) {
	// 4 bytes at offset 0 in a 4-byte file = valid.
	data := []byte{0x01, 0x00, 0x00, 0x00}
	r := safeio.NewReader(bytes.NewReader(data), 4, 256<<20)
	v, err := r.U32(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 1 {
		t.Fatalf("got %d, want 1", v)
	}
}

func TestU64_atLastPosition(t *testing.T) {
	data := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	r := safeio.NewReader(bytes.NewReader(data), 8, 256<<20)
	v, err := r.U64(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 8 {
		t.Fatalf("got %d, want 8", v)
	}
}
