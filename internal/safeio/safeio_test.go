package safeio_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/t3bik/modelvet/internal/safeio"
)

func newReader(data []byte) *safeio.Reader {
	return safeio.NewReader(bytes.NewReader(data), int64(len(data)), 256<<20)
}

func TestReadAt_exact(t *testing.T) {
	r := newReader([]byte{1, 2, 3, 4, 5})
	buf := make([]byte, 3)
	if err := r.ReadAt(buf, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf[0] != 2 || buf[1] != 3 || buf[2] != 4 {
		t.Fatalf("wrong bytes: %v", buf)
	}
}

func TestReadAt_outOfBounds(t *testing.T) {
	r := newReader([]byte{1, 2, 3})
	buf := make([]byte, 2)
	if err := r.ReadAt(buf, 2); !errors.Is(err, safeio.ErrOutOfBounds) {
		t.Fatalf("expected ErrOutOfBounds, got %v", err)
	}
}

func TestBytes_normal(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	r := newReader(data)
	b, err := r.Bytes(0, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, data) {
		t.Fatalf("mismatch: %v", b)
	}
}

func TestBytes_negativeN(t *testing.T) {
	r := newReader([]byte{1, 2, 3})
	_, err := r.Bytes(0, -1)
	if !errors.Is(err, safeio.ErrNegativeLength) {
		t.Fatalf("expected ErrNegativeLength, got %v", err)
	}
}

func TestBytes_allocTooLarge(t *testing.T) {
	r := safeio.NewReader(bytes.NewReader(make([]byte, 10)), 10, 5)
	_, err := r.Bytes(0, 6)
	if !errors.Is(err, safeio.ErrAllocTooLarge) {
		t.Fatalf("expected ErrAllocTooLarge, got %v", err)
	}
}

func TestBytes_overflowSafe(t *testing.T) {
	// off near MaxInt64 + small n would overflow off+n; our check must catch it.
	r := safeio.NewReader(bytes.NewReader(make([]byte, 8)), 8, 256<<20)
	_, err := r.Bytes(7, 2) // 7+2=9 > 8 → out of bounds
	if !errors.Is(err, safeio.ErrOutOfBounds) {
		t.Fatalf("expected ErrOutOfBounds, got %v", err)
	}
}

func TestBytes_zeroLen(t *testing.T) {
	r := newReader([]byte{1, 2, 3})
	b, err := r.Bytes(0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) != 0 {
		t.Fatalf("expected empty slice")
	}
}

func TestU32(t *testing.T) {
	// 0x01020304 in LE = bytes 04 03 02 01
	data := []byte{0x04, 0x03, 0x02, 0x01}
	r := newReader(data)
	v, err := r.U32(0)
	if err != nil {
		t.Fatal(err)
	}
	if v != 0x01020304 {
		t.Fatalf("got 0x%X", v)
	}
}

func TestU32_atEOF(t *testing.T) {
	r := newReader([]byte{1, 2, 3}) // only 3 bytes, need 4
	_, err := r.U32(0)
	if !errors.Is(err, safeio.ErrOutOfBounds) {
		t.Fatalf("expected ErrOutOfBounds, got %v", err)
	}
}

func TestU64(t *testing.T) {
	// 0x0102030405060708 LE
	data := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	r := newReader(data)
	v, err := r.U64(0)
	if err != nil {
		t.Fatal(err)
	}
	if v != 0x0102030405060708 {
		t.Fatalf("got 0x%X", v)
	}
}

func TestU64_atEOF(t *testing.T) {
	r := newReader(make([]byte, 7)) // only 7, need 8
	_, err := r.U64(0)
	if !errors.Is(err, safeio.ErrOutOfBounds) {
		t.Fatalf("expected ErrOutOfBounds, got %v", err)
	}
}

func TestMulU64_normal(t *testing.T) {
	p, ok := safeio.MulU64(3, 7)
	if !ok || p != 21 {
		t.Fatalf("got %d, ok=%v", p, ok)
	}
}

func TestMulU64_overflow(t *testing.T) {
	_, ok := safeio.MulU64(1<<32, 1<<32)
	if ok {
		t.Fatal("expected overflow")
	}
}

func TestMulU64_zero(t *testing.T) {
	p, ok := safeio.MulU64(0, 999)
	if !ok || p != 0 {
		t.Fatalf("got %d, ok=%v", p, ok)
	}
}
