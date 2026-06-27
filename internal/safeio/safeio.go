// Package safeio provides bounded-read helpers over io.ReaderAt.
// Every read validates bounds against the known file size and a per-Reader
// allocation cap BEFORE any allocation, enforcing the project's core safety
// property: never trust a length field before validating it.
package safeio

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Sentinel errors returned by Reader methods.
var (
	ErrOutOfBounds    = errors.New("safeio: read out of bounds")
	ErrNegativeLength = errors.New("safeio: negative length")
	ErrAllocTooLarge  = errors.New("safeio: allocation exceeds cap")
	ErrTruncated      = errors.New("safeio: unexpected end of data")
)

// Reader wraps an io.ReaderAt with a known total Size and a hard cap on any
// single allocation. Every read is bounds-checked against Size; every
// allocation is checked against maxAlloc BEFORE it happens.
type Reader struct {
	ra       io.ReaderAt
	size     int64
	maxAlloc int64
}

// NewReader creates a Reader. maxAlloc is the largest single []byte that will
// ever be allocated through this reader (e.g. 256 MiB). Panics if maxAlloc <= 0.
func NewReader(ra io.ReaderAt, size int64, maxAlloc int64) *Reader {
	if maxAlloc <= 0 {
		panic("safeio.NewReader: maxAlloc must be positive")
	}
	return &Reader{ra: ra, size: size, maxAlloc: maxAlloc}
}

// Size returns the total file size.
func (r *Reader) Size() int64 { return r.size }

// ReadAt reads exactly len(p) bytes at off. Returns an error if [off,off+len(p))
// is not fully within [0,Size). Never short-reads silently.
func (r *Reader) ReadAt(p []byte, off int64) error {
	n := int64(len(p))
	if err := r.checkBounds(off, n); err != nil {
		return err
	}
	got, err := r.ra.ReadAt(p, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("safeio: read at %d: %w", off, err)
	}
	if int64(got) < n {
		return ErrTruncated
	}
	return nil
}

// Bytes allocates and returns n bytes at off.
// Guards (in order):
//   - n < 0           → ErrNegativeLength
//   - n > maxAlloc    → ErrAllocTooLarge  (refuse BEFORE alloc)
//   - bounds check    → ErrOutOfBounds    (overflow-safe)
func (r *Reader) Bytes(off, n int64) ([]byte, error) {
	if n < 0 {
		return nil, ErrNegativeLength
	}
	if n > r.maxAlloc {
		return nil, fmt.Errorf("%w: requested %d, cap %d", ErrAllocTooLarge, n, r.maxAlloc)
	}
	if err := r.checkBounds(off, n); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	if err := r.ReadAt(buf, off); err != nil {
		return nil, err
	}
	return buf, nil
}

// U32 reads a little-endian uint32 at off.
func (r *Reader) U32(off int64) (uint32, error) {
	var buf [4]byte
	if err := r.ReadAt(buf[:], off); err != nil {
		return 0, fmt.Errorf("safeio: U32 at %d: %w", off, err)
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

// U64 reads a little-endian uint64 at off.
func (r *Reader) U64(off int64) (uint64, error) {
	var buf [8]byte
	if err := r.ReadAt(buf[:], off); err != nil {
		return 0, fmt.Errorf("safeio: U64 at %d: %w", off, err)
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

// checkBounds performs the overflow-safe bounds check.
// Never writes off+n (could overflow int64); instead checks n > size-off.
// Precondition: n >= 0 is assumed (callers have already checked).
func (r *Reader) checkBounds(off, n int64) error {
	if off < 0 || n < 0 || off > r.size || n > r.size-off {
		return fmt.Errorf("%w: off=%d n=%d size=%d", ErrOutOfBounds, off, n, r.size)
	}
	return nil
}

// MulU64 multiplies a and b, returning (product, ok). ok is false if the
// multiplication would overflow uint64. Callers use this for dim/shape
// products; on overflow they emit the appropriate finding.
func MulU64(a, b uint64) (uint64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	p := a * b
	if p/a != b {
		return 0, false
	}
	return p, true
}
