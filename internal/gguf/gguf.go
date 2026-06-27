// Package gguf implements a static security scanner for GGUF model artifacts.
// It inspects file bytes without executing or loading the model.
package gguf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/t3bik/modelvet/internal/finding"
	"github.com/t3bik/modelvet/internal/safeio"
)

const (
	// ggufMagic is the first 4 bytes of every GGUF file.
	ggufMagic = "GGUF"

	// ggmlMaxDims is llama.cpp's GGML_MAX_DIMS constant.
	ggmlMaxDims = 8

	// maxStringLen is the threshold above which a string is flagged as
	// implausibly large (DoS signal) even if within file bounds (64 MiB).
	maxStringLen = 64 << 20

	// maxAllocBytes caps any single read/allocation through safeio.
	maxAllocBytes = 256 << 20

	// headerCap is the tensor-data alignment in GGUF v3 (32 bytes).
	// Tensor offsets are relative to the start of tensor data, which begins
	// after the header is aligned up to this boundary.
	ggufAlignment = 32
)

// Scanner implements scan.Scanner for GGUF files.
type Scanner struct{}

// New returns a new GGUF Scanner.
func New() *Scanner { return &Scanner{} }

// Format returns the format this scanner handles.
func (s *Scanner) Format() finding.Format { return finding.FormatGGUF }

// Scan inspects the GGUF artifact at ra (size bytes) and returns all findings.
// Detected risks are Findings; an error means the file cannot be parsed at all.
func (s *Scanner) Scan(ra io.ReaderAt, size int64) ([]finding.Finding, error) {
	if size < 8 {
		return nil, fmt.Errorf("gguf: file too small (%d bytes)", size)
	}

	r := safeio.NewReader(ra, size, maxAllocBytes)
	var findings []finding.Finding

	// ── 1. Magic ──────────────────────────────────────────────────────────────
	magicBuf, err := r.Bytes(0, 4)
	if err != nil {
		return nil, fmt.Errorf("gguf: read magic: %w", err)
	}
	if string(magicBuf) != ggufMagic {
		findings = append(findings, finding.New("GGUF-MAGIC-001", 0,
			fmt.Sprintf("magic bytes are %q, expected %q", magicBuf, ggufMagic)))
		// Cannot trust the rest of the file structure; return early.
		return findings, nil
	}

	// ── 2. Version ────────────────────────────────────────────────────────────
	version, err := r.U32(4)
	if err != nil {
		return nil, fmt.Errorf("gguf: read version: %w", err)
	}
	if version < 1 || version > 3 {
		findings = append(findings, finding.New("GGUF-VERSION-001", 4,
			fmt.Sprintf("version=%d (expected 1, 2, or 3)", version)))
	}

	// ── 3. Counts ─────────────────────────────────────────────────────────────
	if size < 24 {
		findings = append(findings, finding.New("GGUF-TRUNC-001", 8,
			"file too short to contain tensor_count and metadata_kv_count"))
		return findings, nil
	}

	tensorCount, err := r.U64(8)
	if err != nil {
		return nil, fmt.Errorf("gguf: read tensor_count: %w", err)
	}
	kvCount, err := r.U64(16)
	if err != nil {
		return nil, fmt.Errorf("gguf: read kv_count: %w", err)
	}

	// Sanity: minimum bytes per KV or tensor is ~9 (8-byte key len + 1 byte).
	// Use 9 as minimum cost to detect absurd counts quickly.
	const minBytesPerEntry = 9
	if kvCount > uint64(size)/minBytesPerEntry {
		findings = append(findings, finding.New("GGUF-COUNT-001", 16,
			fmt.Sprintf("metadata_kv_count=%d cannot fit in %d-byte file", kvCount, size)))
		// Cannot safely iterate; stop here.
		return findings, nil
	}
	if tensorCount > uint64(size)/minBytesPerEntry {
		findings = append(findings, finding.New("GGUF-COUNT-001", 8,
			fmt.Sprintf("tensor_count=%d cannot fit in %d-byte file", tensorCount, size)))
		return findings, nil
	}

	// ── 4. Metadata KV entries ────────────────────────────────────────────────
	off := int64(24) // cursor after the 24-byte fixed header
	seenKeys := make(map[string]bool, kvCount)

	for i := uint64(0); i < kvCount; i++ {
		// Read key length + key string.
		keyLen, newOff, err := readStringLen(r, off)
		if err != nil {
			findings = append(findings, finding.New("GGUF-TRUNC-001", off,
				fmt.Sprintf("kv[%d]: truncated reading key length: %v", i, err)))
			return findings, nil
		}
		keyStr, newOff2, kErr := readString(r, newOff, keyLen, size, i, "key")
		if kErr != nil {
			if kErr == errOOB {
				findings = append(findings, finding.New("GGUF-STRLEN-001", newOff,
					fmt.Sprintf("kv[%d]: key length %d exceeds remaining file", i, keyLen)))
				return findings, nil
			}
			if kErr == errHuge {
				findings = append(findings, finding.New("GGUF-STRLEN-002", newOff,
					fmt.Sprintf("kv[%d]: key length %d is implausibly large (>64 MiB)", i, keyLen)))
				return findings, nil
			}
			findings = append(findings, finding.New("GGUF-TRUNC-001", newOff,
				fmt.Sprintf("kv[%d]: cannot read key: %v", i, kErr)))
			return findings, nil
		}
		off = newOff2

		if seenKeys[keyStr] {
			findings = append(findings, finding.New("GGUF-KV-DUP-001", off,
				fmt.Sprintf("duplicate metadata key %q", keyStr)))
		}
		seenKeys[keyStr] = true

		// Read value type.
		if off < 0 || 4 > size-off {
			findings = append(findings, finding.New("GGUF-TRUNC-001", off,
				fmt.Sprintf("kv[%d]: truncated reading value type", i)))
			return findings, nil
		}
		var typeBuf [4]byte
		if err := r.ReadAt(typeBuf[:], off); err != nil {
			return nil, fmt.Errorf("gguf: kv[%d] value type: %w", i, err)
		}
		kvType := binary.LittleEndian.Uint32(typeBuf[:])
		off += 4

		if !validKVType(kvType) {
			findings = append(findings, finding.New("GGUF-KV-TYPE-001", off-4,
				fmt.Sprintf("kv[%d] key=%q: value_type=%d is outside valid ggml_metadata_value_type enum (0–12)", i, keyStr, kvType)))
			// Cannot advance cursor safely past an unknown value type; stop.
			return findings, nil
		}

		// Skip over the value payload to advance the cursor.
		newOff3, skipErr := skipKVValue(r, off, kvType, size, i, 0)
		if skipErr != nil {
			if errors.Is(skipErr, errArrayDepth) {
				findings = append(findings, finding.New("GGUF-ARRAY-DEPTH-001", off,
					fmt.Sprintf("kv[%d] key=%q: metadata array nested beyond max depth (%d)", i, keyStr, maxArrayDepth)))
				return findings, nil
			}
			findings = append(findings, finding.New("GGUF-TRUNC-001", off,
				fmt.Sprintf("kv[%d]: truncated reading value (type=%d): %v", i, kvType, skipErr)))
			return findings, nil
		}
		off = newOff3
	}

	// ── 5. Tensor info entries ────────────────────────────────────────────────
	// Align tensor data start (GGUF v3 pads to 32-byte alignment).
	// The tensor offsets in the file are relative to the START of tensor data,
	// which is the next multiple of `ggufAlignment` after the header.
	// We compute that so we can do GGUF-OFFSET-001 checks.
	headerEnd := off
	tensorDataStart := align(headerEnd, ggufAlignment)

	type tensorRegion struct {
		name   string
		begin  uint64
		end    uint64 // exclusive
	}
	regions := make([]tensorRegion, 0, tensorCount)

	for i := uint64(0); i < tensorCount; i++ {
		// Name
		tNameLen, newOff, err := readStringLen(r, off)
		if err != nil {
			findings = append(findings, finding.New("GGUF-TRUNC-001", off,
				fmt.Sprintf("tensor[%d]: truncated reading name length", i)))
			return findings, nil
		}
		tName, newOff2, nErr := readString(r, newOff, tNameLen, size, i, "tensor name")
		if nErr != nil {
			findings = append(findings, finding.New("GGUF-TRUNC-001", newOff,
				fmt.Sprintf("tensor[%d]: truncated reading name", i)))
			return findings, nil
		}
		off = newOff2

		// n_dims
		if off < 0 || 4 > size-off {
			findings = append(findings, finding.New("GGUF-TRUNC-001", off,
				fmt.Sprintf("tensor[%d]: truncated reading n_dims", i)))
			return findings, nil
		}
		nDimsRaw, err := r.U32(off)
		if err != nil {
			return nil, fmt.Errorf("gguf: tensor[%d] n_dims: %w", i, err)
		}
		off += 4

		if nDimsRaw > ggmlMaxDims {
			findings = append(findings, finding.New("GGUF-NDIMS-001", off-4,
				fmt.Sprintf("tensor[%d] %q: n_dims=%d exceeds GGML_MAX_DIMS=%d", i, tName, nDimsRaw, ggmlMaxDims)))
			// Skip dims we cannot trust, continue to stay somewhat in sync.
			// We cannot advance reliably, so stop.
			return findings, nil
		}
		nDims := int64(nDimsRaw)

		// dims[n_dims]
		dimsOff := off
		if off < 0 || nDims*8 > size-off {
			findings = append(findings, finding.New("GGUF-TRUNC-001", off,
				fmt.Sprintf("tensor[%d]: truncated dims array", i)))
			return findings, nil
		}
		var dimsProduct uint64 = 1
		overflow := false
		for d := int64(0); d < nDims; d++ {
			dim, err := r.U64(dimsOff + d*8)
			if err != nil {
				return nil, fmt.Errorf("gguf: tensor[%d] dim[%d]: %w", i, d, err)
			}
			p, ok := safeio.MulU64(dimsProduct, dim)
			if !ok {
				overflow = true
				break
			}
			dimsProduct = p
		}
		off += nDims * 8

		if overflow {
			findings = append(findings, finding.New("GGUF-DIMOVF-001", dimsOff,
				fmt.Sprintf("tensor[%d] %q: product of dims overflows uint64", i, tName)))
			// Cannot compute tensor size; skip the rest of this tensor.
			// We still need to read ggml_type + offset to stay in sync.
		}

		// ggml_type
		if off < 0 || 4 > size-off {
			findings = append(findings, finding.New("GGUF-TRUNC-001", off,
				fmt.Sprintf("tensor[%d]: truncated reading ggml_type", i)))
			return findings, nil
		}
		ttype, err := r.U32(off)
		if err != nil {
			return nil, fmt.Errorf("gguf: tensor[%d] ggml_type: %w", i, err)
		}
		off += 4
		if !validGGMLType(ttype) {
			findings = append(findings, finding.New("GGUF-TTYPE-001", off-4,
				fmt.Sprintf("tensor[%d] %q: ggml_type=%d unknown", i, tName, ttype)))
		}

		// offset
		if off < 0 || 8 > size-off {
			findings = append(findings, finding.New("GGUF-TRUNC-001", off,
				fmt.Sprintf("tensor[%d]: truncated reading offset", i)))
			return findings, nil
		}
		tensorOff, err := r.U64(off)
		if err != nil {
			return nil, fmt.Errorf("gguf: tensor[%d] offset: %w", i, err)
		}
		off += 8

		if !overflow {
			bytesPerBlock, elemsPerBlock := ggmlTypeBlockBytes(ttype)
			if bytesPerBlock > 0 && elemsPerBlock > 0 {
				// Compute number of blocks (ceiling division).
				numBlocks := (dimsProduct + elemsPerBlock - 1) / elemsPerBlock
				tensorBytes, ok := safeio.MulU64(numBlocks, bytesPerBlock)
				if !ok {
					findings = append(findings, finding.New("GGUF-DIMOVF-001", dimsOff,
						fmt.Sprintf("tensor[%d] %q: tensor byte size overflows uint64", i, tName)))
				} else {
					// tensorOff is relative to tensorDataStart.
					absBegin := tensorDataStart + int64(tensorOff) //nolint:gosec // G115: tensorOff is uint64 from file
					absEnd := absBegin + int64(tensorBytes)        //nolint:gosec // G115: checked tensorBytes bounds above

					// Overflow-safe check: absEnd > size
					if absBegin < 0 || int64(tensorOff) > size-tensorDataStart || //nolint:gosec // G115: checked bounds
						tensorBytes > uint64(size)-uint64(absBegin) {
						findings = append(findings, finding.New("GGUF-OFFSET-001", off-8,
							fmt.Sprintf("tensor[%d] %q: offset=%d + size=%d extends beyond file (filesize=%d)",
								i, tName, tensorOff, tensorBytes, size)))
					} else {
						regions = append(regions, tensorRegion{
							name:  tName,
							begin: uint64(absBegin), //nolint:gosec // G115: absBegin >= 0 checked above
							end:   uint64(absEnd),   //nolint:gosec // G115: absEnd >= absBegin from addition
						})
					}
				}
			}
		}
	}

	// ── 6. Tensor overlap check ───────────────────────────────────────────────
	for i := 0; i < len(regions); i++ {
		for j := i + 1; j < len(regions); j++ {
			a, b := regions[i], regions[j]
			if a.begin < b.end && b.begin < a.end {
				findings = append(findings, finding.New("GGUF-OFFSET-002", -1,
					fmt.Sprintf("tensors %q and %q have overlapping byte ranges", a.name, b.name)))
			}
		}
	}

	return findings, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

var (
	errOOB        = errors.New("out of bounds")
	errHuge       = errors.New("implausibly large")
	errArrayDepth = errors.New("array nesting depth exceeded")
)

// readStringLen reads the 8-byte little-endian length prefix at off and
// returns (length, nextOff, error).
func readStringLen(r *safeio.Reader, off int64) (uint64, int64, error) {
	v, err := r.U64(off)
	if err != nil {
		return 0, off, err
	}
	return v, off + 8, nil
}

// readString reads keyLen bytes at off, with OOB and huge-string guards.
// Returns the string, the new offset, and a sentinel error (errOOB / errHuge)
// or a wrapped I/O error.
func readString(r *safeio.Reader, off int64, length uint64, size int64, idx uint64, kind string) (string, int64, error) {
	if length > uint64(size) || int64(length) > size-off { //nolint:gosec // G115: overflow-safe; length > uint64(size) guards
		return "", off, errOOB
	}
	if length > maxStringLen {
		return "", off, errHuge
	}
	buf, err := r.Bytes(off, int64(length))
	if err != nil {
		return "", off, fmt.Errorf("%s[%d]: read string: %w", kind, idx, err)
	}
	return string(buf), off + int64(length), nil
}

// maxArrayDepth is the maximum nesting depth for ARRAY-of-ARRAY KV values.
// Real GGUF arrays are never deeply nested; a low cap prevents stack exhaustion
// from crafted inputs with millions of recursive ARRAY element types.
const maxArrayDepth = 64

// skipKVValue advances the cursor past a KV value of the given type.
// depth tracks the current ARRAY nesting level; returns an error if exceeded.
// Returns the new offset or an error.
func skipKVValue(r *safeio.Reader, off int64, kvType uint32, size int64, idx uint64, depth int) (int64, error) {
	switch kvType {
	case 0: // UINT8
		if off > size || 1 > size-off {
			return off, errOOB
		}
		return off + 1, nil
	case 1: // INT8
		if off > size || 1 > size-off {
			return off, errOOB
		}
		return off + 1, nil
	case 2: // UINT16
		if off > size || 2 > size-off {
			return off, errOOB
		}
		return off + 2, nil
	case 3: // INT16
		if off > size || 2 > size-off {
			return off, errOOB
		}
		return off + 2, nil
	case 4: // UINT32
		if off > size || 4 > size-off {
			return off, errOOB
		}
		return off + 4, nil
	case 5: // INT32
		if off > size || 4 > size-off {
			return off, errOOB
		}
		return off + 4, nil
	case 6: // FLOAT32
		if off > size || 4 > size-off {
			return off, errOOB
		}
		return off + 4, nil
	case 7: // BOOL
		if off > size || 1 > size-off {
			return off, errOOB
		}
		return off + 1, nil
	case 8: // STRING
		slen, newOff, err := readStringLen(r, off)
		if err != nil {
			return off, err
		}
		//nolint:gosec // G115: overflow-safe check; slen > uint64(size) guards against overflow
		if slen > uint64(size) || int64(slen) > size-newOff { //nolint:gosec // G115: overflow-safe check
			return newOff, errOOB
		}
		return newOff + int64(slen), nil //nolint:gosec // G115: checked slen bounds above
	case 9: // ARRAY
		if depth >= maxArrayDepth {
			return off, errArrayDepth
		}
		// array: element_type u32, count u64, then count elements of element_type
		if off > size || 12 > size-off {
			return off, fmt.Errorf("truncated array header")
		}
		elemType, err := r.U32(off)
		if err != nil {
			return off, err
		}
		count, err := r.U64(off + 4)
		if err != nil {
			return off, err
		}
		off += 12
		if !validKVType(elemType) {
			return off, fmt.Errorf("unknown array element type %d", elemType)
		}
		// Guard: 1 byte minimum per element to prevent huge loops.
		const minElemBytes = 1
		if count > uint64(size)/minElemBytes { //nolint:gosec // G115: dividing uint64 values
			return off, fmt.Errorf("array count %d cannot fit in file", count)
		}
		for i := uint64(0); i < count; i++ {
			var aerr error
			off, aerr = skipKVValue(r, off, elemType, size, idx, depth+1)
			if aerr != nil {
				return off, fmt.Errorf("array[%d]: %w", i, aerr)
			}
		}
		return off, nil
	case 10: // UINT64
		if off > size || 8 > size-off {
			return off, errOOB
		}
		return off + 8, nil
	case 11: // INT64
		if off > size || 8 > size-off {
			return off, errOOB
		}
		return off + 8, nil
	case 12: // FLOAT64
		if off > size || 8 > size-off {
			return off, errOOB
		}
		return off + 8, nil
	default:
		return off, fmt.Errorf("unknown KV type %d", kvType)
	}
}

// align rounds n up to the nearest multiple of a.
func align(n, a int64) int64 {
	if a == 0 {
		return n
	}
	return ((n + a - 1) / a) * a
}
