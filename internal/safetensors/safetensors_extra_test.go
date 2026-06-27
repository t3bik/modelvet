package safetensors_test

// safetensors_extra_test.go — QA-authored tests for safetensors scanner.
// Covers: ST-TRUNC-001, ST-META-001, ST-OFFSET-001 (OOB critical), shape
// overflow, negative shape dim, empty valid file, and exact RuleID assertions.

import (
	"encoding/binary"
	"encoding/json"
	"testing"
)

// ─── AC2: Valid safetensors produces ZERO findings ────────────────────────────

func TestAC2_ValidSafetensorsNilFindings(t *testing.T) {
	// F32 tensor [3,4] = 12 elements * 4 bytes = 48 bytes data.
	b := newST().addTensor("weight", "F32", []int64{3, 4}, 0, 48)
	ids, err := scan(b.build(48))
	if err != nil {
		t.Fatalf("valid safetensors returned error: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("false positive on valid safetensors: %v", ids)
	}
}

// ─── AC2: ST-TRUNC-001 — file shorter than 8+header_len ─────────────────────

func TestAC2_TruncatedFile_ST_TRUNC_001(t *testing.T) {
	// Construct a safetensors where header_len=20 but the file is only 15 bytes.
	// header_len(8) + body should be 28 bytes but we supply only 15.
	var buf [15]byte
	binary.LittleEndian.PutUint64(buf[:8], 20) // claims 20-byte header
	// But we only have 15 bytes total → 15 - 8 = 7 < 20 → ST-HEADERLEN-001 fires.
	// Actually: header_len(20) > size-8(7) → ST-HEADERLEN-001 (not ST-TRUNC-001).
	// ST-TRUNC-001 would fire if 8+header_len > size after passing OOB check.
	// The code checks ST-HEADERLEN-001 first, so for this case HEADERLEN-001 fires.
	ids, err := scan(buf[:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasID(ids, "ST-HEADERLEN-001") {
		t.Fatalf("expected ST-HEADERLEN-001, got %v", ids)
	}
}

// ST-TRUNC-001 requires: header_len <= size-8 (passes OOB check) but
// 8+header_len > size. This is the edge case where the overflow-safe check
// in safetensors.go differs from the OOB check.
// NOTE: Looking at the implementation, ST-HEADERLEN-001 fires for
// headerLen > size-8, and ST-TRUNC-001 would fire for int64(8)+int64(headerLen) > size.
// Since uint64(headerLen) > uint64(size)-8 is the same as 8+headerLen > size
// for non-wrapping values, these fire on the same condition in this code.
// Document this as a design note: ST-TRUNC-001 is effectively covered by
// ST-HEADERLEN-001 in the current implementation.
func TestAC2_TruncNoteDocumented(t *testing.T) {
	// Verify: file of exactly 8+headerLen bytes passes (not truncated).
	headerJSON := []byte(`{}`)
	var buf []byte
	buf = appendU64(buf, uint64(len(headerJSON)))
	buf = append(buf, headerJSON...)
	// No data segment — but header_len=2 and file=10: 8+2=10 = size → valid.
	ids, err := scan(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasID(ids, "ST-TRUNC-001") || hasID(ids, "ST-HEADERLEN-001") {
		t.Fatalf("unexpected findings on minimal valid file: %v", ids)
	}
}

// ─── AC2: ST-META-001 ─────────────────────────────────────────────────────────

func TestAC2_MetadataNonStringValue(t *testing.T) {
	// __metadata__ with a non-string value (integer) should trigger ST-META-001.
	raw := buildRawST(map[string]interface{}{
		"__metadata__": map[string]interface{}{
			"version": 42, // integer, not string
		},
	}, 0)
	ids, err := scan(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasID(ids, "ST-META-001") {
		t.Fatalf("expected ST-META-001 on non-string metadata value, got %v", ids)
	}
}

func TestAC2_MetadataNonObject(t *testing.T) {
	// __metadata__ that is not an object at all.
	raw := buildRawST(map[string]interface{}{
		"__metadata__": "not_an_object",
	}, 0)
	ids, err := scan(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasID(ids, "ST-META-001") {
		t.Fatalf("expected ST-META-001 on string metadata, got %v", ids)
	}
}

// ─── AC2: ST-OFFSET-001 — OOB read (Critical) ────────────────────────────────

func TestAC2_Offset001OOB(t *testing.T) {
	// Tensor end beyond data segment.
	b := newST().addTensor("w", "F32", []int64{10}, 0, 99999)
	ids, err := scan(b.build(16))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasID(ids, "ST-OFFSET-001") {
		t.Fatalf("expected ST-OFFSET-001, got %v", ids)
	}
}

// ─── AC2: ST-SHAPE-001 — negative dimension ──────────────────────────────────

func TestAC2_ShapeNegativeDimension(t *testing.T) {
	// shape contains -1 → ST-SHAPE-001.
	b := newST().addTensor("w", "F32", []int64{-1, 4}, 0, 16)
	ids, err := scan(b.build(16))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasID(ids, "ST-SHAPE-001") {
		t.Fatalf("expected ST-SHAPE-001 on negative dim, got %v", ids)
	}
}

// ─── AC2: ST-SHAPE-001 — shape product overflow ──────────────────────────────

func TestAC2_ShapeProductOverflow(t *testing.T) {
	// shape [1<<32, 1<<32] product overflows int64 → ST-SHAPE-001.
	b := newST().addTensor("w", "F32", []int64{1 << 32, 1 << 32}, 0, 16)
	ids, err := scan(b.build(16))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasID(ids, "ST-SHAPE-001") {
		t.Fatalf("expected ST-SHAPE-001 on overflow shape, got %v", ids)
	}
}

// ─── AC2: ST-DTYPE-001 various unknown dtypes ────────────────────────────────

func TestAC2_UnknownDtypeVariants(t *testing.T) {
	for _, dtype := range []string{"FLOAT32", "int8", "COMPLEX64", "UNDEFINED", ""} {
		t.Run("dtype="+dtype, func(t *testing.T) {
			b := newST().addTensor("w", dtype, []int64{4}, 0, 16)
			ids, err := scan(b.build(16))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !hasID(ids, "ST-DTYPE-001") {
				t.Fatalf("expected ST-DTYPE-001 for dtype=%q, got %v", dtype, ids)
			}
		})
	}
}

// ─── AC2: known dtypes produce no ST-DTYPE-001 ───────────────────────────────

func TestAC2_KnownDtypesNoFalsePositive(t *testing.T) {
	dtypeSizes := map[string]int64{
		"F64": 8, "F32": 4, "F16": 2, "BF16": 2,
		"I64": 8, "I32": 4, "I16": 2, "I8": 1, "U8": 1, "BOOL": 1,
	}
	for dtype, sz := range dtypeSizes {
		t.Run("dtype="+dtype, func(t *testing.T) {
			span := 4 * sz // 4-element tensor
			b := newST().addTensor("w", dtype, []int64{4}, 0, span)
			ids, err := scan(b.build(span))
			if err != nil {
				t.Fatalf("unexpected error for dtype=%s: %v", dtype, err)
			}
			if hasID(ids, "ST-DTYPE-001") {
				t.Errorf("false positive ST-DTYPE-001 for known dtype %s", dtype)
			}
		})
	}
}

// ─── AC2: ST-OFFSET-002 negative begin ───────────────────────────────────────

func TestAC2_NegativeBeginOffset(t *testing.T) {
	// JSON: begin = -5 (negative).
	raw := buildRawST(map[string]interface{}{
		"w": map[string]interface{}{
			"dtype":        "F32",
			"shape":        []int64{4},
			"data_offsets": []int64{-5, 16},
		},
	}, 32)
	ids, err := scan(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasID(ids, "ST-OFFSET-002") {
		t.Fatalf("expected ST-OFFSET-002 on negative begin, got %v", ids)
	}
}

// ─── AC2: Empty valid file (no tensors) ──────────────────────────────────────

func TestAC2_EmptyValidFile(t *testing.T) {
	b := newST()
	ids, err := scan(b.build(0))
	if err != nil {
		t.Fatalf("unexpected error on empty valid safetensors: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("unexpected findings on empty safetensors: %v", ids)
	}
}

// ─── helper ──────────────────────────────────────────────────────────────────

// buildRawST builds a safetensors file from an arbitrary header map.
func buildRawST(hdr map[string]interface{}, dataSize int64) []byte {
	headerBytes, err := json.Marshal(hdr)
	if err != nil {
		panic(err)
	}
	var buf []byte
	buf = appendU64(buf, uint64(len(headerBytes)))
	buf = append(buf, headerBytes...)
	buf = append(buf, make([]byte, dataSize)...)
	return buf
}
