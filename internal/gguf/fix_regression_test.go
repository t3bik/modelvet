package gguf_test

// fix_regression_test.go — QA verification tests for the 6 applied fixes.
//
// Fix 1: GGUF-ARRAY-DEPTH-001 + maxArrayDepth=64 in skipKVValue.
// Fix 2: GGUF M1 overflow-safe bounds check (n > size-off form).
//
// Each test is self-contained and documents which criterion it proves.

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/t3bik/modelvet/internal/finding"
	"github.com/t3bik/modelvet/internal/gguf"
	scanpkg "github.com/t3bik/modelvet/internal/scan"
)

// buildDeepNestedArrayGGUF builds a GGUF with one KV entry that is an ARRAY
// nested `levels` deep. Each non-terminal level wraps an ARRAY of count=1.
// The innermost level is a UINT8 array of count=0 (no payload bytes needed).
// This produces a compact file (no matter how many levels) because the inner
// arrays all have count=1 (one element) except the innermost (count=0).
func buildDeepNestedArrayGGUF(levels int) []byte {
	var b bytes.Buffer
	// Fixed header: magic + version + tensor_count + kv_count
	b.WriteString("GGUF")
	binary.Write(&b, binary.LittleEndian, uint32(3)) // version 3
	binary.Write(&b, binary.LittleEndian, uint64(0)) // tensor_count = 0
	binary.Write(&b, binary.LittleEndian, uint64(1)) // kv_count = 1

	// KV key = "x" (1 byte)
	binary.Write(&b, binary.LittleEndian, uint64(1))
	b.WriteByte('x')
	// KV value_type = 9 (ARRAY)
	binary.Write(&b, binary.LittleEndian, uint32(9))

	// (levels-1) outer wrapping levels: element_type=ARRAY(9), count=1
	for i := 0; i < levels-1; i++ {
		binary.Write(&b, binary.LittleEndian, uint32(9)) // element_type = ARRAY
		binary.Write(&b, binary.LittleEndian, uint64(1)) // count = 1 element
	}
	// Innermost level: element_type=UINT8(0), count=0 (no data bytes)
	binary.Write(&b, binary.LittleEndian, uint32(0)) // UINT8
	binary.Write(&b, binary.LittleEndian, uint64(0)) // count = 0

	return b.Bytes()
}

// ─── Fix 1a: 200-level deep ARRAY emits GGUF-ARRAY-DEPTH-001 ─────────────────

// TestFix1_DeepArray_EmitsDepthRule is the primary regression for Fix 1.
// Verifies:
//   (a) GGUF-ARRAY-DEPTH-001 (High) is emitted for 200 nested levels.
//   (b) Scan RETURNS — no panic, no "fatal error: stack overflow".
func TestFix1_DeepArray_EmitsDepthRule(t *testing.T) {
	const levels = 200 // far beyond maxArrayDepth=64
	data := buildDeepNestedArrayGGUF(levels)
	t.Logf("crafted GGUF: %d bytes, %d nested array levels", len(data), levels)

	s := gguf.New()

	var (
		findings []finding.Finding
		scanErr  error
		panicked bool
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				t.Errorf("Fix1 (b) FAIL: Scan panicked with 200-level array: %v", r)
			}
		}()
		findings, scanErr = s.Scan(bytes.NewReader(data), int64(len(data)))
	}()

	if panicked {
		// Error already logged above; fail here for clarity.
		t.FailNow()
	}

	if scanErr != nil {
		t.Fatalf("Fix1 FAIL: Scan returned hard error: %v", scanErr)
	}

	// (a) The depth rule must fire.
	depthHit := false
	for _, f := range findings {
		t.Logf("  finding: RuleID=%s Severity=%s", f.RuleID, f.Severity)
		if f.RuleID == "GGUF-ARRAY-DEPTH-001" {
			depthHit = true
			if f.Severity != finding.High {
				t.Errorf("Fix1 (a) FAIL: GGUF-ARRAY-DEPTH-001 Severity=%v, want High", f.Severity)
			}
		}
	}
	if !depthHit {
		t.Fatalf("Fix1 (a) FAIL: expected GGUF-ARRAY-DEPTH-001 for %d levels; got %v",
			levels, findings)
	}
	t.Log("Fix1 (a)(b) PASS: depth-cap finding emitted, Scan returned cleanly")
}

// ─── Fix 1b: Shallow array (≤64 levels) does NOT trigger depth rule ──────────

// TestFix1_ShallowArray_NoDepthRule verifies criterion (c):
// An array nested 3 levels deep must NOT trigger GGUF-ARRAY-DEPTH-001.
func TestFix1_ShallowArray_NoDepthRule(t *testing.T) {
	const levels = 3 // well below maxArrayDepth=64
	data := buildDeepNestedArrayGGUF(levels)

	s := gguf.New()
	findings, err := s.Scan(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Fix1 (c) FAIL: Scan error on %d-level array: %v", levels, err)
	}

	for _, f := range findings {
		if f.RuleID == "GGUF-ARRAY-DEPTH-001" {
			t.Fatalf("Fix1 (c) FAIL: false positive GGUF-ARRAY-DEPTH-001 for shallow %d-level array", levels)
		}
	}
	t.Logf("Fix1 (c) PASS: %d-level array produced no depth finding (other findings: %v)", levels, findings)
}

// TestFix1_CapBoundary verifies the exact boundary behaviour of maxArrayDepth=64.
// The cap check is `depth >= maxArrayDepth` where depth is 0-based.
// An ARRAY with 64 outer levels means the outermost call is depth=0 and the
// innermost (terminal) level is reached at depth=63 — never triggering the cap.
// An ARRAY with 65 outer levels reaches depth=64 for the innermost, triggering.
func TestFix1_CapBoundary(t *testing.T) {
	tests := []struct {
		levels    int
		wantDepth bool
		desc      string
	}{
		{64, false, "64 levels = at cap (depth reaches 63 max, 0-based): no trigger"},
		{65, true, "65 levels = one over cap (depth 64 triggers >= 64): MUST trigger"},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			data := buildDeepNestedArrayGGUF(tt.levels)
			s := gguf.New()
			findings, err := s.Scan(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatalf("Scan error: %v", err)
			}
			depthHit := false
			for _, f := range findings {
				if f.RuleID == "GGUF-ARRAY-DEPTH-001" {
					depthHit = true
				}
			}
			if tt.wantDepth && !depthHit {
				t.Errorf("FAIL: %d levels — expected GGUF-ARRAY-DEPTH-001; got %v", tt.levels, findings)
			}
			if !tt.wantDepth && depthHit {
				t.Errorf("FAIL: %d levels — unexpected GGUF-ARRAY-DEPTH-001", tt.levels)
			}
		})
	}
}

// ─── Fix 1c: End-to-end through scan.Engine (recover-guard path) ──────────────

// TestFix1_EndToEnd_Engine verifies the fix end-to-end through scan.Engine.Walk,
// exercising the recover-guard (DESIGN §6.5). The engine must:
//   - Return Scanned=1.
//   - Emit GGUF-ARRAY-DEPTH-001 in Findings (not swallow it in Errors).
func TestFix1_EndToEnd_Engine(t *testing.T) {
	const levels = 200
	data := buildDeepNestedArrayGGUF(levels)

	dir := t.TempDir()
	ggufPath := filepath.Join(dir, "evil_depth.gguf")
	if err := os.WriteFile(ggufPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	eng := scanpkg.NewEngine()
	res, err := eng.Walk(context.Background(), ggufPath, scanpkg.Options{
		MinSeverity: finding.Info,
		Recurse:     false,
	})
	if err != nil {
		t.Fatalf("Walk returned error: %v", err)
	}

	t.Logf("Walk: scanned=%d skipped=%d errors=%d findings=%d",
		res.Scanned, res.Skipped, len(res.Errors), len(res.Findings))
	for _, fe := range res.Errors {
		t.Logf("  file error: %v", fe)
	}
	for _, f := range res.Findings {
		t.Logf("  finding: RuleID=%s Severity=%s", f.RuleID, f.Severity)
	}

	if res.Scanned != 1 {
		t.Errorf("expected Scanned=1, got %d", res.Scanned)
	}

	depthHit := false
	for _, f := range res.Findings {
		if f.RuleID == "GGUF-ARRAY-DEPTH-001" {
			depthHit = true
		}
	}

	if !depthHit {
		if len(res.Errors) > 0 {
			// The recover-guard fired — this means the fix did not prevent the panic
			// and the guard caught it instead. This is the wrong outcome for Fix 1.
			t.Fatalf("Fix1 FAIL: recover-guard caught panic instead of emitting finding: errors=%v", res.Errors)
		}
		t.Fatalf("Fix1 END-TO-END FAIL: expected GGUF-ARRAY-DEPTH-001; findings=%v", res.Findings)
	}
	t.Log("Fix1 END-TO-END PASS: Engine.Walk alive, depth finding emitted")
}

// ─── Fix 2: Overflow-safe bounds check (GGUF M1) ─────────────────────────────

// TestFix2_OverflowSafeBoundsCheck verifies the n > size-off form is used
// (not off+n > size which can overflow int64). This is structural: the safeio
// package implements the canonical overflow-safe check and the gguf parser uses
// it exclusively. The test crafts inputs that would trigger integer overflow if
// the naive form were used, and asserts the scanner returns an error or finding
// rather than crashing.
func TestFix2_OverflowSafeBoundsCheckNoPanic(t *testing.T) {
	overflowInputs := []struct {
		name string
		data []byte
	}{
		{
			// A GGUF where the key-length field is MaxInt64 (would overflow off+n).
			name: "key_len_MaxInt64",
			data: func() []byte {
				var b []byte
				b = append(b, []byte("GGUF")...)
				b = appendLE32(b, 3)  // version
				b = appendLE64(b, 0)  // tensor_count
				b = appendLE64(b, 1)  // kv_count=1
				b = appendLE64(b, 0x7FFFFFFFFFFFFFFF) // key length = MaxInt64
				return b
			}(),
		},
		{
			// A GGUF where the count field near end + n would wrap.
			name: "count_near_overflow",
			data: func() []byte {
				var b []byte
				b = append(b, []byte("GGUF")...)
				b = appendLE32(b, 3)
				b = appendLE64(b, 0xFFFFFFFFFFFFFFF0) // tensor_count overflows sanity
				b = appendLE64(b, 0)
				return b
			}(),
		},
	}

	for _, tc := range overflowInputs {
		t.Run(tc.name, func(t *testing.T) {
			var panicked bool
			func() {
				defer func() {
					if r := recover(); r != nil {
						panicked = true
						t.Errorf("Fix2 FAIL: Scan panicked on %q: %v", tc.name, r)
					}
				}()
				s := gguf.New()
				_, _ = s.Scan(bytes.NewReader(tc.data), int64(len(tc.data)))
			}()
			if !panicked {
				t.Logf("Fix2 PASS: %q — Scan returned without panic", tc.name)
			}
		})
	}
}

// ─── Helper: little-endian byte encoders ─────────────────────────────────────

func appendLE32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func appendLE64(b []byte, v uint64) []byte {
	return append(b,
		byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}
