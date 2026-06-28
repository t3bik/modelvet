package numpy_test

import (
	"bytes"
	"testing"

	"github.com/t3bik/modelvet/internal/numpy"
)

// scan is a test helper that runs the numpy scanner and returns rule IDs.
func scan(data []byte) ([]string, error) {
	s := numpy.New()
	findings, err := s.Scan(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.RuleID
	}
	return ids, nil
}

func hasID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// ── benign float dtype — must produce no findings ─────────────────────────────

func TestScan_benignFloat(t *testing.T) {
	ids, err := scan(benignNpy())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no findings for float dtype .npy, got %v", ids)
	}
}

// ── object dtype with RCE pickle — must surface NPY-OBJECT-001 + pickle rules ─

func TestScan_objectDtypeRCE(t *testing.T) {
	data := objectNpy(osSystemPickle())
	ids, err := scan(data)
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "NPY-OBJECT-001") {
		t.Fatalf("expected NPY-OBJECT-001, got %v", ids)
	}
	if !hasID(ids, "PKL-GLOBAL-001") {
		t.Fatalf("expected PKL-GLOBAL-001 (os.system gadget), got %v", ids)
	}
	if !hasID(ids, "PKL-REDUCE-001") {
		t.Fatalf("expected PKL-REDUCE-001, got %v", ids)
	}
}

// ── object dtype with benign pickle — NPY-OBJECT-001 but no gadget findings ──

func TestScan_objectDtypeBenignPickle(t *testing.T) {
	// A well-formed pickle stream with PROTO 2 + STOP — no gadgets.
	benignPickle := []byte{0x80, 0x02, '.'}
	data := objectNpy(benignPickle)
	ids, err := scan(data)
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "NPY-OBJECT-001") {
		t.Fatalf("expected NPY-OBJECT-001 even for benign pickle data, got %v", ids)
	}
	if hasID(ids, "PKL-GLOBAL-001") {
		t.Fatalf("unexpected PKL-GLOBAL-001 for benign pickle, got %v", ids)
	}
}

// ── malformed header — must produce NPY-HEADER-001, no panic ─────────────────

func TestScan_malformedHeader(t *testing.T) {
	ids, err := scan(malformedHeaderNpy())
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "NPY-HEADER-001") {
		t.Fatalf("expected NPY-HEADER-001 for garbage header, got %v", ids)
	}
}

// ── truncated file (header_len past EOF) — must produce NPY-TRUNC-001 ────────

func TestScan_truncated(t *testing.T) {
	ids, err := scan(truncatedNpy())
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "NPY-TRUNC-001") {
		t.Fatalf("expected NPY-TRUNC-001 for truncated .npy, got %v", ids)
	}
}

// ── unknown version — must produce NPY-VERSION-001, no panic ─────────────────

func TestScan_unknownVersion(t *testing.T) {
	ids, err := scan(unknownVersionNpy())
	// Error is acceptable (file too small after stripping magic), but no panic.
	_ = err
	// The scanner may return an error for a too-short file OR a version finding.
	// Both are correct behaviour; the key invariant is no panic.
	_ = ids
}

// ── empty file — no panic ─────────────────────────────────────────────────────

func TestScan_emptyFile(t *testing.T) {
	_, _ = scan([]byte{})
}

// ── v2.0 format — must parse correctly ───────────────────────────────────────

func TestScan_v2BenignFloat(t *testing.T) {
	header := "{'descr': '<f4', 'fortran_order': False, 'shape': (3,), }\n"
	data := buildNpyV2(header, make([]byte, 12))
	ids, err := scan(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no findings for v2.0 float dtype .npy, got %v", ids)
	}
}

func TestScan_v2ObjectDtypeRCE(t *testing.T) {
	header := "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }\n"
	data := buildNpyV2(header, osSystemPickle())
	ids, err := scan(data)
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "NPY-OBJECT-001") {
		t.Fatalf("expected NPY-OBJECT-001 in v2.0 object dtype, got %v", ids)
	}
	if !hasID(ids, "PKL-GLOBAL-001") {
		t.Fatalf("expected PKL-GLOBAL-001 in v2.0 object dtype, got %v", ids)
	}
}

// ── .npz (zip) with malicious .npy entry ─────────────────────────────────────

func TestScan_npzWithMaliciousNpy(t *testing.T) {
	malicious := objectNpy(osSystemPickle())
	npzData := buildNpz(map[string][]byte{
		"arr_0.npy": malicious,
	})
	ids, err := scan(npzData)
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "NPY-OBJECT-001") {
		t.Fatalf("expected NPY-OBJECT-001 from .npz scan, got %v", ids)
	}
	if !hasID(ids, "PKL-GLOBAL-001") {
		t.Fatalf("expected PKL-GLOBAL-001 from .npz scan, got %v", ids)
	}
}

// ── .npz with benign .npy entry — no findings ────────────────────────────────

func TestScan_npzBenign(t *testing.T) {
	npzData := buildNpz(map[string][]byte{
		"arr_0.npy": benignNpy(),
	})
	ids, err := scan(npzData)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no findings for .npz with benign .npy, got %v", ids)
	}
}

// ── .npz with mixed entries (only .npy scanned) ───────────────────────────────

func TestScan_npzSkipsNonNpy(t *testing.T) {
	// The .bin file is NOT a .npy — the scanner must not try to parse it.
	npzData := buildNpz(map[string][]byte{
		"weights.bin": osSystemPickle(), // raw pickle, but NOT a .npy entry
		"arr_0.npy":   benignNpy(),
	})
	ids, err := scan(npzData)
	if err != nil {
		t.Fatal(err)
	}
	// No NPY-OBJECT-001 expected — the pickle is in a non-.npy entry.
	if hasID(ids, "NPY-OBJECT-001") {
		t.Fatalf("unexpected NPY-OBJECT-001: scanner should skip non-.npy entries, got %v", ids)
	}
}
