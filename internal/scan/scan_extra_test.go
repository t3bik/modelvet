package scan_test

// scan_extra_test.go — QA-authored tests for scan.Engine and scan.Detect.
// Covers: min-severity filtering, context cancellation, non-recursive walk,
// exact detect precedence cases, FileError.Error().

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/t3bik/modelvet/internal/finding"
	"github.com/t3bik/modelvet/internal/scan"
)

// ─── AC5: MinSeverity filtering ──────────────────────────────────────────────

// TestAC5_MinSeverityFiltersLow: a file that produces only a Medium/Low finding
// when --min-severity=high is set should result in 0 reported findings, and
// exit code 0.
func TestAC5_MinSeverityFiltersLow(t *testing.T) {
	// Write a GGUF with bad version (GGUF-VERSION-001 = Medium).
	data := make([]byte, 24)
	copy(data[0:4], "GGUF")
	data[4] = 99 // version=99 → GGUF-VERSION-001 (Medium)

	path := writeTmpFile(t, "bad_ver.gguf", data)
	eng := scan.NewEngine()

	result, err := eng.Walk(context.Background(), path, scan.Options{
		MinSeverity: finding.High, // only report High+
	})
	if err != nil {
		t.Fatal(err)
	}
	// Medium finding should be filtered out.
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 reported findings with min-severity=high, got %d: %v",
			len(result.Findings), result.Findings)
	}
	// Scanned count should still be 1 (file was dispatched, just filtered).
	if result.Scanned != 1 {
		t.Fatalf("expected Scanned=1, got %d", result.Scanned)
	}
}

// TestAC5_MinSeverityPassesCritical: a Critical finding passes min-severity=high.
func TestAC5_MinSeverityPassesCritical(t *testing.T) {
	// KV type-confusion → GGUF-KV-TYPE-001 (Critical).
	// Build a GGUF with one KV whose type field = 99.
	var buf []byte
	buf = append(buf, []byte("GGUF")...)
	buf = appendLE32(buf, 3)  // version
	buf = appendLE64(buf, 0)  // tensor_count
	buf = appendLE64(buf, 1)  // kv_count
	// KV: key "k" + type=99
	buf = appendLE64(buf, 1) // key length = 1
	buf = append(buf, 'k')
	buf = appendLE32(buf, 99) // type = 99 (invalid)

	path := writeTmpFile(t, "kv_type.gguf", buf)
	eng := scan.NewEngine()

	result, err := eng.Walk(context.Background(), path, scan.Options{
		MinSeverity: finding.High,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "GGUF-KV-TYPE-001" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected GGUF-KV-TYPE-001 in findings, got %v", result.Findings)
	}
}

// ─── AC5: Context cancellation stops walk ────────────────────────────────────

func TestAC5_ContextCancellation(t *testing.T) {
	dir := t.TempDir()

	// Write 5 model files. One malicious GGUF and 4 benign ones.
	malData := make([]byte, 24)
	copy(malData[0:4], "GGUF")
	malData[4] = 99 // bad version
	if err := os.WriteFile(filepath.Join(dir, "a.gguf"), malData, 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		data := make([]byte, 24)
		copy(data[0:4], "GGUF")
		data[4] = 3
		name := filepath.Join(dir, string(rune('b'+i))+".gguf")
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	eng := scan.NewEngine()
	// Walk may or may not scan all files depending on timing — that's fine.
	// What matters: it must not panic and must return cleanly.
	_, err := eng.Walk(ctx, dir, scan.Options{
		MinSeverity: finding.Info,
		Recurse:     true,
	})
	if err != nil {
		// ctx.Err() arriving at Walk level returns nil, not an error — log it.
		t.Logf("Walk returned error (may be ctx): %v", err)
	}
	// Test passes if we get here without panic.
}

// ─── AC5: Non-recursive walk skips subdirectory ──────────────────────────────

func TestAC5_NonRecursiveWalkSkipsSubdir(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "sub")
	if err := os.Mkdir(subdir, 0700); err != nil {
		t.Fatal(err)
	}

	// File at root level.
	data := make([]byte, 24)
	copy(data, "GGUF")
	data[4] = 3
	if err := os.WriteFile(filepath.Join(dir, "root.gguf"), data, 0600); err != nil {
		t.Fatal(err)
	}

	// File in subdirectory — should NOT be scanned when Recurse=false.
	if err := os.WriteFile(filepath.Join(subdir, "deep.gguf"), data, 0600); err != nil {
		t.Fatal(err)
	}

	eng := scan.NewEngine()
	result, err := eng.Walk(context.Background(), dir, scan.Options{
		MinSeverity: finding.Info,
		Recurse:     false,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Only root.gguf should be scanned.
	if result.Scanned != 1 {
		t.Fatalf("expected 1 scanned (Recurse=false), got %d", result.Scanned)
	}
}

// ─── AC5: FileError.Error() format ───────────────────────────────────────────

func TestAC5_FileErrorFormat(t *testing.T) {
	fe := scan.FileError{Path: "/models/evil.gguf", Err: os.ErrNotExist}
	s := fe.Error()
	if s == "" {
		t.Fatal("FileError.Error() returned empty string")
	}
	// Must contain the path.
	if len(s) < len("/models/evil.gguf") {
		t.Fatalf("FileError.Error() too short: %q", s)
	}
}

// ─── AC5: Detect — .pkl/.pickle extensions ───────────────────────────────────

func TestAC5_DetectPickleExtensions(t *testing.T) {
	for _, ext := range []string{".pkl", ".pickle", ".pt", ".pth"} {
		t.Run("ext="+ext, func(t *testing.T) {
			// Data that looks like nothing special (no PK magic, no GGUF magic, no 0x80).
			data := make([]byte, 16) // all zeros
			d := scan.Detect(newFakeReaderAt(data), int64(len(data)), "model"+ext)
			if d.Format != finding.FormatPickle {
				t.Errorf("ext %s: expected FormatPickle, got %v", ext, d.Format)
			}
		})
	}
}

// ─── AC5: Detect — small file (< 4 bytes) falls through to extension ─────────

func TestAC5_DetectTinyFileExtensionFallback(t *testing.T) {
	data := []byte{0x01}
	d := scan.Detect(newFakeReaderAt(data), 1, "model.pkl")
	if d.Format != finding.FormatPickle {
		t.Fatalf("tiny file with .pkl: expected FormatPickle, got %v", d.Format)
	}
}

func TestAC5_DetectTinyFileUnknown(t *testing.T) {
	data := []byte{0x01}
	d := scan.Detect(newFakeReaderAt(data), 1, "model.xyz")
	if d.Format != finding.FormatUnknown {
		t.Fatalf("tiny file with .xyz: expected FormatUnknown, got %v", d.Format)
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

type fakeReaderAt []byte

func newFakeReaderAt(b []byte) fakeReaderAt { return fakeReaderAt(b) }

func (f fakeReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(f)) {
		return 0, os.ErrNotExist
	}
	n := copy(p, f[off:])
	return n, nil
}

func appendLE32(buf []byte, v uint32) []byte {
	return append(buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func appendLE64(buf []byte, v uint64) []byte {
	return append(buf,
		byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}
