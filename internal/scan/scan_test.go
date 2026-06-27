package scan_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/t3bik/modelvet/internal/finding"
	"github.com/t3bik/modelvet/internal/scan"
)

// writeTmpFile writes data to a temp file with the given name suffix.
func writeTmpFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("writeTmpFile: %v", err)
	}
	return path
}

func TestEngine_skipUnknown(t *testing.T) {
	path := writeTmpFile(t, "random.xyz", []byte{0x01, 0x02, 0x03})
	eng := scan.NewEngine()
	result, err := eng.Walk(context.Background(), path, scan.Options{MinSeverity: finding.Info})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skipped != 1 {
		t.Fatalf("expected 1 skipped, got %d", result.Skipped)
	}
	if result.Scanned != 0 {
		t.Fatalf("expected 0 scanned, got %d", result.Scanned)
	}
}

func TestEngine_gguf_badMagic(t *testing.T) {
	// Write a 20-byte file that starts with "XXXX" (bad magic) with .gguf ext.
	data := make([]byte, 24)
	copy(data, "XXXX")
	path := writeTmpFile(t, "bad.gguf", data)
	eng := scan.NewEngine()
	result, err := eng.Walk(context.Background(), path, scan.Options{MinSeverity: finding.Info})
	if err != nil {
		t.Fatal(err)
	}
	if result.Scanned != 1 {
		t.Fatalf("expected 1 scanned")
	}
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "GGUF-MAGIC-001" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected GGUF-MAGIC-001, got %v", result.Findings)
	}
}

func TestEngine_dirWalk(t *testing.T) {
	dir := t.TempDir()
	// Write a benign GGUF file: magic + version=3 + tensor_count=0 + kv_count=0.
	// That's 4+4+8+8 = 24 bytes minimum valid header.
	ggufData := make([]byte, 24)
	copy(ggufData[0:4], "GGUF")
	ggufData[4] = 3   // version = 3 (LE uint32, others = 0)
	// tensor_count = 0 at offset 8, kv_count = 0 at offset 16 — already zero.
	_ = os.WriteFile(filepath.Join(dir, "model.gguf"), ggufData, 0600)
	_ = os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello"), 0600)

	eng := scan.NewEngine()
	result, err := eng.Walk(context.Background(), dir, scan.Options{MinSeverity: finding.Info, Recurse: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Scanned < 1 {
		t.Fatalf("expected at least 1 scanned, got %d", result.Scanned)
	}
	if result.Skipped < 1 {
		t.Fatalf("expected at least 1 skipped, got %d", result.Skipped)
	}
}

func TestEngine_recoverGuard(t *testing.T) {
	// Inject a panicking scanner directly to verify the recover guard.
	eng := scan.NewEngineWithScanners(map[finding.Format]scan.Scanner{
		finding.FormatGGUF: &panicScanner{},
	})
	data := append([]byte("GGUF"), make([]byte, 24)...)
	path := writeTmpFile(t, "panic.gguf", data)
	result, err := eng.Walk(context.Background(), path, scan.Options{MinSeverity: finding.Info})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Errors) == 0 {
		t.Fatal("expected a FileError from panicking scanner, got none")
	}
}

// panicScanner is a Scanner that always panics — used to test the recover guard.
type panicScanner struct{}

func (p *panicScanner) Scan(_ io.ReaderAt, _ int64) ([]finding.Finding, error) {
	panic("deliberate test panic")
}
func (p *panicScanner) Format() finding.Format { return finding.FormatGGUF }
