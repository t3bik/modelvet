package scan

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/t3bik/modelvet/internal/finding"
	"github.com/t3bik/modelvet/internal/gguf"
	"github.com/t3bik/modelvet/internal/numpy"
	"github.com/t3bik/modelvet/internal/pickle"
	"github.com/t3bik/modelvet/internal/safetensors"
)

// Options configures a scan pass.
type Options struct {
	MinSeverity finding.Severity
	Recurse     bool
}

// FileError records a per-file scan error (non-fatal; walk continues).
type FileError struct {
	Path string
	Err  error
}

func (e FileError) Error() string {
	return fmt.Sprintf("%s: %v", e.Path, e.Err)
}

// Result is the aggregate outcome of a Walk.
type Result struct {
	Findings []finding.Finding
	Errors   []FileError
	Scanned  int // files dispatched to a scanner
	Skipped  int // files with FormatUnknown
}

// Engine holds the registry of scanners. No mutable state between calls.
type Engine struct {
	scanners map[finding.Format]Scanner
}

// NewEngine wires up all format scanners.
func NewEngine() *Engine {
	return &Engine{
		scanners: map[finding.Format]Scanner{
			finding.FormatGGUF:        gguf.New(),
			finding.FormatSafetensors: safetensors.New(),
			finding.FormatPickle:      pickle.New(),
			finding.FormatNumpy:       numpy.New(),
		},
	}
}

// NewEngineWithScanners creates an Engine with an explicit scanner map.
// Intended for tests that inject stub scanners.
func NewEngineWithScanners(scanners map[finding.Format]Scanner) *Engine {
	return &Engine{scanners: scanners}
}

// File scans a single file: open, detect format, dispatch, stamp Path, filter
// by MinSeverity. Wrapped in a recover guard so a panicking scanner becomes a
// FileError rather than crashing the process.
func (e *Engine) File(ctx context.Context, path string, opts Options) ([]finding.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f, err := os.Open(path) //nolint:gosec // G304: user-provided paths are intentional for CLI tool
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	size := info.Size()

	detected := Detect(f, size, filepath.Base(path))
	if detected.Format == finding.FormatUnknown {
		return nil, nil // signal: skipped (caller increments Skipped)
	}

	scanner, ok := e.scanners[detected.Format]
	if !ok {
		return nil, nil
	}

	findings, err := safeCallScanner(scanner, f, size)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	// Stamp path and filter by MinSeverity.
	// Always return a non-nil slice to signal "was scanned" (even if empty).
	result := make([]finding.Finding, 0, len(findings))
	for i := range findings {
		findings[i].Path = path
		if findings[i].Severity >= opts.MinSeverity {
			result = append(result, findings[i])
		}
	}
	return result, nil
}

// safeCallScanner wraps scanner.Scan in a recover guard (§6.5).
// If the scanner panics, the panic is converted to an error.
func safeCallScanner(s Scanner, ra io.ReaderAt, size int64) (findings []finding.Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("scanner panic (recovered): %v", r)
		}
	}()
	return s.Scan(ra, size)
}

// Walk scans a path that may be a file or directory tree.
// ctx cancellation stops the walk between files.
func (e *Engine) Walk(ctx context.Context, root string, opts Options) (Result, error) {
	info, err := os.Stat(root)
	if err != nil {
		return Result{}, fmt.Errorf("stat %q: %w", root, err)
	}

	var result Result

	if !info.IsDir() {
		e.scanOne(ctx, root, opts, &result)
		return result, nil
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			result.Errors = append(result.Errors, FileError{Path: path, Err: walkErr})
			return nil
		}
		if d.IsDir() {
			if !opts.Recurse && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip non-regular files (FIFOs, devices, symlinks, etc.) to prevent
		// blocking on a read from a special file in the scan tree.
		if !d.Type().IsRegular() {
			return nil
		}
		e.scanOne(ctx, path, opts, &result)
		return nil
	})
	if err != nil {
		// ctx cancellation arrives here.
		if err == ctx.Err() {
			return result, nil
		}
		return result, err
	}
	return result, nil
}

// scanOne scans a single file and appends results into *r.
// File returns (nil, nil) to signal FormatUnknown/skipped; (non-nil, nil) when
// successfully dispatched to a scanner (findings may be empty).
func (e *Engine) scanOne(ctx context.Context, path string, opts Options, r *Result) {
	findings, err := e.File(ctx, path, opts)
	if err != nil {
		r.Errors = append(r.Errors, FileError{Path: path, Err: err})
		return
	}
	if findings == nil {
		// nil means FormatUnknown — file was skipped.
		r.Skipped++
		return
	}
	// Non-nil (possibly empty) slice: file was dispatched to a scanner.
	r.Scanned++
	r.Findings = append(r.Findings, findings...)
}
