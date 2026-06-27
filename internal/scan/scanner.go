// Package scan orchestrates format detection and dispatch.
package scan

import (
	"io"

	"github.com/t3bik/modelvet/internal/finding"
)

// Scanner is the consumer-side interface each format scanner implements.
// A Scanner must NOT retain the reader, spawn goroutines, or read beyond
// what it needs.
//
// Scan inspects the artifact and returns findings (possibly empty).
// A returned error means the scanner could not run at all (e.g. truncated
// below the minimum header). Detected risks are Findings, not errors.
type Scanner interface {
	Scan(ra io.ReaderAt, size int64) ([]finding.Finding, error)
	Format() finding.Format
}
