// Package report provides output writers for modelvet scan results.
package report

import (
	"errors"
	"fmt"
	"io"

	"github.com/t3bik/modelvet/internal/finding"
	"github.com/t3bik/modelvet/internal/scan"
)

// ErrUnknownFormat is returned by NewWriter for an unrecognised format string.
var ErrUnknownFormat = errors.New("report: unknown output format")

// Format identifies the desired output style.
type Format string

const (
	FormatHuman Format = "human"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// Writer renders a scan.Result to an io.Writer.
type Writer interface {
	Write(result scan.Result) error
}

// NewWriter constructs the Writer for the requested format.
func NewWriter(format Format, w io.Writer) (Writer, error) {
	return NewWriterQuiet(format, w, false)
}

// NewWriterQuiet constructs the Writer for the requested format.
// When quiet is true and format is human, per-file "OK" lines are suppressed;
// findings and the summary are always printed. For JSON/SARIF, quiet is a no-op.
func NewWriterQuiet(format Format, w io.Writer, quiet bool) (Writer, error) {
	switch format {
	case FormatHuman:
		return &humanWriter{w: w, quiet: quiet}, nil
	case FormatJSON:
		return &jsonWriter{w: w}, nil
	case FormatSARIF:
		return &sarifWriter{w: w}, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownFormat, format)
	}
}

// ExitCode maps a Result to a process exit code.
//   0 → no findings at or above High
//   1 → at least one High/Critical finding
//   2 → reserved for usage/setup errors (set by cmd, not here)
func ExitCode(result scan.Result) int {
	for _, f := range result.Findings {
		if f.Severity >= finding.High {
			return 1
		}
	}
	return 0
}
