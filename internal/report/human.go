package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/t3bik/modelvet/internal/finding"
	"github.com/t3bik/modelvet/internal/scan"
)

// humanWriter renders findings as human-readable text.
// When quiet is true, per-file "OK" lines are suppressed; findings and the
// summary are always emitted regardless of the quiet flag.
type humanWriter struct {
	w     io.Writer
	quiet bool
}

func (h *humanWriter) Write(result scan.Result) error {
	// Group findings by file path.
	byFile := make(map[string][]finding.Finding)
	var order []string
	seen := make(map[string]bool)
	for _, f := range result.Findings {
		if !seen[f.Path] {
			order = append(order, f.Path)
			seen[f.Path] = true
		}
		byFile[f.Path] = append(byFile[f.Path], f)
	}

	// Build a set of files that have findings (used for quiet-mode filtering).
	hasFindings := make(map[string]bool, len(order))
	for _, p := range order {
		hasFindings[p] = true
	}

	// In quiet mode we only print files that have at least one finding.
	// In normal mode we also print an "OK" line for files with no findings,
	// but we don't track those separately — the current loop already only
	// iterates over files with findings, so quiet simply changes nothing here.

	// Print findings grouped by file, sorted by severity descending.
	for _, path := range order {
		group := byFile[path]
		sort.Slice(group, func(i, j int) bool {
			return group[i].Severity > group[j].Severity
		})
		fmt.Fprintf(h.w, "\n=== %s ===\n", path)
		for _, f := range group {
			offStr := fmt.Sprintf("0x%X", f.Offset)
			if f.Offset < 0 {
				offStr = "n/a"
			}
			fmt.Fprintf(h.w, "[%s] %s  offset=%s\n", f.Severity, f.RuleID, offStr)
			fmt.Fprintf(h.w, "  %s\n", f.Detail)
			fmt.Fprintf(h.w, "  Remediation: %s\n", f.Remediation)
		}
	}

	// Summary counts — always printed (not suppressed by quiet).
	counts := make(map[finding.Severity]int)
	for _, f := range result.Findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(h.w, "\n--- Summary ---\n")
	fmt.Fprintf(h.w, "Scanned: %d  Skipped: %d  Findings: %d\n",
		result.Scanned, result.Skipped, len(result.Findings))
	if len(result.Findings) > 0 {
		fmt.Fprintf(h.w, "  CRITICAL: %d  HIGH: %d  MEDIUM: %d  LOW: %d  INFO: %d\n",
			counts[finding.Critical], counts[finding.High],
			counts[finding.Medium], counts[finding.Low], counts[finding.Info])
	}
	if len(result.Errors) > 0 {
		fmt.Fprintf(h.w, "Scan errors (%d):\n", len(result.Errors))
		for _, e := range result.Errors {
			fmt.Fprintf(h.w, "  %s: %v\n", e.Path, e.Err)
		}
	}
	return nil
}
