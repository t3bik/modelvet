package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/t3bik/modelvet/internal/scan"
)

type jsonWriter struct {
	w io.Writer
}

// jsonReport is the top-level JSON output structure.
type jsonReport struct {
	Findings []jsonFinding `json:"findings"`
	Summary  jsonSummary   `json:"summary"`
	Errors   []jsonError   `json:"errors,omitempty"`
}

type jsonFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Format      string `json:"format"`
	Path        string `json:"path"`
	Offset      int64  `json:"offset"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type jsonSummary struct {
	Scanned  int `json:"scanned"`
	Skipped  int `json:"skipped"`
	Findings int `json:"findings"`
}

type jsonError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (j *jsonWriter) Write(result scan.Result) error {
	report := jsonReport{
		Summary: jsonSummary{
			Scanned:  result.Scanned,
			Skipped:  result.Skipped,
			Findings: len(result.Findings),
		},
	}
	for _, f := range result.Findings {
		report.Findings = append(report.Findings, jsonFinding{
			RuleID:      f.RuleID,
			Severity:    f.Severity.String(),
			Format:      string(f.Format),
			Path:        f.Path,
			Offset:      f.Offset,
			Detail:      f.Detail,
			Remediation: f.Remediation,
		})
	}
	for _, e := range result.Errors {
		report.Errors = append(report.Errors, jsonError{Path: e.Path, Message: e.Err.Error()})
	}

	enc := json.NewEncoder(j.w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("json writer: %w", err)
	}
	return nil
}
