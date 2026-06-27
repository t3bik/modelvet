// Package finding defines the shared vocabulary for modelvet: Severity,
// Format, Finding, and the Rule catalog helpers. It is a leaf package with
// no imports outside the standard library.
package finding

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrBadSeverity is returned by ParseSeverity for unrecognised inputs.
var ErrBadSeverity = errors.New("finding: unknown severity")

// Severity orders findings from informational to critical.
// Ordered so that comparisons (>=) work for --min-severity filtering and
// exit-code decisions.
type Severity int

const (
	Info     Severity = iota // observational; not a risk by itself
	Low                      // hygiene / minor robustness issue
	Medium                   // suspicious; warrants review
	High                     // likely-exploitable or strong malicious signal
	Critical                 // code-execution gadget or memory-safety break
)

var severityNames = [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

// String returns the canonical uppercase name of the severity.
func (s Severity) String() string {
	if int(s) < 0 || int(s) >= len(severityNames) {
		return fmt.Sprintf("SEVERITY(%d)", int(s))
	}
	return severityNames[s]
}

// MarshalJSON encodes a Severity as its string name so JSON output is human-readable.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON parses a Severity from its string name.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	v, err := ParseSeverity(str)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// ParseSeverity converts a case-insensitive severity name to Severity.
// Returns ErrBadSeverity for unknown names.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "INFO":
		return Info, nil
	case "LOW":
		return Low, nil
	case "MEDIUM":
		return Medium, nil
	case "HIGH":
		return High, nil
	case "CRITICAL":
		return Critical, nil
	default:
		return Info, fmt.Errorf("%w: %q", ErrBadSeverity, s)
	}
}

// Format identifies which artifact format produced a finding.
type Format string

const (
	FormatGGUF        Format = "gguf"
	FormatSafetensors Format = "safetensors"
	FormatPickle      Format = "pickle"
	FormatUnknown     Format = "unknown"
)

// Finding is one detected issue. Value type, immutable once produced.
// Designed to marshal cleanly to JSON and map onto SARIF without custom code.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Severity    Severity `json:"severity"`
	Format      Format   `json:"format"`
	Path        string   `json:"path"`
	Offset      int64    `json:"offset"`
	Detail      string   `json:"detail"`
	Remediation string   `json:"remediation"`
}
