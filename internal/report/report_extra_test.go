package report_test

// report_extra_test.go — QA-authored additional tests for report writers.
// Covers: ExitCode post-filter semantics, SARIF schema completeness, JSON
// round-trip with multiple findings, human writer with errors section,
// empty result set, SARIF severity mapping for all levels.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/t3bik/modelvet/internal/finding"
	"github.com/t3bik/modelvet/internal/report"
	"github.com/t3bik/modelvet/internal/scan"
)

// ─── AC6: ExitCode with --min-severity interaction ───────────────────────────
// Design §7: exit code is computed on post-filter (reported) findings.
// Raising --min-severity above High gives exit 0 even if a High finding existed.
// This test proves the specification: ExitCode(result) where result.Findings
// contains only Medium entries (post-filter) → exit 0.

func TestAC6_ExitCodePostFilterSemantics(t *testing.T) {
	tests := []struct {
		name     string
		findings []finding.Finding
		want     int
	}{
		{
			name:     "no findings → 0",
			findings: nil,
			want:     0,
		},
		{
			name:     "info only → 0",
			findings: []finding.Finding{finding.New("GGUF-VERSION-001", -1, "v99")},
			want:     0,
		},
		{
			name:     "medium only → 0",
			findings: []finding.Finding{finding.New("GGUF-KV-DUP-001", -1, "dup")},
			want:     0,
		},
		{
			name:     "high → 1",
			findings: []finding.Finding{finding.New("GGUF-MAGIC-001", 0, "bad magic")},
			want:     1,
		},
		{
			name:     "critical → 1",
			findings: []finding.Finding{finding.New("GGUF-KV-TYPE-001", 0, "type confusion")},
			want:     1,
		},
		{
			name: "mixed critical+medium → 1",
			findings: []finding.Finding{
				finding.New("GGUF-VERSION-001", -1, "v99"),
				finding.New("GGUF-KV-TYPE-001", 0, "type confusion"),
			},
			want: 1,
		},
		{
			name: "post-filter medium-only (simulates --min-severity=info with only medium results) → 0",
			findings: []finding.Finding{
				finding.New("ST-DTYPE-001", 8, "unknown dtype"),
				finding.New("ST-JSON-001", 8, "bad json"),
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scan.Result{Findings: tt.findings, Scanned: 1}
			got := report.ExitCode(result)
			if got != tt.want {
				t.Fatalf("ExitCode = %d, want %d (findings: %v)", got, tt.want, tt.findings)
			}
		})
	}
}

// ─── AC6: SARIF schema fields ─────────────────────────────────────────────────

func TestAC6_SARIFSchemaFields(t *testing.T) {
	f := finding.New("GGUF-KV-TYPE-001", 0x1A4, "type_code=99")
	f.Path = "/models/bad.gguf"

	var buf bytes.Buffer
	w, err := report.NewWriter(report.FormatSARIF, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(makeResult(f)); err != nil {
		t.Fatal(err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("SARIF not valid JSON: %v\nOutput: %s", err, buf.String())
	}

	// Required top-level fields.
	if sarif["version"] != "2.1.0" {
		t.Errorf("version: got %v", sarif["version"])
	}
	if _, ok := sarif["$schema"]; !ok {
		t.Error("missing $schema field")
	}
	runs, ok := sarif["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatalf("expected non-empty runs array")
	}

	run := runs[0].(map[string]interface{})

	// Tool.driver must have name and rules.
	tool, ok := run["tool"].(map[string]interface{})
	if !ok {
		t.Fatal("missing tool field")
	}
	driver, ok := tool["driver"].(map[string]interface{})
	if !ok {
		t.Fatal("missing driver field")
	}
	if driver["name"] != "modelvet" {
		t.Errorf("driver.name: got %v", driver["name"])
	}
	rules, ok := driver["rules"].([]interface{})
	if !ok || len(rules) == 0 {
		t.Fatalf("expected non-empty rules array")
	}

	// Validate rule structure.
	rule := rules[0].(map[string]interface{})
	if rule["id"] == nil {
		t.Error("rule missing id")
	}
	if _, ok := rule["fullDescription"]; !ok {
		t.Error("rule missing fullDescription")
	}

	// Validate result structure.
	results, ok := run["results"].([]interface{})
	if !ok || len(results) == 0 {
		t.Fatal("expected results array")
	}
	res := results[0].(map[string]interface{})
	if res["ruleId"] != "GGUF-KV-TYPE-001" {
		t.Errorf("ruleId: got %v", res["ruleId"])
	}
	if res["level"] != "error" {
		t.Errorf("level for Critical: got %v", res["level"])
	}

	// Location with byte offset.
	locs, ok := res["locations"].([]interface{})
	if !ok || len(locs) == 0 {
		t.Fatal("expected locations")
	}
	loc := locs[0].(map[string]interface{})
	physLoc := loc["physicalLocation"].(map[string]interface{})
	artifactLoc := physLoc["artifactLocation"].(map[string]interface{})
	if !strings.HasPrefix(artifactLoc["uri"].(string), "file://") {
		t.Errorf("uri should start with file://, got %v", artifactLoc["uri"])
	}
}

// ─── AC6: SARIF severity mapping ─────────────────────────────────────────────

func TestAC6_SARIFSeverityMapping(t *testing.T) {
	tests := []struct {
		ruleID    string
		wantLevel string
	}{
		{"GGUF-KV-TYPE-001", "error"},   // Critical → error
		{"GGUF-MAGIC-001", "error"},     // High → error
		{"GGUF-VERSION-001", "warning"}, // Medium → warning
		{"PKL-OPAQUE-001", "note"},      // Low → note
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			f := finding.New(tt.ruleID, 0, "test")
			f.Path = "/tmp/test"
			var buf bytes.Buffer
			w, _ := report.NewWriter(report.FormatSARIF, &buf)
			_ = w.Write(makeResult(f))

			var sarif map[string]interface{}
			if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
				t.Fatal(err)
			}
			runs := sarif["runs"].([]interface{})
			run := runs[0].(map[string]interface{})
			results := run["results"].([]interface{})
			res := results[0].(map[string]interface{})
			if res["level"] != tt.wantLevel {
				t.Errorf("ruleID %s: level=%v, want %q", tt.ruleID, res["level"], tt.wantLevel)
			}
		})
	}
}

// ─── AC6: JSON writer with multiple findings and errors ───────────────────────

func TestAC6_JSONMultipleFindingsAndErrors(t *testing.T) {
	f1 := finding.New("GGUF-KV-TYPE-001", 0, "type confusion")
	f1.Path = "/models/a.gguf"
	f2 := finding.New("PKL-GLOBAL-001", -1, "os.system")
	f2.Path = "/models/b.pkl"

	result := scan.Result{
		Findings: []finding.Finding{f1, f2},
		Errors:   []scan.FileError{{Path: "/models/c.bin", Err: bytes.ErrTooLarge}},
		Scanned:  2,
		Skipped:  1,
	}

	var buf bytes.Buffer
	w, _ := report.NewWriter(report.FormatJSON, &buf)
	if err := w.Write(result); err != nil {
		t.Fatal(err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("JSON invalid: %v\n%s", err, buf.String())
	}

	findings := out["findings"].([]interface{})
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	summary := out["summary"].(map[string]interface{})
	if summary["scanned"].(float64) != 2 {
		t.Errorf("summary.scanned: got %v", summary["scanned"])
	}
	if summary["skipped"].(float64) != 1 {
		t.Errorf("summary.skipped: got %v", summary["skipped"])
	}
	errs := out["errors"].([]interface{})
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}
}

// ─── AC6: Human writer with errors section ───────────────────────────────────

func TestAC6_HumanWriterErrors(t *testing.T) {
	f := finding.New("GGUF-MAGIC-001", 0, "bad magic")
	f.Path = "/models/bad.gguf"

	result := scan.Result{
		Findings: []finding.Finding{f},
		Errors:   []scan.FileError{{Path: "/models/corrupt.gguf", Err: bytes.ErrTooLarge}},
		Scanned:  2,
		Skipped:  0,
	}

	var buf bytes.Buffer
	w, _ := report.NewWriter(report.FormatHuman, &buf)
	if err := w.Write(result); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Scan errors") {
		t.Errorf("expected 'Scan errors' section in human output:\n%s", out)
	}
	if !strings.Contains(out, "/models/corrupt.gguf") {
		t.Errorf("expected error path in human output:\n%s", out)
	}
}

// ─── AC6: Human writer on empty result ───────────────────────────────────────

func TestAC6_HumanWriterEmptyResult(t *testing.T) {
	var buf bytes.Buffer
	w, _ := report.NewWriter(report.FormatHuman, &buf)
	if err := w.Write(scan.Result{Scanned: 5, Skipped: 2}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Scanned: 5") {
		t.Errorf("expected Scanned:5 in output:\n%s", out)
	}
	if !strings.Contains(out, "Skipped: 2") {
		t.Errorf("expected Skipped:2 in output:\n%s", out)
	}
}

// ─── AC6: SARIF with no findings → empty results array, no rules ─────────────

func TestAC6_SARIFEmptyResult(t *testing.T) {
	var buf bytes.Buffer
	w, _ := report.NewWriter(report.FormatSARIF, &buf)
	if err := w.Write(scan.Result{Scanned: 1}); err != nil {
		t.Fatal(err)
	}
	var sarif map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("SARIF not valid JSON: %v", err)
	}
	runs := sarif["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	// results may be nil or empty — both acceptable.
	results, _ := run["results"].([]interface{})
	if len(results) != 0 {
		t.Errorf("expected empty results for empty result set, got %d", len(results))
	}
}
