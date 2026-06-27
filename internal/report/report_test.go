package report_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/t3bik/modelvet/internal/finding"
	"github.com/t3bik/modelvet/internal/report"
	"github.com/t3bik/modelvet/internal/scan"
)

func makeResult(findings ...finding.Finding) scan.Result {
	return scan.Result{
		Findings: findings,
		Scanned:  1,
	}
}

func TestNewWriter_human(t *testing.T) {
	w, err := report.NewWriter(report.FormatHuman, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w == nil {
		t.Fatal("expected non-nil writer")
	}
}

func TestNewWriter_json(t *testing.T) {
	w, err := report.NewWriter(report.FormatJSON, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if w == nil {
		t.Fatal("expected non-nil writer")
	}
}

func TestNewWriter_sarif(t *testing.T) {
	w, err := report.NewWriter(report.FormatSARIF, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if w == nil {
		t.Fatal("expected non-nil writer")
	}
}

func TestNewWriter_unknown(t *testing.T) {
	_, err := report.NewWriter("xml", &bytes.Buffer{})
	if !errors.Is(err, report.ErrUnknownFormat) {
		t.Fatalf("expected ErrUnknownFormat, got %v", err)
	}
}

func TestExitCode_noFindings(t *testing.T) {
	if got := report.ExitCode(scan.Result{}); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
}

func TestExitCode_mediumOnly(t *testing.T) {
	f := finding.New("GGUF-VERSION-001", -1, "test")
	if got := report.ExitCode(makeResult(f)); got != 0 {
		t.Fatalf("expected 0 for Medium-only, got %d", got)
	}
}

func TestExitCode_high(t *testing.T) {
	f := finding.New("GGUF-MAGIC-001", 0, "test")
	if got := report.ExitCode(makeResult(f)); got != 1 {
		t.Fatalf("expected 1 for High, got %d", got)
	}
}

func TestExitCode_critical(t *testing.T) {
	f := finding.New("GGUF-KV-TYPE-001", 0, "test")
	if got := report.ExitCode(makeResult(f)); got != 1 {
		t.Fatalf("expected 1 for Critical, got %d", got)
	}
}

func TestHumanWriter_output(t *testing.T) {
	f := finding.New("GGUF-KV-TYPE-001", 0x1A4, "type_code=99 outside enum")
	f.Path = "/models/test.gguf"
	var buf bytes.Buffer
	w, _ := report.NewWriter(report.FormatHuman, &buf)
	if err := w.Write(makeResult(f)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "CRITICAL") {
		t.Errorf("expected CRITICAL in output: %s", out)
	}
	if !strings.Contains(out, "GGUF-KV-TYPE-001") {
		t.Errorf("expected rule ID in output: %s", out)
	}
	if !strings.Contains(out, "0x1A4") {
		t.Errorf("expected offset 0x1A4 in output: %s", out)
	}
}

func TestJSONWriter_roundtrip(t *testing.T) {
	f := finding.New("PKL-GLOBAL-001", -1, "os.system gadget")
	f.Path = "/models/evil.pkl"
	var buf bytes.Buffer
	w, _ := report.NewWriter(report.FormatJSON, &buf)
	if err := w.Write(makeResult(f)); err != nil {
		t.Fatal(err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON not valid: %v", err)
	}
	findings, ok := result["findings"].([]interface{})
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings array, got %v", result)
	}
	first := findings[0].(map[string]interface{})
	if first["rule_id"] != "PKL-GLOBAL-001" {
		t.Errorf("unexpected rule_id: %v", first["rule_id"])
	}
	if first["severity"] != "CRITICAL" {
		t.Errorf("unexpected severity: %v", first["severity"])
	}
}

func TestSARIFWriter_structure(t *testing.T) {
	f := finding.New("ST-OFFSET-001", 8, "tensor oob")
	f.Path = "/models/test.safetensors"
	var buf bytes.Buffer
	w, _ := report.NewWriter(report.FormatSARIF, &buf)
	if err := w.Write(makeResult(f)); err != nil {
		t.Fatal(err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("SARIF not valid JSON: %v", err)
	}
	if sarif["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", sarif["version"])
	}
	runs, ok := sarif["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("expected runs array")
	}
	run := runs[0].(map[string]interface{})
	results, ok := run["results"].([]interface{})
	if !ok || len(results) == 0 {
		t.Fatal("expected results array")
	}
	first := results[0].(map[string]interface{})
	if first["ruleId"] != "ST-OFFSET-001" {
		t.Errorf("unexpected ruleId: %v", first["ruleId"])
	}
	if first["level"] != "error" {
		t.Errorf("expected level=error for Critical, got %v", first["level"])
	}
}
