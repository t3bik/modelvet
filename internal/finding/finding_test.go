package finding_test

import (
	"errors"
	"testing"

	"github.com/t3bik/modelvet/internal/finding"
)

func TestSeverity_String(t *testing.T) {
	cases := []struct {
		s    finding.Severity
		want string
	}{
		{finding.Info, "INFO"},
		{finding.Low, "LOW"},
		{finding.Medium, "MEDIUM"},
		{finding.High, "HIGH"},
		{finding.Critical, "CRITICAL"},
	}
	for _, tc := range cases {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}

func TestSeverity_Ordering(t *testing.T) {
	if finding.Info >= finding.Low {
		t.Error("Info should be < Low")
	}
	if finding.Low >= finding.Medium {
		t.Error("Low should be < Medium")
	}
	if finding.Medium >= finding.High {
		t.Error("Medium should be < High")
	}
	if finding.High >= finding.Critical {
		t.Error("High should be < Critical")
	}
}

func TestParseSeverity_roundtrip(t *testing.T) {
	for _, s := range []finding.Severity{finding.Info, finding.Low, finding.Medium, finding.High, finding.Critical} {
		parsed, err := finding.ParseSeverity(s.String())
		if err != nil {
			t.Fatalf("ParseSeverity(%q): %v", s.String(), err)
		}
		if parsed != s {
			t.Errorf("round-trip failed: %v → %q → %v", s, s.String(), parsed)
		}
	}
}

func TestParseSeverity_caseInsensitive(t *testing.T) {
	_, err := finding.ParseSeverity("critical")
	if err != nil {
		t.Fatal(err)
	}
	_, err = finding.ParseSeverity("MEDIUM")
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseSeverity_unknown(t *testing.T) {
	_, err := finding.ParseSeverity("SUPERCRITICAL")
	if !errors.Is(err, finding.ErrBadSeverity) {
		t.Fatalf("expected ErrBadSeverity, got %v", err)
	}
}

func TestCatalog_integrity(t *testing.T) {
	// Every entry in Catalog has a non-empty ID, Title, and Remediation.
	for id, rule := range finding.Catalog {
		if id == "" {
			t.Error("empty key in Catalog")
		}
		if rule.ID != id {
			t.Errorf("Catalog[%q].ID = %q (mismatch)", id, rule.ID)
		}
		if rule.Title == "" {
			t.Errorf("Catalog[%q].Title is empty", id)
		}
		if rule.Remediation == "" {
			t.Errorf("Catalog[%q].Remediation is empty", id)
		}
	}
}

func TestNew_knownRule(t *testing.T) {
	f := finding.New("GGUF-KV-TYPE-001", 42, "detail")
	if f.RuleID != "GGUF-KV-TYPE-001" {
		t.Errorf("wrong RuleID: %s", f.RuleID)
	}
	if f.Severity != finding.Critical {
		t.Errorf("wrong Severity: %v", f.Severity)
	}
	if f.Offset != 42 {
		t.Errorf("wrong Offset: %d", f.Offset)
	}
	if f.Format != finding.FormatGGUF {
		t.Errorf("wrong Format: %v", f.Format)
	}
}

func TestNew_unknownRulePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for unknown rule ID, got none")
		}
	}()
	finding.New("NONEXISTENT-RULE", 0, "should panic")
}

func TestCatalog_uniqueIDs(t *testing.T) {
	seen := make(map[string]bool)
	for id := range finding.Catalog {
		if seen[id] {
			t.Errorf("duplicate ID in Catalog: %q", id)
		}
		seen[id] = true
	}
}
