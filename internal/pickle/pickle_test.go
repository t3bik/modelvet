package pickle_test

import (
	"bytes"
	"testing"

	"github.com/t3bik/modelvet/internal/pickle"
)

func scan(data []byte) ([]string, error) {
	s := pickle.New()
	findings, err := s.Scan(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.RuleID
	}
	return ids, nil
}

func hasID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestScan_benign(t *testing.T) {
	ids, err := scan(benignPickle())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no findings on benign pickle, got %v", ids)
	}
}

func TestScan_osSystemRCE(t *testing.T) {
	ids, err := scan(osSystemGadget())
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "PKL-GLOBAL-001") {
		t.Fatalf("expected PKL-GLOBAL-001, got %v", ids)
	}
	if !hasID(ids, "PKL-REDUCE-001") {
		t.Fatalf("expected PKL-REDUCE-001, got %v", ids)
	}
}

func TestScan_watchListModule(t *testing.T) {
	ids, err := scan(watchListGlobal())
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "PKL-GLOBAL-002") {
		t.Fatalf("expected PKL-GLOBAL-002, got %v", ids)
	}
}

func TestScan_truncated(t *testing.T) {
	ids, err := scan(truncatedPickle())
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "PKL-TRUNC-001") {
		t.Fatalf("expected PKL-TRUNC-001, got %v", ids)
	}
}

func TestScan_unknownOpcode(t *testing.T) {
	ids, err := scan(unknownOpcodePickle())
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "PKL-OPAQUE-001") {
		t.Fatalf("expected PKL-OPAQUE-001, got %v", ids)
	}
}

func TestScan_zipBenign(t *testing.T) {
	ids, err := scan(zipOf(benignPickle()))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no findings in zip of benign pickle, got %v", ids)
	}
}

func TestScan_zipMalicious(t *testing.T) {
	ids, err := scan(zipOf(osSystemGadget()))
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "PKL-GLOBAL-001") {
		t.Fatalf("expected PKL-GLOBAL-001 in zipped pickle, got %v", ids)
	}
}

func TestScan_zipTooManyEntries(t *testing.T) {
	// 10001 entries > zipMaxEntries (10000).
	data := zipWithManyEntries(10001)
	ids, err := scan(data)
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "PKL-ZIP-001") {
		t.Fatalf("expected PKL-ZIP-001, got %v", ids)
	}
}

func TestScan_emptyFile(t *testing.T) {
	// Empty file: scanner should return without panic.
	_, _ = scan([]byte{})
}
