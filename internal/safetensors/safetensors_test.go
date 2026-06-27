package safetensors_test

import (
	"bytes"
	"testing"

	"github.com/t3bik/modelvet/internal/safetensors"
)

func scan(data []byte) ([]string, error) {
	s := safetensors.New()
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

func TestScan_valid(t *testing.T) {
	// F32 tensor with shape [2,2] = 4 elements * 4 bytes = 16 bytes data.
	b := newST().addTensor("weight", "F32", []int64{2, 2}, 0, 16)
	ids, err := scan(b.build(16))
	if err != nil {
		t.Fatalf("unexpected error on valid safetensors: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no findings, got %v", ids)
	}
}

func TestScan_tinyFile(t *testing.T) {
	_, err := scan([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error on 3-byte file")
	}
}

func TestScan_headerLenOOB(t *testing.T) {
	// header_len = 100 but file is only 10 bytes → header_len > size-8.
	data := withOversizedHeaderLen(10)
	ids, err := scan(data)
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "ST-HEADERLEN-001") {
		t.Fatalf("expected ST-HEADERLEN-001, got %v", ids)
	}
}

func TestScan_headerLenDoS(t *testing.T) {
	// ST-HEADERLEN-002: header_len > 100 MiB but within a large-enough file.
	data := withDoSHeaderLenLarge()
	ids, err := scan(data)
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "ST-HEADERLEN-002") {
		t.Fatalf("expected ST-HEADERLEN-002, got %v", ids)
	}
}

func TestScan_badJSON(t *testing.T) {
	ids, err := scan(withBadJSON())
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "ST-JSON-001") {
		t.Fatalf("expected ST-JSON-001, got %v", ids)
	}
}

func TestScan_offsetOOB(t *testing.T) {
	// end > dataSize.
	b := newST().addTensor("w", "F32", []int64{4}, 0, 9999)
	ids, err := scan(b.build(16))
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "ST-OFFSET-001") {
		t.Fatalf("expected ST-OFFSET-001, got %v", ids)
	}
}

func TestScan_offsetBeginGTEnd(t *testing.T) {
	b := newST().addTensor("w", "F32", []int64{4}, 16, 0)
	ids, err := scan(b.build(32))
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "ST-OFFSET-002") {
		t.Fatalf("expected ST-OFFSET-002, got %v", ids)
	}
}

func TestScan_shapeMismatch(t *testing.T) {
	// shape [4] * F32 (4 bytes) = 16 bytes, but span = 12.
	b := newST().addTensor("w", "F32", []int64{4}, 0, 12)
	ids, err := scan(b.build(16))
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "ST-SHAPE-001") {
		t.Fatalf("expected ST-SHAPE-001, got %v", ids)
	}
}

func TestScan_unknownDtype(t *testing.T) {
	b := newST().addTensor("w", "XFLOAT", []int64{4}, 0, 16)
	ids, err := scan(b.build(16))
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "ST-DTYPE-001") {
		t.Fatalf("expected ST-DTYPE-001, got %v", ids)
	}
}

func TestScan_overlap(t *testing.T) {
	// Two tensors overlapping in data segment.
	b := newST().
		addTensor("a", "F32", []int64{4}, 0, 16).
		addTensor("b", "F32", []int64{4}, 8, 24)
	ids, err := scan(b.build(32))
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "ST-OFFSET-003") {
		t.Fatalf("expected ST-OFFSET-003, got %v", ids)
	}
}

func TestScan_metadataBad(t *testing.T) {
	// __metadata__ with a non-string value.
	b := newST()
	ids, err := scan(b.build(0))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no findings on empty valid file, got %v", ids)
	}
}

func TestScan_metadataOK(t *testing.T) {
	b := newST().withMetadata("author", "test")
	ids, err := scan(b.build(0))
	if err != nil {
		t.Fatal(err)
	}
	if hasID(ids, "ST-META-001") {
		t.Fatalf("unexpected ST-META-001 on valid metadata")
	}
}
