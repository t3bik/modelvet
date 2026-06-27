package gguf_test

import (
	"bytes"
	"testing"

	"github.com/t3bik/modelvet/internal/gguf"
)

func scan(data []byte) ([]string, error) {
	s := gguf.New()
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
	b := newGGUF()
	ids, err := scan(b.build())
	if err != nil {
		t.Fatalf("unexpected error on valid GGUF: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no findings on valid GGUF, got %v", ids)
	}
}

func TestScan_badMagic(t *testing.T) {
	ids, err := scan(newGGUF().withBadMagic())
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "GGUF-MAGIC-001") {
		t.Fatalf("expected GGUF-MAGIC-001, got %v", ids)
	}
}

func TestScan_badVersion(t *testing.T) {
	ids, err := scan(newGGUF().withVersion(99))
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "GGUF-VERSION-001") {
		t.Fatalf("expected GGUF-VERSION-001, got %v", ids)
	}
}

func TestScan_kvTypeConfusion(t *testing.T) {
	// Type code 99 is outside the valid 0–12 enum.
	ids, err := scan(newGGUF().withKVType(99))
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "GGUF-KV-TYPE-001") {
		t.Fatalf("expected GGUF-KV-TYPE-001, got %v", ids)
	}
}

func TestScan_kvTypeValidBoundary(t *testing.T) {
	// Type 12 is the last valid code; should not produce a type-confusion finding.
	// Use type 7 (BOOL) with value 0x00 for simplicity as the valid case.
	b := newGGUF()
	b.kvs = []ggufKV{{key: "k", kvType: 7, val: []byte{0x00}}}
	ids, err := scan(b.build())
	if err != nil {
		t.Fatal(err)
	}
	if hasID(ids, "GGUF-KV-TYPE-001") {
		t.Fatalf("unexpected GGUF-KV-TYPE-001 on type 7 (BOOL): %v", ids)
	}
}

func TestScan_hugeKVCount(t *testing.T) {
	ids, err := scan(newGGUF().withHugeKVCount(^uint64(0)))
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "GGUF-COUNT-001") {
		t.Fatalf("expected GGUF-COUNT-001, got %v", ids)
	}
}

func TestScan_hugeTensorCount(t *testing.T) {
	ids, err := scan(newGGUF().withHugeTensorCount(^uint64(0)))
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "GGUF-COUNT-001") {
		t.Fatalf("expected GGUF-COUNT-001, got %v", ids)
	}
}

func TestScan_absurdNDims(t *testing.T) {
	ids, err := scan(newGGUF().withNDims(9))
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "GGUF-NDIMS-001") {
		t.Fatalf("expected GGUF-NDIMS-001, got %v", ids)
	}
}

func TestScan_dimOverflow(t *testing.T) {
	ids, err := scan(newGGUF().withDimOverflow())
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "GGUF-DIMOVF-001") {
		t.Fatalf("expected GGUF-DIMOVF-001, got %v", ids)
	}
}

func TestScan_offsetPastEOF(t *testing.T) {
	ids, err := scan(newGGUF().withOffsetPastEOF())
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "GGUF-OFFSET-001") {
		t.Fatalf("expected GGUF-OFFSET-001, got %v", ids)
	}
}

func TestScan_dupKey(t *testing.T) {
	ids, err := scan(newGGUF().withDupKey())
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "GGUF-KV-DUP-001") {
		t.Fatalf("expected GGUF-KV-DUP-001, got %v", ids)
	}
}

func TestScan_hugeString(t *testing.T) {
	ids, err := scan(newGGUF().withHugeString())
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(ids, "GGUF-STRLEN-001") {
		t.Fatalf("expected GGUF-STRLEN-001, got %v", ids)
	}
}

func TestScan_truncated(t *testing.T) {
	// Truncate mid-header: 10 bytes has magic+version but not the full 24-byte fixed header.
	// The scanner must either return an error or a GGUF-TRUNC-001 finding.
	raw := newGGUF().build()
	truncated := raw[:10]
	ids, err := scan(truncated)
	if err != nil {
		// Truncated-below-minimum returns an error, which is acceptable.
		return
	}
	if !hasID(ids, "GGUF-TRUNC-001") {
		t.Fatalf("expected GGUF-TRUNC-001 or error on truncated GGUF (10 bytes), got ids=%v", ids)
	}
}

func TestScan_tinyFile(t *testing.T) {
	_, err := scan([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error on 2-byte file")
	}
}

func TestValidKVType_boundary(t *testing.T) {
	// 0 and 12 are valid; 13 and max are not.
	for _, tc := range []struct {
		code  uint32
		valid bool
	}{
		{0, true},
		{12, true},
		{13, false},
		{^uint32(0), false},
	} {
		raw := newGGUF().withKVType(tc.code)
		ids, err := scan(raw)
		if err != nil {
			continue // file may be too small/invalid; skip
		}
		gotConfusion := hasID(ids, "GGUF-KV-TYPE-001")
		if tc.valid && gotConfusion {
			t.Errorf("type %d: unexpected GGUF-KV-TYPE-001", tc.code)
		}
		if !tc.valid && !gotConfusion {
			t.Errorf("type %d: expected GGUF-KV-TYPE-001 but not found", tc.code)
		}
	}
}
