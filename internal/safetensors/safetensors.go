// Package safetensors implements a static security scanner for safetensors
// model files. It reads the 8-byte header-length prefix and validates the JSON
// header without loading or executing any model data.
package safetensors

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/t3bik/modelvet/internal/finding"
	"github.com/t3bik/modelvet/internal/safeio"
)

const (
	// headerCap is the maximum JSON header length we will allocate/parse.
	// Above this we flag ST-HEADERLEN-002 and stop. (100 MiB)
	headerCap = 100 << 20

	// maxAllocBytes caps any single read through safeio.
	maxAllocBytes = 256 << 20
)

// knownDtypes maps safetensors dtype strings to their element byte size.
// Unknown dtypes are flagged as ST-DTYPE-001.
var knownDtypes = map[string]int64{
	"F64":  8,
	"F32":  4,
	"F16":  2,
	"BF16": 2,
	"I64":  8,
	"I32":  4,
	"I16":  2,
	"I8":   1,
	"U8":   1,
	"BOOL": 1,
}

// Scanner implements scan.Scanner for safetensors files.
type Scanner struct{}

// New returns a new safetensors Scanner.
func New() *Scanner { return &Scanner{} }

// Format returns the format this scanner handles.
func (s *Scanner) Format() finding.Format { return finding.FormatSafetensors }

// Scan inspects the safetensors artifact and returns all findings.
func (s *Scanner) Scan(ra io.ReaderAt, size int64) ([]finding.Finding, error) {
	if size < 8 {
		return nil, fmt.Errorf("safetensors: file too small (%d bytes)", size)
	}

	r := safeio.NewReader(ra, size, maxAllocBytes)
	var findings []finding.Finding

	// ── 1. Header length ──────────────────────────────────────────────────────
	headerLen, err := r.U64(0)
	if err != nil {
		return nil, fmt.Errorf("safetensors: read header_len: %w", err)
	}

	// ST-HEADERLEN-001: header claims more bytes than exist after the prefix.
	if headerLen > uint64(size)-8 {
		findings = append(findings, finding.New("ST-HEADERLEN-001", 0,
			fmt.Sprintf("header_len=%d > file_size-8=%d", headerLen, size-8)))
		return findings, nil
	}

	// ST-TRUNC-001: file shorter than 8+header_len.
	// Safe: headerLen already checked <= size-8 above, so no overflow.
	if int64(8)+int64(headerLen) > size { //nolint:gosec // G115: checked overflow at line 65
		findings = append(findings, finding.New("ST-TRUNC-001", 0,
			fmt.Sprintf("file too short: need %d bytes, have %d", 8+headerLen, size)))
		return findings, nil
	}

	// ST-HEADERLEN-002: implausibly large (DoS signal).
	if headerLen > headerCap {
		findings = append(findings, finding.New("ST-HEADERLEN-002", 0,
			fmt.Sprintf("header_len=%d exceeds 100 MiB DoS cap", headerLen)))
		return findings, nil
	}

	// ── 2. Read and parse the JSON header ─────────────────────────────────────
	headerBuf, err := r.Bytes(8, int64(headerLen))
	if err != nil {
		return nil, fmt.Errorf("safetensors: read header: %w", err)
	}

	// ST-JSON-001: first byte must be '{'.
	if len(headerBuf) == 0 || headerBuf[0] != '{' {
		findings = append(findings, finding.New("ST-JSON-001", 8,
			"header does not start with '{' — not a JSON object"))
		return findings, nil
	}

	var header map[string]json.RawMessage
	if err := json.Unmarshal(headerBuf, &header); err != nil {
		findings = append(findings, finding.New("ST-JSON-001", 8,
			fmt.Sprintf("JSON parse error: %v", err)))
		return findings, nil
	}

	// The data segment starts at offset 8+headerLen.
	dataStart := int64(8 + headerLen)
	dataSize := size - dataStart // total bytes in data segment

	// ── 3. Per-tensor checks ──────────────────────────────────────────────────
	type region struct {
		name  string
		begin int64
		end   int64
	}
	var regions []region

	for name, raw := range header {
		if name == "__metadata__" {
			// ST-META-001: __metadata__ must be a flat string→string map.
			findings = append(findings, checkMetadata(name, raw)...)
			continue
		}

		var entry struct {
			Dtype       string    `json:"dtype"`
			Shape       []int64   `json:"shape"`
			DataOffsets [2]int64  `json:"data_offsets"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			findings = append(findings, finding.New("ST-JSON-001", 8,
				fmt.Sprintf("tensor %q: malformed entry: %v", name, err)))
			continue
		}

		begin := entry.DataOffsets[0]
		end := entry.DataOffsets[1]

		// ST-OFFSET-002: begin > end or negative.
		if begin < 0 || end < 0 || begin > end {
			findings = append(findings, finding.New("ST-OFFSET-002", 8,
				fmt.Sprintf("tensor %q: begin=%d end=%d (begin>end or negative)", name, begin, end)))
			continue
		}

		// ST-OFFSET-001: end beyond data segment.
		if end > dataSize {
			findings = append(findings, finding.New("ST-OFFSET-001", 8,
				fmt.Sprintf("tensor %q: data_offsets[1]=%d > data_size=%d (OOB)", name, end, dataSize)))
			continue
		}

		regions = append(regions, region{name: name, begin: begin, end: end})

		// ST-DTYPE-001: unknown dtype.
		dtypeSize, dtypeKnown := knownDtypes[strings.ToUpper(entry.Dtype)]
		if !dtypeKnown {
			findings = append(findings, finding.New("ST-DTYPE-001", 8,
				fmt.Sprintf("tensor %q: unknown dtype %q", name, entry.Dtype)))
			// Continue; we cannot compute shape check without dtype size.
			continue
		}

		// ST-SHAPE-001: product(shape) * dtype_size must equal end-begin.
		span := end - begin
		if mismatch, f := checkShapeSize(name, entry.Shape, dtypeSize, span); mismatch {
			findings = append(findings, f)
		}
	}

	// ── 4. Overlap check ──────────────────────────────────────────────────────
	for i := 0; i < len(regions); i++ {
		for j := i + 1; j < len(regions); j++ {
			a, b := regions[i], regions[j]
			if a.begin < b.end && b.begin < a.end {
				findings = append(findings, finding.New("ST-OFFSET-003", 8,
					fmt.Sprintf("tensors %q and %q have overlapping data ranges", a.name, b.name)))
			}
		}
	}

	return findings, nil
}

// checkShapeSize verifies product(shape)*dtypeSize == span.
// Returns (true, finding) on mismatch; (false, zero) otherwise.
func checkShapeSize(name string, shape []int64, dtypeSize, span int64) (bool, finding.Finding) {
	if dtypeSize <= 0 {
		return false, finding.Finding{}
	}
	// Compute product with overflow guard.
	var prod int64 = 1
	for _, d := range shape {
		if d < 0 {
			return true, finding.New("ST-SHAPE-001", 8,
				fmt.Sprintf("tensor %q: negative dimension %d", name, d))
		}
		// Overflow-safe multiply: if prod * d would exceed maxInt64, flag.
		if d != 0 && prod > maxI64/d {
			return true, finding.New("ST-SHAPE-001", 8,
				fmt.Sprintf("tensor %q: shape product overflows int64", name))
		}
		prod *= d
	}
	// prod * dtypeSize
	if prod != 0 && prod > maxI64/dtypeSize {
		return true, finding.New("ST-SHAPE-001", 8,
			fmt.Sprintf("tensor %q: shape*dtype product overflows int64", name))
	}
	expected := prod * dtypeSize
	if expected != span {
		return true, finding.New("ST-SHAPE-001", 8,
			fmt.Sprintf("tensor %q: expected %d bytes (shape×dtype), got span %d", name, expected, span))
	}
	return false, finding.Finding{}
}

const maxI64 = int64(^uint64(0) >> 1)

// checkMetadata validates that __metadata__ is a flat string→string map.
func checkMetadata(name string, raw json.RawMessage) []finding.Finding {
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(raw, &meta); err != nil {
		return []finding.Finding{finding.New("ST-META-001", 8,
			"__metadata__ is not a JSON object")}
	}
	const maxValLen = 1 << 20 // 1 MiB per value is absurd for metadata
	for k, v := range meta {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return []finding.Finding{finding.New("ST-META-001", 8,
				fmt.Sprintf("__metadata__[%q] is not a string", k))}
		}
		if int64(len(s)) > maxValLen {
			return []finding.Finding{finding.New("ST-META-001", 8,
				fmt.Sprintf("__metadata__[%q] value length %d exceeds 1 MiB", k, len(s)))}
		}
	}
	return nil
}
