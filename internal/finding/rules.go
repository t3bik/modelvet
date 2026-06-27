package finding

import "fmt"

// Rule is the canonical metadata for one detection rule.
type Rule struct {
	ID          string
	Severity    Severity
	Title       string
	Remediation string
}

// Catalog is the authoritative rule registry. Package-level, read-only after
// init. Every ID referenced in scanner code must appear here; the
// finding_test.go integrity test enforces this.
var Catalog = map[string]Rule{
	// ── GGUF rules ────────────────────────────────────────────────────────────
	"GGUF-MAGIC-001": {
		ID:          "GGUF-MAGIC-001",
		Severity:    High,
		Title:       "Invalid GGUF magic bytes",
		Remediation: "Verify the file is a genuine GGUF artifact. Do not load in llama.cpp or any GGUF-aware parser.",
	},
	"GGUF-VERSION-001": {
		ID:          "GGUF-VERSION-001",
		Severity:    Medium,
		Title:       "Unknown GGUF version field",
		Remediation: "Accepted GGUF versions are 1, 2, and 3. Reject or quarantine files with other version values.",
	},
	"GGUF-KV-TYPE-001": {
		ID:          "GGUF-KV-TYPE-001",
		Severity:    Critical,
		Title:       "KV value-type code outside valid ggml enum (type-confusion)",
		Remediation: "A metadata KV entry claims a type code not in the ggml_metadata_value_type enum (0–12). A parser that trusts it will perform a type-confused read. Reject this file immediately.",
	},
	"GGUF-KV-DUP-001": {
		ID:          "GGUF-KV-DUP-001",
		Severity:    Medium,
		Title:       "Duplicate metadata key",
		Remediation: "Duplicate keys cause ambiguity: some loaders take the first value, others the last. Reject or deduplicate before loading.",
	},
	"GGUF-STRLEN-001": {
		ID:          "GGUF-STRLEN-001",
		Severity:    High,
		Title:       "String length field exceeds remaining file size",
		Remediation: "A declared string or key length points beyond the file boundary. Reject the file; a parser that follows the length will read out of bounds.",
	},
	"GGUF-STRLEN-002": {
		ID:          "GGUF-STRLEN-002",
		Severity:    Medium,
		Title:       "Implausibly large string (DoS signal)",
		Remediation: "A single string length exceeds 64 MiB. This is a denial-of-service signal. Reject or cap string reads before processing.",
	},
	"GGUF-COUNT-001": {
		ID:          "GGUF-COUNT-001",
		Severity:    High,
		Title:       "tensor_count or metadata_kv_count cannot fit in file",
		Remediation: "The declared count implies more data than the file contains. Reject the file; a parser trusting the count will loop out of bounds.",
	},
	"GGUF-NDIMS-001": {
		ID:          "GGUF-NDIMS-001",
		Severity:    High,
		Title:       "Tensor n_dims exceeds GGML_MAX_DIMS (8)",
		Remediation: "llama.cpp defines GGML_MAX_DIMS=8. An n_dims beyond this will over-read the dims array. Reject the file.",
	},
	"GGUF-DIMOVF-001": {
		ID:          "GGUF-DIMOVF-001",
		Severity:    High,
		Title:       "Tensor dimension product overflows uint64",
		Remediation: "The product of the tensor dimensions overflows a 64-bit integer, causing an incorrect tensor-size computation. Reject the file.",
	},
	"GGUF-TTYPE-001": {
		ID:          "GGUF-TTYPE-001",
		Severity:    Medium,
		Title:       "Tensor ggml_type outside known enum",
		Remediation: "The tensor type code is not in the known ggml_type enum. A parser may mis-compute block sizes. Reject or quarantine.",
	},
	"GGUF-OFFSET-001": {
		ID:          "GGUF-OFFSET-001",
		Severity:    Critical,
		Title:       "Tensor data extends beyond file size (OOB read)",
		Remediation: "offset + computed_size exceeds the file boundary. Any attempt to mmap or read the tensor data is an out-of-bounds memory access. Reject the file.",
	},
	"GGUF-OFFSET-002": {
		ID:          "GGUF-OFFSET-002",
		Severity:    Medium,
		Title:       "Tensor data regions overlap",
		Remediation: "Two or more tensors claim the same byte range. This indicates a forged or corrupt file. Review before loading.",
	},
	"GGUF-TRUNC-001": {
		ID:          "GGUF-TRUNC-001",
		Severity:    High,
		Title:       "File truncated before header is complete",
		Remediation: "The file ends before the declared KV/tensor table is fully present. Reject; the file is incomplete or forged.",
	},
	"GGUF-ARRAY-DEPTH-001": {
		ID:          "GGUF-ARRAY-DEPTH-001",
		Severity:    High,
		Title:       "Metadata array nested beyond maximum depth",
		Remediation: "A KV metadata array has nesting depth exceeding the safe limit. Legitimate GGUF arrays are never deeply nested; this is a crafted input designed to exhaust stack space. Reject the file.",
	},

	// ── safetensors rules ─────────────────────────────────────────────────────
	"ST-HEADERLEN-001": {
		ID:          "ST-HEADERLEN-001",
		Severity:    High,
		Title:       "Header length exceeds file size",
		Remediation: "header_len > file_size - 8: the declared JSON header extends beyond the file. Reject immediately.",
	},
	"ST-HEADERLEN-002": {
		ID:          "ST-HEADERLEN-002",
		Severity:    Medium,
		Title:       "Implausibly large header length (DoS signal)",
		Remediation: "header_len > 100 MiB. This is a denial-of-service signal. Reject or cap before parsing.",
	},
	"ST-JSON-001": {
		ID:          "ST-JSON-001",
		Severity:    Medium,
		Title:       "Header is not valid JSON or not an object",
		Remediation: "The safetensors JSON header is malformed. Reject the file.",
	},
	"ST-OFFSET-001": {
		ID:          "ST-OFFSET-001",
		Severity:    Critical,
		Title:       "Tensor data_offsets extends beyond data segment (OOB)",
		Remediation: "A tensor's [begin,end] extends outside the data segment. Reading it is an out-of-bounds access. Reject the file.",
	},
	"ST-OFFSET-002": {
		ID:          "ST-OFFSET-002",
		Severity:    High,
		Title:       "Malformed tensor offsets (begin > end or negative)",
		Remediation: "begin > end, or a negative offset — malformed or forged. Reject the file.",
	},
	"ST-OFFSET-003": {
		ID:          "ST-OFFSET-003",
		Severity:    Medium,
		Title:       "Tensor data regions overlap",
		Remediation: "Two tensors share byte ranges in the data segment. This is a forged or corrupt file.",
	},
	"ST-SHAPE-001": {
		ID:          "ST-SHAPE-001",
		Severity:    High,
		Title:       "Declared shape×dtype size does not match data_offsets span",
		Remediation: "product(shape) * sizeof(dtype) != end - begin. A size/shape mismatch can cause type-confused memory access. Reject.",
	},
	"ST-DTYPE-001": {
		ID:          "ST-DTYPE-001",
		Severity:    Medium,
		Title:       "Unknown dtype in safetensors header",
		Remediation: "The dtype string is not in the known safetensors set. Parsers may mis-compute element size. Review before loading.",
	},
	"ST-META-001": {
		ID:          "ST-META-001",
		Severity:    Low,
		Title:       "Malformed or oversized __metadata__ object",
		Remediation: "__metadata__ should be a flat string→string map. Unusual values may confuse tooling.",
	},
	"ST-TRUNC-001": {
		ID:          "ST-TRUNC-001",
		Severity:    High,
		Title:       "File shorter than 8 + header_len (truncated)",
		Remediation: "The file is too short to contain the declared header. Reject; incomplete or corrupt.",
	},

	// ── pickle rules ──────────────────────────────────────────────────────────
	"PKL-GLOBAL-001": {
		ID:          "PKL-GLOBAL-001",
		Severity:    Critical,
		Title:       "GLOBAL/STACK_GLOBAL references known code-execution module",
		Remediation: "The pickle references a dangerous module (os, subprocess, builtins, etc.). Unpickling this file may execute arbitrary code. Reject immediately.",
	},
	"PKL-GLOBAL-002": {
		ID:          "PKL-GLOBAL-002",
		Severity:    High,
		Title:       "GLOBAL/STACK_GLOBAL references capability-enabling module",
		Remediation: "The pickle references a watch-listed module. While not always malicious, this warrants human review before unpickling.",
	},
	"PKL-REDUCE-001": {
		ID:          "PKL-REDUCE-001",
		Severity:    High,
		Title:       "REDUCE opcode present alongside GLOBAL reference",
		Remediation: "REDUCE + GLOBAL is the standard RCE gadget shape in malicious pickles. Combined with a dangerous GLOBAL, this is a Critical-risk artifact.",
	},
	"PKL-INST-001": {
		ID:          "PKL-INST-001",
		Severity:    High,
		Title:       "INST/OBJ/NEWOBJ referencing a dangerous global",
		Remediation: "Alternate construction-time execution paths that can call arbitrary code. Reject the file.",
	},
	"PKL-PROTO-001": {
		ID:          "PKL-PROTO-001",
		Severity:    Low,
		Title:       "Unusual pickle protocol version",
		Remediation: "Pickle protocol 0–5 are known. An unusual version may indicate a crafted stream.",
	},
	"PKL-TRUNC-001": {
		ID:          "PKL-TRUNC-001",
		Severity:    Medium,
		Title:       "Pickle stream ends without STOP opcode",
		Remediation: "A truncated or malformed opcode stream. May be evasive or corrupt.",
	},
	"PKL-OPAQUE-001": {
		ID:          "PKL-OPAQUE-001",
		Severity:    Low,
		Title:       "Unrecognised opcode byte",
		Remediation: "An unknown opcode was encountered. This may be crafted to confuse static scanners. Stop walking and review.",
	},
	"PKL-ZIP-001": {
		ID:          "PKL-ZIP-001",
		Severity:    Medium,
		Title:       "Zip container exceeds entry/size caps or suspicious compression ratio",
		Remediation: "The PyTorch zip container has unusual properties (too many entries, high compression ratio). Possible zip-bomb. Reject.",
	},
	"PKL-ZIP-002": {
		ID:          "PKL-ZIP-002",
		Severity:    Low,
		Title:       "Zip container claims to be a model but contains no data.pkl entry",
		Remediation: "A PK-magic (zip) file with a model extension contains no data.pkl entry. This may indicate a misidentified file, an empty container, or a tampered archive.",
	},
}

// New builds a Finding from a catalog rule + per-occurrence detail/offset.
// It panics on an unknown rule ID — this is a programming error caught in
// tests, never reachable from file input.
func New(ruleID string, offset int64, detail string) Finding {
	rule, ok := Catalog[ruleID]
	if !ok {
		panic(fmt.Sprintf("finding.New: unknown rule ID %q — add it to Catalog", ruleID))
	}
	return Finding{
		RuleID:      rule.ID,
		Severity:    rule.Severity,
		Format:      formatForID(ruleID),
		Offset:      offset,
		Detail:      detail,
		Remediation: rule.Remediation,
	}
}

// formatForID derives the Format from the rule ID prefix.
func formatForID(id string) Format {
	switch {
	case len(id) > 4 && id[:5] == "GGUF-":
		return FormatGGUF
	case len(id) > 2 && id[:3] == "ST-":
		return FormatSafetensors
	case len(id) > 3 && id[:4] == "PKL-":
		return FormatPickle
	default:
		return FormatUnknown
	}
}
