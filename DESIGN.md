# modelvet — Design

A static security scanner for machine-learning model artifacts. `modelvet`
inspects GGUF, safetensors, and Python pickle model files for supply-chain and
malicious-artifact risks **without ever loading, unpickling, or executing them**.
This document gives a developer everything needed to implement `modelvet`
directly, idiomatically, and with no rework.

- **Module:** `github.com/t3bik/modelvet`
- **Go:** 1.24
- **Binary:** `modelvet`
- **Scope:** Pure static analysis of file bytes. No model load, no Python, no
  unpickling, no network. The tool reads a file and emits findings. That is the
  entire trust boundary — and keeping it that small is itself the headline
  security property.

> **Origin.** This tool is the productized, general form of a real
> responsible-disclosure finding: a type-confusion vulnerability in llama.cpp's
> GGUF metadata parsing (a KV value-type code outside the valid enum, leading to
> mis-typed reads). `modelvet` detects that class of bug — and its siblings —
> across the three dominant model-serialization formats.

---

## 1. Design principles

- **Safety against hostile input is the product.** Every file `modelvet` reads
  is assumed malicious. The scanner must never crash, never OOM, never block
  unboundedly, and never execute attacker-controlled logic. This is not a
  side-concern bolted on at the end; it shapes every parser API (§6).
- **Never trust a length field before validating it.** All formats here are
  length-prefixed. The cardinal rule: **validate every count/length/offset
  against the real file size before allocating or reading.** Reject absurd
  values with a finding instead of allocating to satisfy them (§6).
- **Stdlib first.** Parsing, ZIP handling, JSON, hashing, and output all use the
  standard library. The design targets **zero third-party runtime
  dependencies**; one optional test-only dependency is justified in §11.
  A small dependency set directly shrinks the `govulncheck`/`gosec` surface.
- **Pure, side-effect-free parsers.** Each format scanner is a pure function of
  `(bytes, size) -> ([]Finding, error)`. No globals, no I/O beyond the supplied
  reader, no clock, no randomness. Trivially table-testable and fuzzable from
  in-test byte fixtures.
- **`io.ReaderAt` + bounded reads, never `io.ReadAll`.** Parsers read exactly
  the bytes they need at known offsets, each read capped. No parser ever slurps
  a whole file into memory (§6).
- **No global mutable state.** All configuration passes explicitly via structs;
  the only package-level vars are sentinel errors and static rule/enum tables.
- **No panics in library code.** `internal/...` packages return wrapped errors.
  A `recover` guard wraps each scanner as defense-in-depth (§6.5), but the
  parsers are written so it never fires. Only `cmd/modelvet` may call `os.Exit`.
- **CI-native UX.** Human report by default, `--format json|sarif` for tooling,
  and a non-zero exit when HIGH/CRITICAL findings exist so a CI job fails loudly.

---

## 2. Package layout

```
modelvet/
├── go.mod                          # module github.com/t3bik/modelvet, go 1.24
├── go.sum                          # empty / x-only; no runtime deps
├── README.md                       # what it does, install, examples, the "no-load" guarantee
├── LICENSE                         # MIT
├── Makefile                        # build, test -race -cover, vet, gosec, govulncheck, fuzz
├── .goreleaser.yaml                # cross-build + Homebrew tap (see §10)
├── .github/
│   └── workflows/
│       ├── ci.yml                  # build + vet + test -race + govulncheck + gosec
│       └── release.yml             # goreleaser on tag push
│
├── cmd/
│   └── modelvet/
│       └── main.go                 # the ONLY package that may os.Exit; flags + glue
│
├── internal/
│   ├── finding/
│   │   ├── finding.go              # Finding, Severity, Format types (shared vocabulary)
│   │   ├── rules.go                # the canonical rule catalog: ID -> {severity, title, hint}
│   │   └── finding_test.go         # Severity ordering, String(), rule-catalog integrity
│   │
│   ├── safeio/
│   │   ├── safeio.go               # bounded-read helpers over io.ReaderAt (the safety core)
│   │   └── safeio_test.go          # cap enforcement, EOF/truncation, overflow guards
│   │
│   ├── gguf/
│   │   ├── gguf.go                 # Scanner: GGUF parse + detection rules
│   │   ├── types.go                # ggml type enum + GGUF KV value-type enum (data + validity)
│   │   ├── gguf_test.go            # table tests over crafted fixtures
│   │   ├── fixtures_test.go        # in-test GGUF byte-builder (valid + each malformed variant)
│   │   └── fuzz_test.go            # FuzzScanGGUF
│   │
│   ├── safetensors/
│   │   ├── safetensors.go          # Scanner: 8-byte len + JSON header + bounds rules
│   │   ├── safetensors_test.go     # table tests over crafted fixtures
│   │   ├── fixtures_test.go        # in-test safetensors byte-builder
│   │   └── fuzz_test.go            # FuzzScanSafetensors
│   │
│   ├── pickle/
│   │   ├── pickle.go               # Scanner: static opcode walk (NO unpickling)
│   │   ├── opcodes.go              # pickle opcode table (byte -> {name, argkind}) — data
│   │   ├── dangerous.go            # dangerous module/callable allow/deny tables — data
│   │   ├── zip.go                  # detect+enter PyTorch zip container, find data.pkl entries
│   │   ├── pickle_test.go          # benign vs malicious opcode-stream table tests
│   │   ├── fixtures_test.go        # in-test pickle + zip-of-pickle byte-builder
│   │   └── fuzz_test.go            # FuzzScanPickle (opcode walker robustness)
│   │
│   ├── scan/
│   │   ├── scan.go                 # orchestrator: detect format, dispatch, walk dirs
│   │   ├── detect.go               # format detection by magic bytes + extension
│   │   ├── scanner.go              # Scanner interface (the seam every format implements)
│   │   ├── scan_test.go            # detection + dispatch + dir-walk + recover-guard tests
│   │   └── detect_test.go          # magic/extension precedence table tests
│   │
│   └── report/
│       ├── report.go               # Writer interface; NewWriter(format) factory
│       ├── human.go                # HumanWriter (severity-tagged text, default)
│       ├── json.go                 # JSONWriter (encoding/json)
│       ├── sarif.go                # SARIFWriter (GitHub code-scanning schema)
│       └── report_test.go          # golden output per format; exit-code helper
```

**Dependency direction (one-way, no cycles):**

```
cmd/modelvet   ->  scan, report, finding
scan           ->  gguf, safetensors, pickle, finding, safeio
gguf           ->  finding, safeio
safetensors    ->  finding, safeio
pickle         ->  finding, safeio
report         ->  finding
finding        ->  (std only)
safeio         ->  (std only)
```

`finding` is the leaf vocabulary package everyone shares (no imports of its
own). `safeio` is the leaf safety package (std only). Format scanners depend
**only** on `finding` + `safeio` — they know nothing of `scan` or `report`.
`scan` is the composition point that detects format and dispatches; `report`
renders `finding.Finding`s. `cmd/modelvet` is the composition root: parse flags,
walk paths via `scan`, pipe findings to a `report.Writer`, compute exit code.

This is the exact same shape as the sibling `gorecon`: a leaf domain type, leaf
infrastructure helpers, independent feature packages, an orchestrator, and a
thin command. Reviewers see one coherent house style across the portfolio.

---

## 3. Core types & interfaces

### 3.1 `internal/finding` — the shared vocabulary

```go
// Severity orders findings from informational to critical. Ordered so that
// comparisons (>=) work for --min-severity filtering and exit-code decisions.
type Severity int

const (
    Info Severity = iota // observational; not a risk by itself
    Low                  // hygiene / minor robustness issue
    Medium               // suspicious; warrants review
    High                 // likely-exploitable or strong malicious signal
    Critical             // code-execution gadget or memory-safety break
)

func (s Severity) String() string          // "INFO".."CRITICAL"
func ParseSeverity(string) (Severity, error) // for --min-severity; ErrBadSeverity

// Format identifies which artifact format produced a finding.
type Format string

const (
    FormatGGUF        Format = "gguf"
    FormatSafetensors Format = "safetensors"
    FormatPickle      Format = "pickle"
    FormatUnknown     Format = "unknown"
)

// Finding is one detected issue. Value type, immutable once produced, and
// designed to marshal cleanly to JSON and map onto SARIF without custom code.
type Finding struct {
    RuleID      string   `json:"rule_id"`     // stable ID, e.g. "GGUF-KV-TYPE-001"
    Severity    Severity `json:"severity"`    // marshals via String() (see note)
    Format      Format   `json:"format"`      // which scanner produced it
    Path        string   `json:"path"`        // file path (set by orchestrator)
    Offset      int64    `json:"offset"`      // byte offset of the issue; -1 if N/A
    Detail      string   `json:"detail"`      // short, specific human description
    Remediation string   `json:"remediation"` // what the user should do about it
}
```

Notes:
- `Severity` marshals as its string form via a `MarshalJSON` (and SARIF maps it
  to `error`/`warning`/`note`). The numeric ordering stays internal.
- `Path` is **not** known to the format scanners — they receive bytes, not
  paths. The orchestrator stamps `Path` onto each returned finding. This keeps
  the scanners pure and path-agnostic (and trivially testable).
- `Offset` is the byte position the developer should anchor each finding to
  (e.g. the offset of the bad type code, the header-length field, the opcode).
  `-1` means "whole file / no meaningful offset."

```go
// rules.go — the canonical catalog. A finding is constructed FROM a rule so
// severity/title/remediation stay consistent and centrally reviewable.
type Rule struct {
    ID          string
    Severity    Severity
    Title       string
    Remediation string
}

// Catalog maps RuleID -> Rule. Package-level, read-only after init.
var Catalog = map[string]Rule{ /* every rule from §5 */ }

// New builds a Finding from a catalog rule + per-occurrence detail/offset.
// Panics ONLY on an unknown rule ID — a programming error caught in tests,
// never reachable from input. (This is the one allowed panic, and it lives in
// a constructor exercised by a catalog-integrity test.)
func New(ruleID string, offset int64, detail string) Finding
```

A `finding_test.go` integrity test asserts: every ID referenced anywhere in the
codebase exists in `Catalog`, every `Catalog` entry has a non-empty title and
remediation, and IDs are unique. This makes the rule set a reviewable artifact.

### 3.2 `internal/safeio` — the bounded-read safety core

This tiny package is where "don't trust length fields" is enforced once, so the
three parsers don't each re-implement (and mis-implement) it.

```go
// Reader wraps an io.ReaderAt with a known total Size and a hard cap on any
// single allocation. Every read is bounds-checked against Size; every
// allocation is checked against MaxAlloc BEFORE it happens.
type Reader struct {
    ra      io.ReaderAt
    size    int64
    maxAlloc int64 // largest single []byte we will ever allocate
}

func NewReader(ra io.ReaderAt, size int64, maxAlloc int64) *Reader

func (r *Reader) Size() int64

// ReadAt reads exactly len(p) bytes at off, erroring if [off,off+len(p)) is not
// fully within [0,Size). Never short-reads silently.
func (r *Reader) ReadAt(p []byte, off int64) error

// Bytes allocates and returns n bytes at off. Guards:
//   - n < 0                         -> ErrNegativeLength
//   - n > maxAlloc                  -> ErrAllocTooLarge   (refuse BEFORE alloc)
//   - off < 0 || off+n > Size       -> ErrOutOfBounds     (overflow-safe check)
// Only after all guards pass is make([]byte, n) called.
func (r *Reader) Bytes(off, n int64) ([]byte, error)

// U32 / U64 read fixed-width little-endian integers with bounds checks.
func (r *Reader) U32(off int64) (uint32, error)
func (r *Reader) U64(off int64) (uint64, error)

var (
    ErrOutOfBounds    = errors.New("safeio: read out of bounds")
    ErrNegativeLength = errors.New("safeio: negative length")
    ErrAllocTooLarge  = errors.New("safeio: allocation exceeds cap")
    ErrTruncated      = errors.New("safeio: unexpected end of data")
)
```

The **overflow-safe bounds check** is the crux. Never write `off+n > size`
directly (it can overflow `int64`). Instead:

```go
if off < 0 || n < 0 || off > size || n > size-off { return ErrOutOfBounds }
```

`n > size-off` cannot overflow because `off <= size` is already established.
This single helper, unit-tested against overflow inputs, is what makes every
downstream parser safe by construction.

### 3.3 `internal/scan` — the Scanner seam + orchestrator

```go
// Scanner is the consumer-side interface each format implements. It is given a
// random-access view of the file and its size, and returns findings. It must
// NOT retain the reader, spawn goroutines, or read beyond what it needs.
//
// The signature is (io.ReaderAt, size) rather than (io.Reader) on purpose:
// these formats are offset-indexed (tensor offsets, header lengths), so random
// access is natural and lets the parser read only the slices it needs.
type Scanner interface {
    // Scan inspects the artifact and returns findings (possibly empty).
    // A returned error means the scanner could not run at all (e.g. truncated
    // below the minimum header); detected risks are Findings, NOT errors.
    Scan(ra io.ReaderAt, size int64) ([]finding.Finding, error)
    Format() finding.Format
}
```

The split between *error* and *Finding* is deliberate and consistent across all
three scanners:
- **Finding** = "I parsed this and it looks dangerous/malformed." (the product)
- **error**  = "I could not even begin (not this format / truncated header)."

A file that is *malformed in an interesting way* (bad enum, OOB offset) yields
**Findings**, not an error — that is the whole point of the tool.

```go
// detect.go
type DetectedFormat struct {
    Format finding.Format
    // Confidence: Magic (bytes matched) outranks Extension (name only).
    ByMagic bool
}

// Detect peeks the leading magic bytes and the filename extension to choose a
// scanner. Magic wins over extension; extension breaks ties / handles pickle
// (which has weak magic). Returns FormatUnknown if nothing matches.
func Detect(ra io.ReaderAt, size int64, filename string) DetectedFormat

// scan.go — the orchestrator.
type Options struct {
    MinSeverity finding.Severity
    Recurse     bool // walk directories
}

// Engine holds the registry of scanners. No mutable state between calls.
type Engine struct {
    scanners map[finding.Format]Scanner
}

func NewEngine() *Engine // wires gguf, safetensors, pickle scanners

// File scans a single file: open, detect, dispatch, stamp Path, filter by
// MinSeverity. Wrapped in the recover-guard. Returns findings for that file.
func (e *Engine) File(ctx context.Context, path string, opts Options) ([]finding.Finding, error)

// Walk scans a path that may be a file or a directory tree, honoring
// opts.Recurse. ctx cancellation stops the walk between files. Aggregates
// findings; per-file errors are collected, not fatal (see §7).
func (e *Engine) Walk(ctx context.Context, root string, opts Options) (Result, error)

// Result is the aggregate outcome of a Walk.
type Result struct {
    Findings []finding.Finding
    Errors   []FileError // per-file scan errors (non-fatal)
    Scanned  int         // files actually dispatched to a scanner
    Skipped  int         // files with FormatUnknown
}
```

`ctx` is the first parameter of `File`/`Walk` and is checked between files (the
per-file parse itself is bounded and fast, so we cancel at file granularity
rather than mid-parse — simpler and sufficient).

### 3.4 `internal/report` — output writers

```go
// Writer renders findings to an io.Writer. Consumer-side interface.
type Writer interface {
    Write(scan.Result) error // render the full result set
}

type Format string
const (
    FormatHuman Format = "human"
    FormatJSON  Format = "json"
    FormatSARIF Format = "sarif"
)

func NewWriter(format Format, w io.Writer) (Writer, error) // ErrUnknownFormat

var ErrUnknownFormat = errors.New("report: unknown output format")

// ExitCode maps a Result to a process exit code (pure; tested in isolation):
//   0  -> no findings at/above High
//   1  -> at least one High/Critical finding
//   2  -> reserved for usage/setup errors (set by cmd, not here)
func ExitCode(scan.Result) int
```

Notes:
- `Write` takes the whole `Result` (not per-finding streaming) because the
  output volume is small (one report per run) and SARIF needs the full set to
  build its `results` array and `rules` list. Simpler than a streaming writer
  and there is no latency concern — this is a batch tool, not a live scan.
- `HumanWriter` groups findings by file, sorts by severity descending, and tags
  each line `[CRITICAL] GGUF-KV-TYPE-001  offset=0x1a4  <detail>` plus a
  remediation line. It prints a final summary count per severity.
- `report` imports `scan` only for the `Result` type. `scan` does **not** import
  `report` — direction stays one-way.

---

## 4. Format detection (`scan/detect.go`)

| Format | Magic | Extensions | Notes |
|---|---|---|---|
| GGUF | first 4 bytes == `GGUF` (0x47 0x47 0x55 0x46) | `.gguf` | Strong magic; magic alone is sufficient. |
| safetensors | none reliable (starts with an 8-byte length, then `{`) | `.safetensors` | Heuristic: 8-byte LE length is sane (`<= size`) **and** byte 8 is `{`. Extension is the primary signal; the `{`-at-offset-8 check confirms. |
| pickle (raw) | first byte is `PROTO` opcode `0x80` followed by a version byte 1–5, **or** a classic opcode | `.pkl`, `.pickle`, `.bin`, `.pt`, `.pth` | Weak magic; extension drives detection, magic confirms. |
| pickle (zip) | first 2 bytes `PK` (0x50 0x4B), and the zip contains a `*/data.pkl` or `data.pkl` entry | `.pt`, `.pth`, `.bin`, `.zip` | PyTorch `torch.save` container. Detected as ZIP, then entered (§5.3). |

Precedence: **magic match wins**; if no magic matches, fall back to extension;
if neither, `FormatUnknown` (file is counted as Skipped, no error). A `.bin`
could be raw pickle or a zip-pickle — the `PK` magic disambiguates. This table
is the entirety of `detect.go` and is exhaustively table-tested.

---

## 5. Detection rules (the rule catalog)

Every rule has a **stable ID** (`<FORMAT>-<CATEGORY>-NNN`), a fixed severity, a
title, and a remediation hint, all centralized in `finding/rules.go` (§3.1).
Severities reflect exploitability: memory-safety breaks and code-exec gadgets
are Critical/High; malformations and hygiene are Medium/Low.

### 5.1 GGUF rules (`gguf/`)

GGUF layout parsed: `magic[4] | version u32 | tensor_count u64 | metadata_kv_count
u64 | metadata_kv[] | tensor_info[]`. Each KV is `key(len u64 + bytes) |
value_type u32 | value`. Each tensor_info is `name(len u64 + bytes) | n_dims u32
| dims[n_dims] u64 | ggml_type u32 | offset u64`.

| ID | Severity | Trigger |
|---|---|---|
| `GGUF-MAGIC-001` | High | Magic bytes are not `GGUF`. (Mis-detected or corrupt.) |
| `GGUF-VERSION-001` | Medium | `version` outside known set {1,2,3}. Future/forged. |
| `GGUF-KV-TYPE-001` | **Critical** | A metadata KV `value_type` code is **outside the valid ggml KV enum** (0–12). *This is the author's type-confusion class:* a parser that trusts it will read the wrong type. |
| `GGUF-KV-DUP-001` | Medium | Duplicate metadata key. Ambiguous; some loaders take first, some last. |
| `GGUF-STRLEN-001` | High | A string/key length field exceeds remaining file size (claims more bytes than exist → over-read). |
| `GGUF-STRLEN-002` | Medium | A string length is implausibly large but within file (e.g. > 64 MiB single string) → DoS/abuse signal. |
| `GGUF-COUNT-001` | High | `tensor_count` or `metadata_kv_count` so large that the declared structures cannot fit in `size` (overflow / truncation). |
| `GGUF-NDIMS-001` | High | `n_dims` absurd (e.g. > 8, llama.cpp's `GGML_MAX_DIMS`). Over-read of the dims array. |
| `GGUF-DIMOVF-001` | High | `product(dims)` overflows `uint64` (or exceeds a sane element cap) → integer-overflow in size computation. |
| `GGUF-TTYPE-001` | Medium | A tensor `ggml_type` code outside the known ggml type enum. |
| `GGUF-OFFSET-001` | **Critical** | Tensor `offset + computed_size` extends **beyond file size** → out-of-bounds read when the tensor data is accessed. |
| `GGUF-OFFSET-002` | Medium | Tensor data regions **overlap** (two tensors claim the same bytes). |
| `GGUF-TRUNC-001` | High | File ends before the declared header (KV/tensor table) is fully present. |

`gguf/types.go` holds the two enums as data: `validKVType(uint32) bool` (0–12)
and `validGGMLType(uint32) bool`, plus `ggmlTypeBlockSize`/`typeSize` tables
used to compute a tensor's byte size for the `GGUF-OFFSET-001` check. All pure
lookups, table-tested.

### 5.2 safetensors rules (`safetensors/`)

Layout: `header_len u64 LE | header JSON (header_len bytes) | tensor data`. The
JSON header maps each tensor name to `{dtype, shape:[...], data_offsets:[begin,
end]}`, plus an optional `__metadata__` object.

| ID | Severity | Trigger |
|---|---|---|
| `ST-HEADERLEN-001` | High | `header_len > size - 8` (header claims more bytes than the file holds → over-read). |
| `ST-HEADERLEN-002` | Medium | `header_len` implausibly large (e.g. > 100 MiB) though within file → header-DoS signal; refuse to fully parse, flag, stop. |
| `ST-JSON-001` | Medium | Header is not valid JSON, or top level is not an object. |
| `ST-OFFSET-001` | **Critical** | A tensor `data_offsets` `[begin,end]` falls outside the data segment `[0, size-8-header_len)` → OOB read. |
| `ST-OFFSET-002` | High | `begin > end`, or either is negative (JSON number < 0) → malformed/forged offsets. |
| `ST-OFFSET-003` | Medium | Two tensors' `[begin,end]` ranges **overlap**. |
| `ST-SHAPE-001` | High | `product(shape) * sizeof(dtype) != end - begin` → declared size/shape mismatch (classic confusion primitive). |
| `ST-DTYPE-001` | Medium | `dtype` not in the known safetensors set (`F64,F32,F16,BF16,I64..I8,U8,BOOL,…`). |
| `ST-META-001` | Low | `__metadata__` present but not an object of string→string, or contains absurdly large values. |
| `ST-TRUNC-001` | High | File shorter than `8 + header_len` → truncated header. |

`product(shape)` and `product(shape)*sizeof(dtype)` are computed with
**checked multiplication** (overflow → treat as `ST-SHAPE-001` / refuse),
reusing the same overflow discipline as `safeio`.

### 5.3 pickle rules (`pickle/`)

The pickle scanner is a **static opcode disassembler**. It walks the opcode
stream byte-by-byte using `opcodes.go` (opcode → name + argument kind), reading
each opcode's inline argument length to advance — but it **never builds the
object graph, never resolves a GLOBAL, never calls REDUCE**. It records which
`(module, name)` pairs appear via `GLOBAL` / `STACK_GLOBAL` and whether
reduction opcodes are present, then matches against the dangerous tables in
`dangerous.go`.

For the **zip container** (`zip.go`): open with `archive/zip` over the
`io.ReaderAt`, enumerate entries, and for each `*/data.pkl` (or `data.pkl`)
entry, open it through an `io.LimitedReader`-bounded path and run the same
opcode walk. Zip-bomb defenses in §6.4.

| ID | Severity | Trigger |
|---|---|---|
| `PKL-GLOBAL-001` | **Critical** | `GLOBAL`/`STACK_GLOBAL` references a known code-exec module (`os`, `posix`, `nt`, `subprocess`, `sys`, `runpy`, `builtins`, `__builtin__`, `importlib`, `pty`, `socket`, …) — e.g. `os.system`, `subprocess.Popen`, `builtins.exec/eval`. |
| `PKL-GLOBAL-002` | High | `GLOBAL`/`STACK_GLOBAL` references a module on the **watch** list (`shutil`, `pickle`, `webbrowser`, `base64`, `codecs`, `operator.attrgetter`, …) — capability-enabling but not always malicious. |
| `PKL-REDUCE-001` | High | A `REDUCE` opcode is present together with **any** GLOBAL — the standard RCE gadget shape (callable + args → call). Critical if the GLOBAL is on the deny list (reported as `PKL-GLOBAL-001` + this). |
| `PKL-INST-001` | High | `INST` / `OBJ` / `NEWOBJ` / `NEWOBJ_EX` referencing a dangerous global — alternate construction-time execution paths. |
| `PKL-PROTO-001` | Low | Pickle protocol version unusual/out of range (0–5). Informational signal. |
| `PKL-TRUNC-001` | Medium | Opcode stream ends without a `STOP`, or an opcode's declared arg length runs past EOF → malformed/evasive. |
| `PKL-OPAQUE-001` | Low | An unrecognized opcode byte encountered → possibly crafted to confuse naive scanners; flag and stop walking this stream. |
| `PKL-ZIP-001` | Medium | Zip container exceeds entry-count / total-uncompressed-size caps, or has a suspicious compression ratio (zip-bomb signal). |

`dangerous.go` keeps two **data-only** sets: `denyModules` (→ Critical) and
`watchModules` (→ High). Keeping them as reviewable tables (not regexes buried
in logic) is deliberate: a reviewer can audit exactly what is flagged.

---

## 6. Memory-safety / DoS-resistance strategy (concrete)

This section is the heart of the design — the property a BİLGEM reviewer will
look for first. Each parser handles **hostile** input.

### 6.1 One allocation guard, used everywhere
All variable-length reads go through `safeio.Reader.Bytes(off, n)`, which
refuses `n > maxAlloc` and `off+n > size` **before** `make`. No parser calls
`make([]byte, n)` on an attacker-controlled `n` directly. `maxAlloc` is a
`const` budget (e.g. 256 MiB) passed at `NewReader`.

### 6.2 Validate counts/lengths against real size before looping
Before iterating `metadata_kv_count` KV entries or `tensor_count` tensors, the
GGUF scanner checks that even the **minimum** encoding of that many entries fits
in `size` (each entry has a known minimum byte cost). A `tensor_count` of
`2^63` is rejected as `GGUF-COUNT-001` instead of entering a `2^63`-iteration
loop. Same for safetensors `header_len` (`ST-HEADERLEN-001/002`) — the header is
read **only after** confirming `header_len <= size-8` and `<= headerCap`.

### 6.3 Overflow-safe arithmetic
- Bounds checks use the `n > size-off` form (§3.2) — never `off+n` which can
  wrap.
- `product(dims)` / `product(shape)` use checked multiplication: multiply
  step-by-step, and on overflow emit the relevant finding (`GGUF-DIMOVF-001` /
  `ST-SHAPE-001`) and stop — never trust a wrapped product.
- Tensor `offset + size` (GGUF) and `data_offsets` (safetensors) compared with
  the overflow-safe form against `size`.

### 6.4 Zip-bomb defenses (pickle container)
`archive/zip` reading is bounded by:
- **Entry-count cap** (e.g. 10 000 entries) → over cap ⇒ `PKL-ZIP-001`, stop.
- **Per-entry uncompressed-size cap** and **total-uncompressed cap**: trust
  `File.UncompressedSize64` for a fast pre-check, but the authoritative guard is
  reading each `data.pkl` through an `io.LimitedReader` capped at the per-entry
  limit — so a lying header cannot cause an over-read.
- **Compression-ratio check**: if uncompressed/compressed for an entry exceeds a
  threshold (e.g. 1000×), flag `PKL-ZIP-001`. Only `data.pkl` entries are
  actually decompressed; other entries (weights) are never inflated.

### 6.5 Per-scanner recover guard (defense-in-depth)
`Engine.File` wraps each `scanner.Scan` call in a `defer/recover`. The parsers
are written to never panic (all index math is bounds-checked), but if one ever
did on a pathological input, the guard converts it into a `FileError` for that
one file and the walk continues — a single hostile file can never crash the
process. This guard is itself tested with a deliberately-panicking stub scanner.

### 6.6 No unbounded reads, ever
There is no `io.ReadAll` anywhere in the parsers. Every read is `ReadAt` of a
bounded slice at a known offset. The opcode walker (pickle) reads forward
through a `bufio.Reader` over an `io.LimitedReader`, never materializing the
whole stream, and stops at the first `STOP`, EOF, or cap.

### 6.7 What we deliberately do NOT do
No unpickling. No `reflect`-based object construction. No `os/exec`. No eval of
any format. No following of external references. The scanner's only capability
is *reading bytes and comparing them to tables*. This is stated in the README as
the core guarantee.

---

## 7. Error-handling strategy & exit codes

| Situation | Handling |
|---|---|
| Bad CLI flag / unknown `--format` / bad `--min-severity` | **Fatal usage error.** `cmd` prints to stderr, exits **2**. Sentinels (`report.ErrUnknownFormat`, `finding.ErrBadSeverity`) matched with `errors.Is`. |
| Path does not exist / not readable | **Fatal.** Wrapped `os` error to stderr, exit **2**. |
| File is `FormatUnknown` (not a model artifact) | **Not an error.** Counted as `Skipped`; no finding. |
| Scanner returns an error (truncated header, can't begin) | **Per-file, non-fatal.** Recorded in `Result.Errors` as a `FileError`; walk continues. Printed under a "could not scan" section. |
| Scanner panics on hostile input (should never happen) | **Contained.** Recover guard → `FileError`; walk continues (§6.5). |
| A detected risk (bad enum, OOB offset, RCE gadget) | **A Finding, not an error.** The normal product output. |
| `ctx` cancelled (SIGINT) | **Clean stop** between files; partial findings reported; exit reflects what was found so far. |

**Exit codes (set only by `cmd/modelvet`):**
- `0` — ran successfully, **no** finding at or above **High**.
- `1` — ran successfully, **at least one** High/Critical finding. *(CI-fail.)*
- `2` — usage/setup error (bad flags, unreadable path).

`report.ExitCode(Result)` computes 0 vs 1 purely from findings; `cmd` overrides
to 2 on setup errors. `--min-severity` filters the **reported** findings but the
exit code is always computed on the High/Critical presence among *reported*
findings (so raising `--min-severity` above High and getting a clean report also
gives exit 0 — documented, predictable).

**Error idioms (matching the house style):**
- **Sentinel errors** at package boundaries where the caller branches
  (`safeio.ErrOutOfBounds`, `report.ErrUnknownFormat`, `finding.ErrBadSeverity`).
- **Wrapped errors** inside libraries: `fmt.Errorf("gguf: read kv %d: %w", i, err)`
  — context accumulates, `errors.Is` still matches the sentinel.
- **No panics** in `internal/...` except the catalog-misuse panic in
  `finding.New` (programming error, test-covered, unreachable from input).
- Only `cmd/modelvet` calls `os.Exit`.

---

## 8. CLI (`cmd/modelvet/main.go`)

Stdlib `flag` only — **no Cobra/urfave**. The command surface is one verb and
five flags; a CLI framework would add dependency surface (and `govulncheck`
noise) for zero benefit. This matches the sibling `gorecon` decision.

```
modelvet scan [flags] <path-or-dir> [more paths...]

flags:
      --format        string   output: human|json|sarif        (default "human")
      --min-severity  string   info|low|medium|high|critical    (default "info")
      --recurse       bool      recurse into directories         (default true)
      --quiet         bool      suppress the per-file "OK" lines (default false)
  -h, --help
```

`main` responsibilities (thin glue, no business logic):
1. Parse the `scan` subcommand + flags; require ≥1 path. Bad flags → exit 2.
2. `ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)`;
   `defer stop()`.
3. Parse `--min-severity` (`finding.ParseSeverity`), `--format`. Fatal → exit 2.
4. `eng := scan.NewEngine()`; for each path `eng.Walk(ctx, path, opts)`; merge
   `Result`s.
5. `w, err := report.NewWriter(format, os.Stdout)`; `w.Write(result)`.
6. `os.Exit(report.ExitCode(result))` (or 2 on a setup error).

The single subcommand (`scan`) leaves room to add `version` / future verbs
without restructuring; dispatch is a simple `switch os.Args[1]`.

---

## 9. Test & fuzz strategy

Offline and deterministic: **every** test builds its inputs from in-test byte
fixtures — no checked-in binary model files, no network, no real `.gguf`/`.pt`
on disk. This is requirement-critical and is the credibility centerpiece.

### 9.1 Fixture builders (the enablers)

Each format package has a `fixtures_test.go` exposing small *builders* that
assemble valid bytes, with knobs to corrupt one field at a time:

```go
// gguf/fixtures_test.go
type ggufBuilder struct { /* version, kvs, tensors, plus corruption flags */ }
func newGGUF() *ggufBuilder
func (b *ggufBuilder) kv(key string, typ uint32, val any) *ggufBuilder
func (b *ggufBuilder) tensor(name string, dims []uint64, ttype uint32, off uint64) *ggufBuilder
func (b *ggufBuilder) build() []byte          // valid, well-formed GGUF
// targeted corruptions return raw bytes for one malformed variant each:
func (b *ggufBuilder) withBadMagic() []byte
func (b *ggufBuilder) withKVType(code uint32) []byte   // e.g. 99 -> GGUF-KV-TYPE-001
func (b *ggufBuilder) withHugeCount(n uint64) []byte   // -> GGUF-COUNT-001
func (b *ggufBuilder) withNDims(n uint32) []byte       // -> GGUF-NDIMS-001
func (b *ggufBuilder) withOffsetPastEOF() []byte       // -> GGUF-OFFSET-001
func (b *ggufBuilder) truncatedAt(n int) []byte        // -> GGUF-TRUNC-001
```

Analogous `stBuilder` (safetensors: header JSON + data, with offset/shape/dtype
corruptions and a `withHeaderLen(n)` knob) and `pickleBuilder` (emits raw opcode
sequences: a benign `STOP`-terminated stream, an `os.system` REDUCE gadget, a
truncated stream, an unknown opcode, plus `zipOf(pkl []byte)` to wrap a pickle
in a PyTorch-style zip).

Crucially, the malicious-pickle fixture is **assembled from opcode bytes in the
test**, not produced by Python's `pickle` — so the test suite never imports or
runs a pickler, keeping the "no Python, no execution" guarantee end-to-end.

### 9.2 Table tests (per scanner)

| Function | Cases |
|---|---|
| `safeio.Reader.Bytes` | exact read; `n>maxAlloc` → `ErrAllocTooLarge`; `off+n>size` (incl. overflow inputs) → `ErrOutOfBounds`; negative `n`/`off`; zero-length read. |
| `safeio.Reader.U32/U64` | LE decode correct; at-EOF → `ErrOutOfBounds`. |
| `gguf.Scanner.Scan` | valid → no findings; **one case per rule** in §5.1 via the matching builder corruption; assert the exact `RuleID` (and `Offset` where load-bearing). |
| `gguf.validKVType / validGGMLType` | boundary codes (0, 12, 13, max-uint32). |
| `gguf` dim-product | normal; overflow pair → `GGUF-DIMOVF-001`. |
| `safetensors.Scanner.Scan` | valid → none; one case per §5.2 rule; bad JSON; oversized header. |
| `safetensors` shape×dtype size | match vs mismatch → `ST-SHAPE-001`; overflow. |
| `pickle.Scanner.Scan` | benign stream → none/`Info`; `os.system`+REDUCE → `PKL-GLOBAL-001`+`PKL-REDUCE-001`; watch-list module → `PKL-GLOBAL-002`; truncated → `PKL-TRUNC-001`; unknown opcode → `PKL-OPAQUE-001`. |
| `pickle.zip` | benign zip-of-pickle parsed; zip with too many entries → `PKL-ZIP-001`; high-ratio entry → `PKL-ZIP-001`. |
| `scan.Detect` | each magic, each extension, `PK` zip vs raw pickle, magic-beats-extension, unknown. |
| `scan.Engine.File` | dispatch to right scanner; unknown → Skipped; panicking stub scanner → contained as `FileError`. |
| `report.NewWriter` | each format constructs; bad → `ErrUnknownFormat`. |
| `report` writers | fixed `Result` → exact human/JSON/SARIF bytes (golden); JSON round-trips; SARIF validates against the schema shape (rules + results present, severity mapping). |
| `report.ExitCode` | no findings → 0; Medium-only → 0; one High → 1; one Critical → 1. |
| `finding` catalog | every referenced ID exists; all entries titled+remediated; IDs unique; `Severity.String`/`ParseSeverity` round-trip. |

### 9.3 Native fuzz targets (robustness — the credibility piece)

Go 1.24 native fuzzing on the two binary parsers (the highest-risk surface):

```go
// gguf/fuzz_test.go
func FuzzScanGGUF(f *testing.F) {
    f.Add(newGGUF().build())          // valid seed
    f.Add(newGGUF().withKVType(99))   // the type-confusion seed
    f.Add(newGGUF().withOffsetPastEOF())
    f.Fuzz(func(t *testing.T, data []byte) {
        s := gguf.New()
        // INVARIANT: Scan must never panic and must return within bounded
        // memory/time on ANY input. We assert it returns (no panic) and that
        // it does not allocate beyond the safeio cap (guard cannot be tripped).
        _, _ = s.Scan(bytes.NewReader(data), int64(len(data)))
    })
}
```

`FuzzScanSafetensors` is analogous (random header-len + random JSON + random
data). `FuzzScanPickle` fuzzes the opcode walker (random opcode bytes) to prove
the disassembler can't be driven to panic or loop unboundedly. The fuzz
invariant is uniform and simple: **for all inputs, `Scan` returns without panic,
without OOM, in bounded time.** Seed corpora come from the same builders. The
Makefile has a `fuzz` target running each for a short fixed duration in CI.

### 9.4 What every test guarantees by construction
No test reads a file from disk outside `t.TempDir()`, none touches the network,
and none invokes Python or any unpickler. The "no execution" property is
therefore visible and enforced in the test suite itself.

---

## 10. Distribution: GoReleaser + Homebrew tap

### 10.1 `go install` (always works)
```
go install github.com/t3bik/modelvet/cmd/modelvet@latest
```
Documented first in the README. `version` is injected at build time via
`-ldflags "-X main.version=..."`; a bare `go install` shows `(devel)`.

### 10.2 `.goreleaser.yaml` (sketch)

Builds darwin/linux × amd64/arm64, emits archives + checksums + a Homebrew
formula pushed to `github.com/t3bik/homebrew-tap`, so
`brew install t3bik/tap/modelvet` works after a tagged release.

```yaml
version: 2

before:
  hooks:
    - go mod tidy
    - go test ./... -race    # release only on a green suite

builds:
  - id: modelvet
    main: ./cmd/modelvet
    binary: modelvet
    env: [CGO_ENABLED=0]     # pure-Go static binary; no cgo, smaller attack surface
    ldflags:
      - -s -w -X main.version={{.Version}} -X main.commit={{.ShortCommit}} -X main.date={{.Date}}
    goos: [darwin, linux]
    goarch: [amd64, arm64]

archives:
  - id: default
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    format: tar.gz

checksum:
  name_template: "checksums.txt"

sboms:                       # supply-chain credibility for a supply-chain tool
  - artifacts: archive

brews:
  - name: modelvet
    repository:
      owner: t3bik
      name: homebrew-tap
    homepage: "https://github.com/t3bik/modelvet"
    description: "Static security scanner for ML model artifacts (GGUF, safetensors, pickle) — no model load, no execution."
    license: "MIT"
    test: |
      system "#{bin}/modelvet", "--help"
    install: |
      bin.install "modelvet"

release:
  github:
    owner: t3bik
    name: modelvet
```

`.github/workflows/release.yml` runs `goreleaser release --clean` on tag push,
with a `HOMEBREW_TAP_GITHUB_TOKEN` secret that can push to `t3bik/homebrew-tap`.
Adding an SBOM (`sboms:`) is a deliberate, fitting touch for a supply-chain
security tool — it makes `modelvet`'s own releases auditable.

### 10.3 README install matrix
`brew install t3bik/tap/modelvet`, `go install …@latest`, and "download a
release binary + verify against `checksums.txt`" — all three documented.

---

## 11. Dependencies (and justification)

**Target: zero third-party runtime dependencies.** Everything in §3–§6 is
standard library:

`flag`, `os`, `os/signal`, `context`, `io`, `bufio`, `bytes`,
`encoding/binary` (LE ints), `encoding/json` (safetensors header, JSON/SARIF
output), `archive/zip` (PyTorch container), `errors`, `fmt`, `sort`, `strings`,
`strconv`, `path/filepath` (dir walk via `filepath.WalkDir`), `math` (overflow
constants).

| Dependency | Status | Why / why not |
|---|---|---|
| `archive/zip` (stdlib) | used | PyTorch `.pt` container handling. Stdlib — no external dep. Read through bounded `LimitedReader` (§6.4). |
| `encoding/json` (stdlib) | used | safetensors header + JSON/SARIF output. Decoded with `json.Decoder` over a **bounded** header slice, never the raw file. |
| SARIF library (e.g. `owenrumney/go-sarif`) | **rejected** | SARIF is just JSON; we emit the small subset GitHub needs via plain structs + `encoding/json`. A dep here adds transitive surface to a *security* tool for marginal convenience. We hand-roll the ~5 structs. |
| Cobra / urfave/cli | **rejected** | One verb, five flags. Stdlib `flag` suffices (matches `gorecon`). |
| `go.uber.org/goleak` *(test-only, optional)* | optional | Could assert no goroutine leaks, but the parsers spawn **no** goroutines — likely unnecessary. Omit unless concurrency is added. |

**gosec / govulncheck posture:**
- No `os/exec`, no shell, no `net` — **no command-injection or SSRF surface.**
- No `math/rand`, no crypto needed.
- Every `make([]byte, n)` is preceded by a cap+bounds check (§6.1) — addresses
  the gosec "slice from untrusted size" concern head-on.
- All errors checked; deliberate ignores (e.g. `defer f.Close()` on a read-only
  file) commented for gosec G104.
- `archive/zip` reads bounded by `io.LimitedReader` + entry caps → no zip-bomb
  decompression (gosec G110 decompression-bomb concern addressed).
- `encoding/json` decodes only a size-validated header slice → no huge-JSON DoS.
- Zero third-party runtime deps ⇒ `govulncheck` surface is the stdlib only.

---

## 12. Files the developer will create

1. `go.mod`, `go.sum`
2. `cmd/modelvet/main.go`
3. `internal/finding/finding.go`, `internal/finding/rules.go`, `internal/finding/finding_test.go`
4. `internal/safeio/safeio.go`, `internal/safeio/safeio_test.go`
5. `internal/gguf/gguf.go`, `internal/gguf/types.go`, `internal/gguf/gguf_test.go`, `internal/gguf/fixtures_test.go`, `internal/gguf/fuzz_test.go`
6. `internal/safetensors/safetensors.go`, `internal/safetensors/safetensors_test.go`, `internal/safetensors/fixtures_test.go`, `internal/safetensors/fuzz_test.go`
7. `internal/pickle/pickle.go`, `internal/pickle/opcodes.go`, `internal/pickle/dangerous.go`, `internal/pickle/zip.go`, `internal/pickle/pickle_test.go`, `internal/pickle/fixtures_test.go`, `internal/pickle/fuzz_test.go`
8. `internal/scan/scan.go`, `internal/scan/detect.go`, `internal/scan/scanner.go`, `internal/scan/scan_test.go`, `internal/scan/detect_test.go`
9. `internal/report/report.go`, `internal/report/human.go`, `internal/report/json.go`, `internal/report/sarif.go`, `internal/report/report_test.go`
10. `README.md`, `LICENSE`, `Makefile`, `.goreleaser.yaml`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`

---

## 13. Open questions / risks

- **GGUF spec drift.** The valid KV-type enum (0–12) and ggml type enum track
  llama.cpp, which evolves. Recommendation: keep both enums as small, clearly
  cited tables in `types.go` with a comment pointing at the upstream constant;
  an unknown-but-plausible code is `Medium`, a wildly-out-of-range code is the
  `Critical` type-confusion finding. Document the enum version in the README.
- **safetensors dtype set.** Same drift risk; encode the known dtype→size map as
  data and flag unknowns as `ST-DTYPE-001` (Medium) rather than erroring.
- **Pickle false positives.** A legitimate model may legitimately reference,
  say, `numpy` reconstructors via REDUCE. Recommendation: deny-list = genuine
  code-exec modules (Critical), watch-list = capability modules (High),
  everything else just informational. Document that High/Critical require human
  triage and that `--min-severity` lets users tune CI strictness.
- **Zip container variants.** `torch.save` has used both zip and legacy formats;
  newer ones nest `archive/data.pkl`. Recommendation: match any entry whose base
  name is `data.pkl` (case-sensitive), scan all of them, and flag if none found
  in a `PK`-magic file claiming to be a model (`Info`).
- **SARIF richness.** We emit a minimal valid SARIF 2.1.0 (driver, rules,
  results with severity + locations by byte offset). Region-by-byte-offset is
  unusual for SARIF (which prefers line/col); we use `byteOffset`/`byteLength`
  in `region`, which GitHub accepts. Note this in the README.
- **Exit-code vs `--min-severity` interaction.** Documented in §7: exit is
  computed on reported (post-filter) findings. Alternative (exit on *any*
  High/Critical regardless of filter) is also defensible — flag for the author
  to confirm. Recommendation: compute on reported, simplest mental model.
- **Per-file vs mid-parse cancellation.** We cancel between files, not mid-parse
  (parses are bounded and sub-millisecond). If huge files ever make a single
  parse slow, revisit with a ctx-aware `safeio.Reader`. Out of scope for v1.
```
