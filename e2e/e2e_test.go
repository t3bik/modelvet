//go:build e2e

// Package e2e contains black-box CLI tests for the modelvet binary.
// The binary is compiled once in TestMain and all tests run against it as a
// subprocess, asserting on stdout/stderr, exit codes, and parsed JSON/SARIF.
// Every fixture file is built programmatically — no real model files, no
// network, no Python.
package e2e

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// TestMain — build the binary once, run all tests, clean up.
// ─────────────────────────────────────────────────────────────────────────────

var binaryPath string

func TestMain(m *testing.M) {
	// Build into a temp dir so the binary is cleaned up after the test run.
	dir, err := os.MkdirTemp("", "modelvet-e2e-bin-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	bin := filepath.Join(dir, "modelvet")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/modelvet")
	// Build from the module root — one directory up from e2e/.
	cmd.Dir = filepath.Join(moduleRoot(), "..")
	out, buildErr := cmd.CombinedOutput()
	if buildErr != nil {
		fmt.Fprintf(os.Stderr, "e2e: go build failed:\n%s\n", out)
		os.Exit(1)
	}
	binaryPath = bin
	os.Exit(m.Run())
}

// moduleRoot returns the absolute path of the modelvet module root.
// At runtime the test binary's working directory is the e2e/ package, so we
// just want the parent.
func moduleRoot() string {
	// go test sets the working directory to the package directory.
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return wd
}

// ─────────────────────────────────────────────────────────────────────────────
// runBinary — helper that executes the binary and captures everything.
// ─────────────────────────────────────────────────────────────────────────────

type runResult struct {
	stdout   string
	stderr   string
	exitCode int
}

func runBinary(t *testing.T, args ...string) runResult {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			t.Fatalf("exec error (not ExitError): %v", err)
		}
	}
	return runResult{
		stdout:   outBuf.String(),
		stderr:   errBuf.String(),
		exitCode: code,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture builders — produce raw bytes for each file type.
// All assembled from raw bytes; no real model library or Python invoked.
// ─────────────────────────────────────────────────────────────────────────────

// ── helpers ──────────────────────────────────────────────────────────────────

func u32le(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func u64le(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func strField(s string) []byte {
	return append(u64le(uint64(len(s))), []byte(s)...)
}

// ── GGUF ──────────────────────────────────────────────────────────────────────

// ggufHeader writes: magic | version u32 | tensor_count u64 | kv_count u64
func ggufHeader(version uint32, tensorCount, kvCount uint64) []byte {
	var b []byte
	b = append(b, []byte("GGUF")...)
	b = append(b, u32le(version)...)
	b = append(b, u64le(tensorCount)...)
	b = append(b, u64le(kvCount)...)
	return b
}

// benignGGUF — valid GGUF with no tensors and one benign string KV.
func benignGGUF() []byte {
	// GGUF v3, 0 tensors, 1 KV (string type=8, value="ok")
	var b []byte
	b = append(b, ggufHeader(3, 0, 1)...)
	// KV: key="model_name", type=8 (STRING), value="ok"
	b = append(b, strField("model_name")...)
	b = append(b, u32le(8)...) // STRING
	b = append(b, strField("ok")...)
	return b
}

// maliciousGGUF_KVType — KV value-type code 99 (outside enum 0-12) → GGUF-KV-TYPE-001 (Critical).
func maliciousGGUF_KVType() []byte {
	var b []byte
	b = append(b, ggufHeader(3, 0, 1)...)
	b = append(b, strField("evil_key")...)
	b = append(b, u32le(99)...) // invalid type
	b = append(b, 0x01)         // placeholder value byte
	return b
}

// maliciousGGUF_OffsetPastEOF — tensor offset past EOF → GGUF-OFFSET-001 (Critical).
// Has 1 tensor with offset 9999 in a tiny file.
func maliciousGGUF_OffsetPastEOF() []byte {
	var b []byte
	b = append(b, ggufHeader(3, 1, 0)...) // 1 tensor, 0 KVs
	b = append(b, strField("t")...)
	b = append(b, u32le(1)...)   // n_dims=1
	b = append(b, u64le(100)...) // 100 elements
	b = append(b, u32le(0)...)   // F32 (4 bytes/elem → 400 bytes total)
	b = append(b, u64le(9999)...) // offset way past EOF
	return b
}

// depthBombGGUF — deeply nested ARRAY-of-ARRAY KV (5000 levels deep) → GGUF-ARRAY-DEPTH-001.
// The process must survive (no stack overflow).
func depthBombGGUF() []byte {
	// Build: 1 KV of type ARRAY, containing ARRAY-of-ARRAY 5000 levels deep.
	// ARRAY format: elem_type u32 | count u64 | elements
	// We want depth > maxArrayDepth (64). Use 5000 for a dramatic proof.
	const depth = 5000
	var b []byte
	b = append(b, ggufHeader(3, 0, 1)...)
	b = append(b, strField("depth_bomb")...)
	b = append(b, u32le(9)...) // ARRAY type
	// Now emit nested ARRAY headers: each array has elem_type=9 (ARRAY) and count=1.
	// Innermost has elem_type=0 (UINT8) and count=0 to terminate safely.
	for i := 0; i < depth; i++ {
		b = append(b, u32le(9)...) // elem_type = ARRAY
		b = append(b, u64le(1)...) // count = 1
	}
	// innermost: UINT8 array with count 0
	b = append(b, u32le(0)...) // elem_type = UINT8
	b = append(b, u64le(0)...) // count = 0
	return b
}

// ── safetensors ───────────────────────────────────────────────────────────────

// benignSafetensors — valid safetensors with one clean tensor.
func benignSafetensors() []byte {
	type tensorEntry struct {
		Dtype       string  `json:"dtype"`
		Shape       []int64 `json:"shape"`
		DataOffsets [2]int64 `json:"data_offsets"`
	}
	hdr := map[string]interface{}{
		"weight": tensorEntry{
			Dtype:       "F32",
			Shape:       []int64{4},
			DataOffsets: [2]int64{0, 16},
		},
	}
	hdrBytes, _ := json.Marshal(hdr)
	var b []byte
	b = append(b, u64le(uint64(len(hdrBytes)))...)
	b = append(b, hdrBytes...)
	b = append(b, make([]byte, 16)...) // data segment: 16 bytes for 4×F32
	return b
}

// maliciousSafetensors_OOBOffset — tensor data_offsets beyond data segment → ST-OFFSET-001 (Critical).
func maliciousSafetensors_OOBOffset() []byte {
	type tensorEntry struct {
		Dtype       string  `json:"dtype"`
		Shape       []int64 `json:"shape"`
		DataOffsets [2]int64 `json:"data_offsets"`
	}
	hdr := map[string]interface{}{
		"evil": tensorEntry{
			Dtype:       "F32",
			Shape:       []int64{4},
			DataOffsets: [2]int64{0, 99999}, // way beyond data segment
		},
	}
	hdrBytes, _ := json.Marshal(hdr)
	var b []byte
	b = append(b, u64le(uint64(len(hdrBytes)))...)
	b = append(b, hdrBytes...)
	b = append(b, make([]byte, 16)...) // only 16 bytes of data
	return b
}

// ── pickle ────────────────────────────────────────────────────────────────────

// benignPickle — PROTO 2, STOP. No dangerous opcodes.
func benignPickle() []byte {
	return []byte{0x80, 0x02, '.'}
}

// maliciousPickle_OsSystem — GLOBAL(os, system) + MARK + "id" + REDUCE + STOP.
// → PKL-GLOBAL-001 (Critical) + PKL-REDUCE-001 (High).
func maliciousPickle_OsSystem() []byte {
	var b []byte
	b = append(b, 0x80, 0x02)        // PROTO 2
	b = append(b, 'c')               // GLOBAL opcode
	b = append(b, []byte("os\n")...)
	b = append(b, []byte("system\n")...)
	b = append(b, '(')               // MARK
	b = append(b, 'U', 0x02, 'i', 'd') // SHORT_BINSTRING "id"
	b = append(b, 'R')               // REDUCE
	b = append(b, '.')               // STOP
	return b
}

// benignPyTorchZip — zip with archive/data.pkl containing benign pickle.
func benignPyTorchZip() []byte {
	return zipOf(benignPickle())
}

// maliciousPyTorchZip — zip with archive/data.pkl containing malicious pickle.
func maliciousPyTorchZip() []byte {
	return zipOf(maliciousPickle_OsSystem())
}

// pkZipNoDataPkl — PK-magic zip with no data.pkl entry → PKL-ZIP-002 (Low).
func pkZipNoDataPkl() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("some_weights.bin")
	_, _ = w.Write([]byte("placeholder"))
	_ = zw.Close()
	return buf.Bytes()
}

// zipOf wraps pickle bytes in a PyTorch-style zip container (archive/data.pkl).
func zipOf(pkl []byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("archive/data.pkl")
	_, _ = w.Write(pkl)
	_ = zw.Close()
	return buf.Bytes()
}

// ─────────────────────────────────────────────────────────────────────────────
// setupFixtureDir — writes all fixture files into a temp dir.
// Returns the temp dir path; caller must defer os.RemoveAll(dir).
// ─────────────────────────────────────────────────────────────────────────────

type fixtureDir struct {
	root string
	// Absolute paths to each fixture.
	benignGGUF           string
	benignSafetensors    string
	benignPickle         string
	benignPyTorchZip     string
	malGGUFKVType        string // GGUF-KV-TYPE-001 Critical
	malGGUFOffsetPastEOF string // GGUF-OFFSET-001 Critical
	depthBombGGUF        string // GGUF-ARRAY-DEPTH-001
	malSafetensorsOOB    string // ST-OFFSET-001 Critical
	malPickleOsSystem    string // PKL-GLOBAL-001 Critical + PKL-REDUCE-001 High
	malPyTorchZip        string // PKL-GLOBAL-001 Critical + PKL-REDUCE-001 High
	pkZipNoDataPkl       string // PKL-ZIP-002 Low
	notAModel            string // .txt — should be skipped
	subDir               string // nested subdir containing a malicious file
	malInSubDir          string // malicious GGUF in a nested subdir
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("writeFile %s: %v", path, err)
	}
}

func setupFixtureDir(t *testing.T) fixtureDir {
	t.Helper()
	root := t.TempDir()

	fd := fixtureDir{root: root}

	fd.benignGGUF = filepath.Join(root, "benign.gguf")
	writeFile(t, fd.benignGGUF, benignGGUF())

	fd.benignSafetensors = filepath.Join(root, "benign.safetensors")
	writeFile(t, fd.benignSafetensors, benignSafetensors())

	fd.benignPickle = filepath.Join(root, "benign.pkl")
	writeFile(t, fd.benignPickle, benignPickle())

	fd.benignPyTorchZip = filepath.Join(root, "benign.pt")
	writeFile(t, fd.benignPyTorchZip, benignPyTorchZip())

	fd.malGGUFKVType = filepath.Join(root, "mal_kv_type.gguf")
	writeFile(t, fd.malGGUFKVType, maliciousGGUF_KVType())

	fd.malGGUFOffsetPastEOF = filepath.Join(root, "mal_offset.gguf")
	writeFile(t, fd.malGGUFOffsetPastEOF, maliciousGGUF_OffsetPastEOF())

	fd.depthBombGGUF = filepath.Join(root, "depth_bomb.gguf")
	writeFile(t, fd.depthBombGGUF, depthBombGGUF())

	fd.malSafetensorsOOB = filepath.Join(root, "mal_oob.safetensors")
	writeFile(t, fd.malSafetensorsOOB, maliciousSafetensors_OOBOffset())

	fd.malPickleOsSystem = filepath.Join(root, "mal_os_system.pkl")
	writeFile(t, fd.malPickleOsSystem, maliciousPickle_OsSystem())

	fd.malPyTorchZip = filepath.Join(root, "mal_model.pt")
	writeFile(t, fd.malPyTorchZip, maliciousPyTorchZip())

	// .bin extension for zip-without-data.pkl (detected as PyTorch zip by PK magic)
	fd.pkZipNoDataPkl = filepath.Join(root, "no_data_pkl.pt")
	writeFile(t, fd.pkZipNoDataPkl, pkZipNoDataPkl())

	fd.notAModel = filepath.Join(root, "readme.txt")
	writeFile(t, fd.notAModel, []byte("this is not a model file"))

	// Nested subdir with a malicious GGUF to test deep recursion.
	fd.subDir = filepath.Join(root, "nested", "deep")
	if err := os.MkdirAll(fd.subDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	fd.malInSubDir = filepath.Join(fd.subDir, "nested_mal.gguf")
	writeFile(t, fd.malInSubDir, maliciousGGUF_KVType())

	return fd
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 1: scan <dir> — full directory walk.
// ─────────────────────────────────────────────────────────────────────────────

func TestE2E_Scenario1_DirectoryScan(t *testing.T) {
	fd := setupFixtureDir(t)

	res := runBinary(t, "scan", "--format", "human", fd.root)

	t.Run("exit_code_1", func(t *testing.T) {
		if res.exitCode != 1 {
			t.Errorf("got exit code %d, want 1 (malicious files present)", res.exitCode)
		}
	})

	t.Run("contains_GGUF-KV-TYPE-001", func(t *testing.T) {
		if !strings.Contains(res.stdout, "GGUF-KV-TYPE-001") {
			t.Errorf("stdout missing GGUF-KV-TYPE-001\n--- stdout ---\n%s", res.stdout)
		}
	})

	t.Run("contains_GGUF-OFFSET-001", func(t *testing.T) {
		if !strings.Contains(res.stdout, "GGUF-OFFSET-001") {
			t.Errorf("stdout missing GGUF-OFFSET-001\n--- stdout ---\n%s", res.stdout)
		}
	})

	t.Run("contains_ST-OFFSET-001", func(t *testing.T) {
		if !strings.Contains(res.stdout, "ST-OFFSET-001") {
			t.Errorf("stdout missing ST-OFFSET-001\n--- stdout ---\n%s", res.stdout)
		}
	})

	t.Run("contains_PKL-GLOBAL-001", func(t *testing.T) {
		if !strings.Contains(res.stdout, "PKL-GLOBAL-001") {
			t.Errorf("stdout missing PKL-GLOBAL-001\n--- stdout ---\n%s", res.stdout)
		}
	})

	t.Run("contains_GGUF-ARRAY-DEPTH-001", func(t *testing.T) {
		if !strings.Contains(res.stdout, "GGUF-ARRAY-DEPTH-001") {
			t.Errorf("stdout missing GGUF-ARRAY-DEPTH-001\n--- stdout ---\n%s", res.stdout)
		}
	})

	t.Run("summary_counts_sane", func(t *testing.T) {
		// Must contain a Summary section with positive scanned count.
		if !strings.Contains(res.stdout, "--- Summary ---") {
			t.Errorf("stdout missing Summary section\n--- stdout ---\n%s", res.stdout)
		}
		if !strings.Contains(res.stdout, "Scanned:") {
			t.Errorf("stdout missing Scanned: line\n--- stdout ---\n%s", res.stdout)
		}
	})

	t.Run("benign_files_no_explicit_findings", func(t *testing.T) {
		// benign.gguf should NOT appear as a finding path.
		if strings.Contains(res.stdout, "benign.gguf") {
			t.Errorf("benign.gguf unexpectedly has findings in stdout:\n%s", res.stdout)
		}
		if strings.Contains(res.stdout, "benign.safetensors") {
			t.Errorf("benign.safetensors unexpectedly has findings in stdout:\n%s", res.stdout)
		}
		if strings.Contains(res.stdout, "benign.pkl") {
			t.Errorf("benign.pkl unexpectedly has findings in stdout:\n%s", res.stdout)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 2: scan <benign-file> — clean, exit 0.
// ─────────────────────────────────────────────────────────────────────────────

func TestE2E_Scenario2_BenignFile(t *testing.T) {
	tests := []struct {
		name  string
		bytes func() []byte
		ext   string
	}{
		{"benign_gguf", benignGGUF, ".gguf"},
		{"benign_safetensors", benignSafetensors, ".safetensors"},
		{"benign_pickle", benignPickle, ".pkl"},
		{"benign_pytorch_zip", benignPyTorchZip, ".pt"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "benign"+tt.ext)
			writeFile(t, path, tt.bytes())

			res := runBinary(t, "scan", path)

			if res.exitCode != 0 {
				t.Errorf("exit code = %d, want 0\n--- stdout ---\n%s\n--- stderr ---\n%s",
					res.exitCode, res.stdout, res.stderr)
			}
			// Stdout should contain summary but no finding-level output.
			if strings.Contains(res.stdout, "[CRITICAL]") || strings.Contains(res.stdout, "[HIGH]") {
				t.Errorf("unexpected High/Critical findings in benign scan:\n%s", res.stdout)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 3: scan <malicious-gguf> --format json
// ─────────────────────────────────────────────────────────────────────────────

func TestE2E_Scenario3_MaliciousGGUF_JSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mal_kv.gguf")
	writeFile(t, path, maliciousGGUF_KVType())

	res := runBinary(t, "scan", "--format", "json", path)

	t.Run("exit_code_1", func(t *testing.T) {
		if res.exitCode != 1 {
			t.Errorf("exit code = %d, want 1", res.exitCode)
		}
	})

	t.Run("stdout_is_valid_json", func(t *testing.T) {
		var raw json.RawMessage
		if err := json.Unmarshal([]byte(res.stdout), &raw); err != nil {
			t.Fatalf("stdout is not valid JSON: %v\n--- stdout ---\n%s", err, res.stdout)
		}
	})

	t.Run("finding_fields_present", func(t *testing.T) {
		var report struct {
			Findings []struct {
				RuleID      string `json:"rule_id"`
				Severity    string `json:"severity"`
				Format      string `json:"format"`
				Path        string `json:"path"`
				Offset      int64  `json:"offset"`
				Detail      string `json:"detail"`
				Remediation string `json:"remediation"`
			} `json:"findings"`
			Summary struct {
				Scanned  int `json:"scanned"`
				Skipped  int `json:"skipped"`
				Findings int `json:"findings"`
			} `json:"summary"`
		}
		if err := json.Unmarshal([]byte(res.stdout), &report); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(report.Findings) == 0 {
			t.Fatal("findings array is empty")
		}
		found := false
		for _, f := range report.Findings {
			if f.RuleID == "GGUF-KV-TYPE-001" {
				found = true
				if f.Severity != "CRITICAL" {
					t.Errorf("GGUF-KV-TYPE-001 severity = %q, want CRITICAL", f.Severity)
				}
				if f.Format != "gguf" {
					t.Errorf("GGUF-KV-TYPE-001 format = %q, want gguf", f.Format)
				}
				if f.Path == "" {
					t.Error("GGUF-KV-TYPE-001 path is empty")
				}
				if f.Detail == "" {
					t.Error("GGUF-KV-TYPE-001 detail is empty")
				}
				if f.Remediation == "" {
					t.Error("GGUF-KV-TYPE-001 remediation is empty")
				}
				// Offset must be non-negative (KV type field is within header).
				if f.Offset < 0 {
					t.Errorf("GGUF-KV-TYPE-001 offset = %d, want >=0", f.Offset)
				}
			}
		}
		if !found {
			t.Errorf("GGUF-KV-TYPE-001 not found in findings; got: %+v", report.Findings)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 4: scan <malicious-pickle> --format sarif
// ─────────────────────────────────────────────────────────────────────────────

func TestE2E_Scenario4_MaliciousPickle_SARIF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mal_os.pkl")
	writeFile(t, path, maliciousPickle_OsSystem())

	res := runBinary(t, "scan", "--format", "sarif", path)

	t.Run("exit_code_1", func(t *testing.T) {
		if res.exitCode != 1 {
			t.Errorf("exit code = %d, want 1", res.exitCode)
		}
	})

	t.Run("stdout_is_valid_json", func(t *testing.T) {
		var raw json.RawMessage
		if err := json.Unmarshal([]byte(res.stdout), &raw); err != nil {
			t.Fatalf("stdout is not valid JSON: %v\n--- stdout ---\n%s", err, res.stdout)
		}
	})

	t.Run("sarif_schema_and_version", func(t *testing.T) {
		var doc struct {
			Version string `json:"version"`
			Schema  string `json:"$schema"`
			Runs    []struct {
				Tool struct {
					Driver struct {
						Name  string `json:"name"`
						Rules []struct {
							ID string `json:"id"`
						} `json:"rules"`
					} `json:"driver"`
				} `json:"tool"`
				Results []struct {
					RuleID string `json:"ruleId"`
					Level  string `json:"level"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal([]byte(res.stdout), &doc); err != nil {
			t.Fatalf("unmarshal SARIF: %v", err)
		}
		if doc.Version != "2.1.0" {
			t.Errorf("SARIF version = %q, want 2.1.0", doc.Version)
		}
		if doc.Schema == "" {
			t.Error("SARIF $schema is empty")
		}
		if len(doc.Runs) == 0 {
			t.Fatal("SARIF runs is empty")
		}
		if doc.Runs[0].Tool.Driver.Name != "modelvet" {
			t.Errorf("driver.name = %q, want modelvet", doc.Runs[0].Tool.Driver.Name)
		}
		if len(doc.Runs[0].Results) == 0 {
			t.Fatal("SARIF results is empty")
		}

		// PKL-GLOBAL-001 must be present as an "error" level result.
		foundPKLGlobal := false
		for _, r := range doc.Runs[0].Results {
			if r.RuleID == "PKL-GLOBAL-001" {
				foundPKLGlobal = true
				if r.Level != "error" {
					t.Errorf("PKL-GLOBAL-001 SARIF level = %q, want error (Critical)", r.Level)
				}
			}
		}
		if !foundPKLGlobal {
			t.Errorf("PKL-GLOBAL-001 not found in SARIF results: %+v", doc.Runs[0].Results)
		}

		// rules array must include PKL-GLOBAL-001.
		foundRule := false
		for _, rule := range doc.Runs[0].Tool.Driver.Rules {
			if rule.ID == "PKL-GLOBAL-001" {
				foundRule = true
			}
		}
		if !foundRule {
			t.Errorf("PKL-GLOBAL-001 not found in SARIF rules: %+v", doc.Runs[0].Tool.Driver.Rules)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 5: --min-severity high on Medium-worst file → exit 0; Critical file still exits 1.
// ─────────────────────────────────────────────────────────────────────────────

func TestE2E_Scenario5_MinSeverity(t *testing.T) {
	// Build a safetensors file whose worst finding is Medium (ST-JSON-001).
	mediumOnlyFile := func() []byte {
		// Bad JSON header → ST-JSON-001 (Medium).
		hdr := []byte("{not valid json")
		var b []byte
		b = append(b, u64le(uint64(len(hdr)))...)
		b = append(b, hdr...)
		return b
	}

	t.Run("medium_file_filtered_out_exit_0", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "medium_only.safetensors")
		writeFile(t, path, mediumOnlyFile())

		// Without filter: should find ST-JSON-001 (Medium).
		resUnfiltered := runBinary(t, "scan", path)
		if !strings.Contains(resUnfiltered.stdout, "ST-JSON-001") {
			t.Logf("unfiltered stdout:\n%s", resUnfiltered.stdout)
			// The medium-only file must produce findings without the filter.
			// If it doesn't, the test setup is wrong.
			t.Fatal("medium-only file produced no findings (test fixture may be wrong)")
		}

		// With --min-severity high: Medium should be filtered out.
		resFiltered := runBinary(t, "scan", "--min-severity", "high", path)
		if resFiltered.exitCode != 0 {
			t.Errorf("--min-severity high on medium-only file: exit code = %d, want 0\n--- stdout ---\n%s",
				resFiltered.exitCode, resFiltered.stdout)
		}
		if strings.Contains(resFiltered.stdout, "ST-JSON-001") {
			t.Errorf("ST-JSON-001 (Medium) present after --min-severity high filtering:\n%s", resFiltered.stdout)
		}
	})

	t.Run("critical_file_still_exits_1", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "critical.gguf")
		writeFile(t, path, maliciousGGUF_KVType())

		res := runBinary(t, "scan", "--min-severity", "high", path)
		if res.exitCode != 1 {
			t.Errorf("critical file with --min-severity high: exit code = %d, want 1\n--- stdout ---\n%s\n--- stderr ---\n%s",
				res.exitCode, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "GGUF-KV-TYPE-001") {
			t.Errorf("GGUF-KV-TYPE-001 (Critical) missing after --min-severity high:\n%s", res.stdout)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 6: --quiet behavior.
// ─────────────────────────────────────────────────────────────────────────────

func TestE2E_Scenario6_Quiet(t *testing.T) {
	t.Run("malicious_file_findings_still_printed", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "mal.gguf")
		writeFile(t, path, maliciousGGUF_KVType())

		res := runBinary(t, "scan", "--quiet", path)
		if res.exitCode != 1 {
			t.Errorf("exit code = %d, want 1", res.exitCode)
		}
		if !strings.Contains(res.stdout, "GGUF-KV-TYPE-001") {
			t.Errorf("--quiet should NOT suppress findings; GGUF-KV-TYPE-001 missing:\n%s", res.stdout)
		}
		// Summary must still be printed.
		if !strings.Contains(res.stdout, "--- Summary ---") {
			t.Errorf("--quiet should not suppress summary:\n%s", res.stdout)
		}
	})

	t.Run("benign_file_quiet_suppresses_ok_line", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "clean.gguf")
		writeFile(t, path, benignGGUF())

		resNormal := runBinary(t, "scan", path)
		resQuiet := runBinary(t, "scan", "--quiet", path)

		// Exit codes unchanged.
		if resNormal.exitCode != 0 {
			t.Errorf("normal exit code = %d, want 0", resNormal.exitCode)
		}
		if resQuiet.exitCode != 0 {
			t.Errorf("quiet exit code = %d, want 0", resQuiet.exitCode)
		}

		// Both should have the summary.
		if !strings.Contains(resQuiet.stdout, "--- Summary ---") {
			t.Errorf("--quiet suppressed summary for benign file:\n%s", resQuiet.stdout)
		}
	})

	t.Run("exit_codes_unchanged_by_quiet", func(t *testing.T) {
		dir := t.TempDir()
		malPath := filepath.Join(dir, "mal.pkl")
		writeFile(t, malPath, maliciousPickle_OsSystem())

		resNormal := runBinary(t, "scan", malPath)
		resQuiet := runBinary(t, "scan", "--quiet", malPath)

		if resNormal.exitCode != resQuiet.exitCode {
			t.Errorf("exit code differs: normal=%d quiet=%d", resNormal.exitCode, resQuiet.exitCode)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 7: DEPTH-BOMB — process must survive, emit GGUF-ARRAY-DEPTH-001.
// ─────────────────────────────────────────────────────────────────────────────

func TestE2E_Scenario7_DepthBomb(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "depth_bomb.gguf")
	writeFile(t, path, depthBombGGUF())

	res := runBinary(t, "scan", path)

	t.Run("process_did_not_crash", func(t *testing.T) {
		// Exit code must be 0 or 1 (not 2, and no crash signal).
		if res.exitCode == 2 {
			t.Errorf("exit code 2 (usage/IO error): stderr:\n%s", res.stderr)
		}
		// Crucially: no stack overflow in stderr.
		if strings.Contains(res.stderr, "fatal error: stack overflow") {
			t.Errorf("STACK OVERFLOW detected in stderr — depth-bomb caused process crash:\n%s", res.stderr)
		}
		if strings.Contains(res.stderr, "runtime: goroutine stack exceeds") {
			t.Errorf("goroutine stack size exceeded in stderr:\n%s", res.stderr)
		}
	})

	t.Run("GGUF-ARRAY-DEPTH-001_in_output", func(t *testing.T) {
		if !strings.Contains(res.stdout, "GGUF-ARRAY-DEPTH-001") {
			t.Errorf("GGUF-ARRAY-DEPTH-001 not found in stdout\n--- stdout ---\n%s\n--- stderr ---\n%s",
				res.stdout, res.stderr)
		}
	})

	t.Run("exit_code_is_0_or_1", func(t *testing.T) {
		if res.exitCode != 0 && res.exitCode != 1 {
			t.Errorf("exit code = %d, want 0 or 1", res.exitCode)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 8: error cases — no path / unknown flag / nonexistent path → exit 2.
// ─────────────────────────────────────────────────────────────────────────────

func TestE2E_Scenario8_ErrorCases(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantExit  int
		wantStderr string
	}{
		{
			name:      "no_path_argument",
			args:      []string{"scan"},
			wantExit:  2,
			wantStderr: "",
		},
		{
			name:      "unknown_flag",
			args:      []string{"scan", "--nonexistent-flag", "/tmp"},
			wantExit:  2,
			wantStderr: "",
		},
		{
			name:      "nonexistent_path",
			args:      []string{"scan", "/nonexistent/path/that/does/not/exist.gguf"},
			wantExit:  2,
			wantStderr: "",
		},
		{
			name:      "unknown_subcommand",
			args:      []string{"foobar"},
			wantExit:  2,
			wantStderr: "",
		},
		{
			name:      "bad_format",
			args:      []string{"scan", "--format", "xml", "/tmp"},
			wantExit:  2,
			wantStderr: "",
		},
		{
			name:      "bad_min_severity",
			args:      []string{"scan", "--min-severity", "bogus", "/tmp"},
			wantExit:  2,
			wantStderr: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			res := runBinary(t, tt.args...)
			if res.exitCode != tt.wantExit {
				t.Errorf("exit code = %d, want %d\n--- stdout ---\n%s\n--- stderr ---\n%s",
					res.exitCode, tt.wantExit, res.stdout, res.stderr)
			}
			// stderr must contain something useful (not empty).
			if res.stderr == "" && res.stdout == "" {
				t.Error("both stdout and stderr are empty for an error case — no user message")
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 9: nested subdir recursion — malicious file in deep subdir is found.
// ─────────────────────────────────────────────────────────────────────────────

func TestE2E_Scenario9_NestedSubdirRecursion(t *testing.T) {
	root := t.TempDir()
	// Create a clean GGUF at the root level.
	writeFile(t, filepath.Join(root, "clean.gguf"), benignGGUF())
	// Create malicious GGUF in a nested subdir.
	subDir := filepath.Join(root, "level1", "level2", "level3")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	malPath := filepath.Join(subDir, "buried.gguf")
	writeFile(t, malPath, maliciousGGUF_KVType())

	res := runBinary(t, "scan", root)

	t.Run("exit_code_1", func(t *testing.T) {
		if res.exitCode != 1 {
			t.Errorf("exit code = %d, want 1\n--- stdout ---\n%s", res.exitCode, res.stdout)
		}
	})

	t.Run("malicious_file_found", func(t *testing.T) {
		if !strings.Contains(res.stdout, "GGUF-KV-TYPE-001") {
			t.Errorf("GGUF-KV-TYPE-001 not found; nested file not scanned\n--- stdout ---\n%s", res.stdout)
		}
	})

	t.Run("nested_path_in_output", func(t *testing.T) {
		if !strings.Contains(res.stdout, "buried.gguf") {
			t.Errorf("nested file path 'buried.gguf' not in output\n--- stdout ---\n%s", res.stdout)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional targeted tests not covered by the 9 core scenarios.
// ─────────────────────────────────────────────────────────────────────────────

// TestE2E_PyTorchZip_Malicious — malicious zip containing data.pkl surfaces pickle rules.
func TestE2E_PyTorchZip_Malicious(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mal_model.pt")
	writeFile(t, path, maliciousPyTorchZip())

	res := runBinary(t, "scan", "--format", "json", path)

	if res.exitCode != 1 {
		t.Errorf("exit code = %d, want 1", res.exitCode)
	}

	var report struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &report); err != nil {
		t.Fatalf("unmarshal: %v\n--- stdout ---\n%s", err, res.stdout)
	}

	ruleIDs := make(map[string]bool)
	for _, f := range report.Findings {
		ruleIDs[f.RuleID] = true
	}
	if !ruleIDs["PKL-GLOBAL-001"] {
		t.Errorf("PKL-GLOBAL-001 not found in PyTorch zip findings; got: %v", ruleIDs)
	}
}

// TestE2E_PkZipNoDataPkl — zip with no data.pkl → PKL-ZIP-002 (Low), exit 0.
func TestE2E_PkZipNoDataPkl(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no_pkl.pt")
	writeFile(t, path, pkZipNoDataPkl())

	res := runBinary(t, "scan", "--format", "json", path)

	// PKL-ZIP-002 is Low severity → exit 0.
	if res.exitCode != 0 {
		t.Errorf("exit code = %d, want 0 (Low severity only)\n--- stdout ---\n%s", res.exitCode, res.stdout)
	}

	var report struct {
		Findings []struct {
			RuleID   string `json:"rule_id"`
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &report); err != nil {
		t.Fatalf("unmarshal: %v\n--- stdout ---\n%s", err, res.stdout)
	}

	found := false
	for _, f := range report.Findings {
		if f.RuleID == "PKL-ZIP-002" {
			found = true
			if f.Severity != "LOW" {
				t.Errorf("PKL-ZIP-002 severity = %q, want LOW", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("PKL-ZIP-002 not found; findings: %+v", report.Findings)
	}
}

// TestE2E_NonModelFile_Skipped — a .txt file is skipped, no findings, exit 0.
func TestE2E_NonModelFile_Skipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "readme.txt")
	writeFile(t, path, []byte("this is not a model file"))

	res := runBinary(t, "scan", path)

	if res.exitCode != 0 {
		t.Errorf("exit code = %d, want 0 for non-model file", res.exitCode)
	}
	if strings.Contains(res.stdout, "[CRITICAL]") || strings.Contains(res.stdout, "[HIGH]") {
		t.Errorf("unexpected findings for non-model .txt file:\n%s", res.stdout)
	}
}

// TestE2E_GGUF_OFFSET001_JSON — malicious GGUF with offset past EOF emits GGUF-OFFSET-001 (Critical).
func TestE2E_GGUF_OFFSET001_JSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "offset.gguf")
	writeFile(t, path, maliciousGGUF_OffsetPastEOF())

	res := runBinary(t, "scan", "--format", "json", path)

	if res.exitCode != 1 {
		t.Errorf("exit code = %d, want 1\n--- stdout ---\n%s", res.exitCode, res.stdout)
	}

	var report struct {
		Findings []struct {
			RuleID   string `json:"rule_id"`
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &report); err != nil {
		t.Fatalf("unmarshal: %v\n--- stdout ---\n%s", err, res.stdout)
	}

	found := false
	for _, f := range report.Findings {
		if f.RuleID == "GGUF-OFFSET-001" {
			found = true
			if f.Severity != "CRITICAL" {
				t.Errorf("GGUF-OFFSET-001 severity = %q, want CRITICAL", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("GGUF-OFFSET-001 not found; findings: %+v", report.Findings)
	}
}
