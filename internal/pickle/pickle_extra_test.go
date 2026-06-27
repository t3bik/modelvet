package pickle_test

// pickle_extra_test.go — QA-authored tests for the pickle scanner.
//
// Developer-flagged risk: STACK_GLOBAL is flagged as PKL-GLOBAL-002
// conservatively. This is the correct conservative behavior:
// - Module/name on the stack cannot be statically verified.
// - A legitimate numpy reconstructor would use STACK_GLOBAL but be
//   flagged PKL-GLOBAL-002 (High) — a documented false-positive risk.
// The test documents this behavior explicitly.
//
// All fixtures are assembled from raw opcode bytes; no Python pickler runs.

import (
	"bytes"
	"testing"

	"github.com/t3bik/modelvet/internal/pickle"
)

// ─── AC3: Benign pickle produces zero dangerous findings ─────────────────────

func TestAC3_BenignPickleZeroFindings(t *testing.T) {
	ids, err := scan(benignPickle())
	if err != nil {
		t.Fatalf("benign pickle error: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("false positive on benign pickle: %v", ids)
	}
}

// ─── AC3: STACK_GLOBAL → PKL-GLOBAL-002 (documented conservative behavior) ───

// TestAC3_StackGlobal_BenignNumpyNoCritical verifies that a STACK_GLOBAL opcode (0x93)
// whose operands resolve statically to a benign module (numpy.core.multiarray)
// does NOT produce a CRITICAL or HIGH finding.
//
// Before the STACK_GLOBAL resolution fix, all STACK_GLOBAL opcodes were conservatively
// flagged as PKL-GLOBAL-002 (High), causing false-positive noise on every legitimate
// numpy/torch model. After the fix, the scanner resolves the two immediately-preceding
// string pushes: if the module is neither in denyModules nor watchModules, no finding
// is emitted — eliminating the false-positive for common ML frameworks.
func TestAC3_StackGlobal_BenignNumpyNoCritical(t *testing.T) {
	// Build a pickle with STACK_GLOBAL preceded by numpy module/name strings —
	// exactly what Python 3.x pickle produces for numpy array serialization.
	pkl := newPickle().
		proto(2).
		binstring("numpy.core.multiarray"). // module pushed onto stack
		binstring("_reconstruct").          // name pushed onto stack
		stackGlobal().                      // 0x93 STACK_GLOBAL — pops module+name
		stop().
		build()

	ids, err := scan(pkl)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must NOT fire PKL-GLOBAL-001: numpy is not a code-execution module.
	if hasID(ids, "PKL-GLOBAL-001") {
		t.Errorf("false positive PKL-GLOBAL-001 for benign numpy STACK_GLOBAL: got %v", ids)
	}

	// Must NOT fire PKL-GLOBAL-002: the module is now statically resolved as benign.
	if hasID(ids, "PKL-GLOBAL-002") {
		t.Errorf("false positive PKL-GLOBAL-002 for benign numpy STACK_GLOBAL: got %v", ids)
	}

	t.Log("PASS: numpy.core.multiarray._reconstruct via STACK_GLOBAL produces no finding (benign, resolved statically)")
}

// ─── AC3: STACK_GLOBAL + REDUCE = PKL-REDUCE-001 ────────────────────────────

func TestAC3_StackGlobalWithReduce(t *testing.T) {
	pkl := newPickle().
		proto(2).
		binstring("os").
		binstring("system").
		stackGlobal().
		mark().
		binstring("id").
		reduce().
		stop().
		build()

	ids, err := scan(pkl)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasID(ids, "PKL-REDUCE-001") {
		t.Fatalf("expected PKL-REDUCE-001 for STACK_GLOBAL+REDUCE, got %v", ids)
	}
}

// ─── AC3: PKL-GLOBAL-001 — all deny-list modules ─────────────────────────────

func TestAC3_DenyListModulesFireGlobal001(t *testing.T) {
	denyModules := []string{
		"os", "posix", "nt", "subprocess", "sys", "runpy",
		"builtins", "__builtin__", "importlib", "pty", "socket",
		"ctypes", "cffi", "_posixsubprocess",
	}
	for _, mod := range denyModules {
		t.Run("module="+mod, func(t *testing.T) {
			pkl := newPickle().proto(2).global(mod, "something").stop().build()
			ids, err := scan(pkl)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if !hasID(ids, "PKL-GLOBAL-001") {
				t.Errorf("expected PKL-GLOBAL-001 for module %q, got %v", mod, ids)
			}
		})
	}
}

// ─── AC3: PKL-GLOBAL-002 — all watch-list modules ────────────────────────────

func TestAC3_WatchListModulesFireGlobal002(t *testing.T) {
	watchModules := []string{
		"shutil", "pickle", "webbrowser", "base64", "codecs",
		"operator", "functools", "itertools", "marshal", "io",
		"tempfile", "glob", "fnmatch",
	}
	for _, mod := range watchModules {
		t.Run("module="+mod, func(t *testing.T) {
			pkl := newPickle().proto(2).global(mod, "something").stop().build()
			ids, err := scan(pkl)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if !hasID(ids, "PKL-GLOBAL-002") {
				t.Errorf("expected PKL-GLOBAL-002 for module %q, got %v", mod, ids)
			}
			if hasID(ids, "PKL-GLOBAL-001") {
				t.Errorf("watch-list module %q should not fire PKL-GLOBAL-001", mod)
			}
		})
	}
}

// ─── AC3: Benign module fires neither ────────────────────────────────────────

func TestAC3_SafeModuleNoGlobalFindings(t *testing.T) {
	// "numpy" is neither deny nor watch — no PKL-GLOBAL-* should fire.
	pkl := newPickle().proto(2).global("numpy", "array").stop().build()
	ids, err := scan(pkl)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if hasID(ids, "PKL-GLOBAL-001") {
		t.Errorf("false positive PKL-GLOBAL-001 for numpy")
	}
	if hasID(ids, "PKL-GLOBAL-002") {
		t.Errorf("false positive PKL-GLOBAL-002 for numpy")
	}
}

// ─── AC3: PKL-REDUCE-001 fires when GLOBAL present (not just deny) ───────────

func TestAC3_ReduceWithWatchListModule(t *testing.T) {
	// watch-list module + REDUCE → PKL-REDUCE-001 fires (RCE gadget shape).
	pkl := newPickle().
		proto(2).
		global("shutil", "rmtree").
		mark().
		binstring("/tmp").
		reduce().
		stop().
		build()
	ids, err := scan(pkl)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !hasID(ids, "PKL-REDUCE-001") {
		t.Fatalf("expected PKL-REDUCE-001 for watch-list+REDUCE, got %v", ids)
	}
}

// ─── AC3: PKL-PROTO-001 — unusual protocol ───────────────────────────────────

func TestAC3_UnusualProtocol(t *testing.T) {
	// Protocol 6 is unknown (0–5 are valid).
	pkl := []byte{0x80, 0x06, '.'} // PROTO 6, STOP
	ids, err := scan(pkl)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !hasID(ids, "PKL-PROTO-001") {
		t.Fatalf("expected PKL-PROTO-001 for protocol 6, got %v", ids)
	}
}

// ─── AC3: Zip benign + malicious round-trips ─────────────────────────────────

func TestAC3_ZipOfMaliciousPickle_PKL_GLOBAL_001_PKL_REDUCE_001(t *testing.T) {
	// Verified end-to-end: zip container wrapping os.system RCE gadget
	// must detect both PKL-GLOBAL-001 and PKL-REDUCE-001.
	ids, err := scan(zipOf(osSystemGadget()))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !hasID(ids, "PKL-GLOBAL-001") {
		t.Fatalf("expected PKL-GLOBAL-001 in zip-wrapped RCE, got %v", ids)
	}
	if !hasID(ids, "PKL-REDUCE-001") {
		t.Fatalf("expected PKL-REDUCE-001 in zip-wrapped RCE, got %v", ids)
	}
}

// ─── AC3: No Python pickler used — verify by construction ─────────────────────

// TestAC3_NoPicklerUsed documents that the fixture assembly uses only raw bytes.
// This test runs and checks the scan result to provide evidence that the
// "no execution" guarantee holds in the test suite. If this test requires
// importing/running Python it would fail at compile time since no Python
// import exists anywhere in this package.
func TestAC3_NoPicklerUsed(t *testing.T) {
	// osSystemGadget() is assembled entirely from opcode bytes (no pickle import).
	// We assert it detects the RCE pattern — proving the scanner works without
	// the runtime pickler.
	gadget := osSystemGadget()
	// Sanity: first byte should be 0x80 (PROTO), second should be 0x02 (version).
	if len(gadget) < 2 || gadget[0] != 0x80 || gadget[1] != 0x02 {
		t.Fatalf("osSystemGadget expected to start with PROTO 2")
	}
	ids, err := scan(gadget)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !hasID(ids, "PKL-GLOBAL-001") {
		t.Fatalf("expected PKL-GLOBAL-001, got %v (no Python was invoked)", ids)
	}
}

// ─── Helper: stackGlobal opcode ──────────────────────────────────────────────

// stackGlobal adds the STACK_GLOBAL opcode (0x93) to a pickleBuilder.
func (p *pickleBuilder) stackGlobal() *pickleBuilder {
	p.buf = append(p.buf, 0x93) // STACK_GLOBAL — no inline argument
	return p
}

// ─── AC3: Multiple globals in one stream ─────────────────────────────────────

func TestAC3_MultipleGlobals(t *testing.T) {
	// One deny-list + one watch-list in the same stream.
	pkl := newPickle().
		proto(2).
		global("os", "system").
		global("shutil", "rmtree").
		stop().
		build()
	ids, err := scan(pkl)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !hasID(ids, "PKL-GLOBAL-001") {
		t.Errorf("expected PKL-GLOBAL-001 for os.system")
	}
	if !hasID(ids, "PKL-GLOBAL-002") {
		t.Errorf("expected PKL-GLOBAL-002 for shutil.rmtree")
	}
}

// ─── AC3: PKL-ZIP-001 compression-ratio check ────────────────────────────────

func TestAC3_ZipHighRatioNotTriggered(t *testing.T) {
	// A normal zip of a tiny benign pickle should not trigger PKL-ZIP-001.
	data := zipOf(benignPickle())
	ids, err := scan(data)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if hasID(ids, "PKL-ZIP-001") {
		t.Fatalf("unexpected PKL-ZIP-001 on normal zip, got %v", ids)
	}
}

// ─── Task 2: STACK_GLOBAL resolution tests ───────────────────────────────────

// stackGlobalPickle builds a protocol-5 pickle that uses STACK_GLOBAL to reference
// the given module and name. The two string literals are pushed via SHORT_BINUNICODE
// immediately before STACK_GLOBAL — the pattern Python 3.x emits for all protocols ≥2.
func stackGlobalPickle(module, name string) []byte {
	return newPickle().
		proto(5).
		binstring(module). // SHORT_BINUNICODE module
		binstring(name).   // SHORT_BINUNICODE name
		stackGlobal().     // 0x93 STACK_GLOBAL pops module+name
		stop().
		build()
}

// stackGlobalPickleWithReduce builds a protocol-5 pickle with STACK_GLOBAL +
// REDUCE — the standard RCE gadget shape Python uses for __reduce__ payloads.
func stackGlobalPickleWithReduce(module, name, arg string) []byte {
	return newPickle().
		proto(5).
		binstring(module).
		binstring(name).
		stackGlobal().
		mark().
		binstring(arg).
		reduce().
		stop().
		build()
}

// TestStackGlobal_DangerousModule_IsCRITICAL verifies that STACK_GLOBAL whose
// operands resolve statically to a deny-list module (posix/os) is escalated
// to PKL-GLOBAL-001 CRITICAL — not left as a conservative PKL-GLOBAL-002 HIGH.
// This is the key escalation fix: modern pickles (protocol ≥2) encode os.system
// as SHORT_BINUNICODE "posix" + SHORT_BINUNICODE "system" + STACK_GLOBAL.
func TestStackGlobal_DangerousModule_IsCRITICAL(t *testing.T) {
	cases := []struct{ module, name string }{
		{"posix", "system"},
		{"os", "system"},
		{"subprocess", "Popen"},
		{"builtins", "exec"},
		{"sys", "exit"},
	}
	for _, tc := range cases {
		t.Run(tc.module+"."+tc.name, func(t *testing.T) {
			pkl := stackGlobalPickle(tc.module, tc.name)
			ids, err := scan(pkl)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if !hasID(ids, "PKL-GLOBAL-001") {
				t.Errorf("STACK_GLOBAL %s.%s: expected PKL-GLOBAL-001 (CRITICAL), got %v",
					tc.module, tc.name, ids)
			}
			// Must NOT also fire the conservative HIGH (we resolved it precisely).
			if hasID(ids, "PKL-GLOBAL-002") {
				t.Errorf("STACK_GLOBAL %s.%s: unexpected conservative PKL-GLOBAL-002 alongside PKL-GLOBAL-001",
					tc.module, tc.name)
			}
		})
	}
}

// TestStackGlobal_PosixSystem_WithReduce_IsCRITICAL_And_REDUCE verifies the
// full RCE gadget shape that Python produces for a __reduce__ payload calling
// os.system('id'): STACK_GLOBAL(posix, system) + REDUCE → both PKL-GLOBAL-001
// CRITICAL and PKL-REDUCE-001 HIGH must be present.
func TestStackGlobal_PosixSystem_WithReduce_IsCRITICAL_And_REDUCE(t *testing.T) {
	pkl := stackGlobalPickleWithReduce("posix", "system", "id")
	ids, err := scan(pkl)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !hasID(ids, "PKL-GLOBAL-001") {
		t.Fatalf("expected PKL-GLOBAL-001 CRITICAL for posix.system via STACK_GLOBAL+REDUCE, got %v", ids)
	}
	if !hasID(ids, "PKL-REDUCE-001") {
		t.Fatalf("expected PKL-REDUCE-001 for STACK_GLOBAL+REDUCE gadget, got %v", ids)
	}
}

// TestStackGlobal_BenignModule_NoFinding verifies that benign modules commonly
// found in legitimate ML model pickles do NOT produce any dangerous finding.
// This is the no-false-positive guarantee for numpy/torch reconstructors.
func TestStackGlobal_BenignModule_NoFinding(t *testing.T) {
	benignCases := []struct{ module, name string }{
		{"numpy.core.multiarray", "_reconstruct"},
		{"numpy", "dtype"},
		{"collections", "OrderedDict"},
		{"torch._utils", "_rebuild_tensor_v2"},
		{"_codecs", "encode"}, // stdlib but not in deny/watch
	}
	for _, tc := range benignCases {
		t.Run(tc.module+"."+tc.name, func(t *testing.T) {
			pkl := stackGlobalPickle(tc.module, tc.name)
			ids, err := scan(pkl)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if hasID(ids, "PKL-GLOBAL-001") {
				t.Errorf("false positive PKL-GLOBAL-001 for benign %s.%s: %v",
					tc.module, tc.name, ids)
			}
			// PKL-GLOBAL-002 should also not fire for statically-resolved benign modules.
			if hasID(ids, "PKL-GLOBAL-002") {
				t.Errorf("false positive PKL-GLOBAL-002 for resolved-benign %s.%s: %v",
					tc.module, tc.name, ids)
			}
		})
	}
}

// TestStackGlobal_UnresolvableOperands_StaysHigh verifies that when a STACK_GLOBAL
// opcode's operands are NOT static string literals (e.g. computed/memoized),
// the scanner falls back to the conservative PKL-GLOBAL-002 HIGH finding.
// This preserves detection for evasive pickles that compute module names at runtime.
func TestStackGlobal_UnresolvableOperands_StaysHigh(t *testing.T) {
	// Build a pickle where STACK_GLOBAL is preceded by non-string opcodes
	// (BINGET, which retrieves a memoized value — not a static string literal).
	// The scanner cannot resolve the module/name statically.
	pkl := []byte{
		0x80, 0x05, // PROTO 5
		'h', 0x00,  // BINGET 0 — retrieves memo[0] (a memoized, non-static value)
		'h', 0x01,  // BINGET 1
		0x93,       // STACK_GLOBAL — operands are memo refs, not literal strings
		'.',        // STOP
	}
	ids, err := scan(pkl)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// Must still flag as PKL-GLOBAL-002 HIGH (conservative fallback).
	if !hasID(ids, "PKL-GLOBAL-002") {
		t.Fatalf("expected conservative PKL-GLOBAL-002 for unresolvable STACK_GLOBAL, got %v", ids)
	}
	// Must NOT escalate to CRITICAL (we don't know the module).
	if hasID(ids, "PKL-GLOBAL-001") {
		t.Fatalf("unexpected PKL-GLOBAL-001 for unresolvable STACK_GLOBAL: %v", ids)
	}
}

// ─── AC3: Fuzz invariant — scan must not panic (direct invocation) ────────────

func TestAC3_ScanNeverPanics(t *testing.T) {
	// A set of hostile inputs assembled from real-world byte patterns.
	hostileInputs := [][]byte{
		{},                                            // empty
		{0x80, 0x02},                                  // PROTO 2, no STOP
		{0x80, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, '.'},     // unknown opcodes before STOP
		make([]byte, 4096),                            // all-zeros
		append([]byte{0x80, 0x02, 'c'}, make([]byte, 100)...), // GLOBAL with no newlines
		{'P', 'K', 0x03, 0x04},                        // truncated ZIP magic
	}
	for i, data := range hostileInputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("input[%d]: panic: %v", i, r)
				}
			}()
			s := pickle.New()
			_, _ = s.Scan(bytes.NewReader(data), int64(len(data)))
		}()
	}
}
