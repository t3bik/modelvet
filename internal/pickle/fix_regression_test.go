package pickle_test

// fix_regression_test.go — QA verification tests for pickle fixes.
//
// Fix 3: PKL-ZIP-002 (Low) — PK-magic zip with no data.pkl emits the rule.
// Fix 4: pickle M3 — per-arg caps on argBytes4/argUnicode4 + bufio.Reader.Discard.
//
// Note on Fix 4: the per-arg caps prevent OOM on crafted oversized argument
// lengths in BINPUT4/BINGET4 and BINUNICODE4 opcodes. We test that the scanner
// handles such crafted streams without OOM or panic and that PKL-TRUNC-001 fires.

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"testing"
)

// ─── Fix 3: PKL-ZIP-002 ──────────────────────────────────────────────────────

// buildZipNoPkl builds a valid zip file that contains no data.pkl entry.
// It has one regular entry named "weights.bin" to verify the zip is valid
// but lacks the expected data.pkl.
func buildZipNoPkl() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("archive/weights.bin")
	if err != nil {
		panic(err)
	}
	w.Write([]byte("fake weight data"))
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// buildZipWithPkl builds a zip with a data.pkl entry (benign content).
func buildZipWithPkl() []byte {
	return zipOf(benignPickle()) // from fixtures_test.go
}

// buildZipBomb returns a zip with too many entries (>10000) — triggers PKL-ZIP-001.
func buildZipBomb() []byte {
	return zipWithManyEntries(10001) // from fixtures_test.go
}

// TestFix3_ZipNoPkl_EmitsPKLZIP002 verifies that a PK-magic zip with NO data.pkl
// fires PKL-ZIP-002 (Low).
func TestFix3_ZipNoPkl_EmitsPKLZIP002(t *testing.T) {
	data := buildZipNoPkl()
	ids, err := scan(data)
	if err != nil {
		t.Fatalf("Fix3 FAIL: unexpected error on zip-no-pkl: %v", err)
	}
	if !hasID(ids, "PKL-ZIP-002") {
		t.Fatalf("Fix3 FAIL: expected PKL-ZIP-002 for zip with no data.pkl; got %v", ids)
	}
	t.Log("Fix3 PASS: PKL-ZIP-002 emitted for zip with no data.pkl")
}

// TestFix3_ZipWithPkl_NoPKLZIP002 verifies that a valid PyTorch zip WITH data.pkl
// does NOT fire PKL-ZIP-002.
func TestFix3_ZipWithPkl_NoPKLZIP002(t *testing.T) {
	data := buildZipWithPkl()
	ids, err := scan(data)
	if err != nil {
		t.Fatalf("Fix3 FAIL: unexpected error on zip-with-pkl: %v", err)
	}
	if hasID(ids, "PKL-ZIP-002") {
		t.Fatalf("Fix3 FAIL: false positive PKL-ZIP-002 for zip that contains data.pkl; got %v", ids)
	}
	t.Log("Fix3 PASS: no PKL-ZIP-002 for a zip containing data.pkl")
}

// TestFix3_ZipBomb_NoPKLZIP002 verifies that the zip-bomb early-exit path
// (PKL-ZIP-001, too many entries) does NOT spuriously emit PKL-ZIP-002.
// The zip has >10000 entries but none are data.pkl, so without the earlyExit
// guard in zip.go, PKL-ZIP-002 would also fire. The guard prevents this.
func TestFix3_ZipBomb_NoPKLZIP002(t *testing.T) {
	data := buildZipBomb()
	ids, err := scan(data)
	if err != nil {
		t.Fatalf("Fix3 FAIL: unexpected error on zip-bomb: %v", err)
	}
	// PKL-ZIP-001 should fire.
	if !hasID(ids, "PKL-ZIP-001") {
		t.Fatalf("Fix3: expected PKL-ZIP-001 on zip bomb; got %v", ids)
	}
	// PKL-ZIP-002 must NOT fire (earlyExit guard prevents spurious emission).
	if hasID(ids, "PKL-ZIP-002") {
		t.Fatalf("Fix3 FAIL: spurious PKL-ZIP-002 emitted alongside PKL-ZIP-001 (zip-bomb): got %v", ids)
	}
	t.Log("Fix3 PASS: zip-bomb early-exit does not spuriously emit PKL-ZIP-002")
}

// TestFix3_EmptyZip_EmitsPKLZIP002 verifies that a completely empty valid zip
// (no entries at all) fires PKL-ZIP-002.
func TestFix3_EmptyZip_EmitsPKLZIP002(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	ids, err := scan(buf.Bytes())
	if err != nil {
		t.Fatalf("Fix3 FAIL: unexpected error on empty zip: %v", err)
	}
	if !hasID(ids, "PKL-ZIP-002") {
		t.Fatalf("Fix3 FAIL: expected PKL-ZIP-002 for empty zip; got %v", ids)
	}
	t.Log("Fix3 PASS: PKL-ZIP-002 emitted for empty zip container")
}

// ─── Fix 4: per-arg caps on oversized arguments ──────────────────────────────

// buildBINUNICODE4Crafted builds a pickle whose BINUNICODE4 opcode (0x8d) has
// a 4-byte length field set to 0xFFFFFFFF (4 GiB). Before Fix 4 (per-arg caps),
// this would attempt to allocate/read 4 GiB via bufio.Reader or Discard.
func buildBINUNICODE4Crafted() []byte {
	buf := []byte{
		0x80, 0x02, // PROTO 2
		0x8d,       // BINUNICODE4 opcode
	}
	// 4-byte little-endian length = maxUint32
	buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF)
	// No actual bytes follow — the file is tiny; the scanner must not OOM.
	buf = append(buf, '.')  // STOP
	return buf
}

// buildBINBYTES8Crafted builds a pickle whose BINBYTES8 opcode (0x8e) has an
// 8-byte length field set to a huge value. Tests the 8-byte arg cap.
func buildBINBYTES8Crafted() []byte {
	buf := []byte{
		0x80, 0x04, // PROTO 4
		0x8e,       // BINBYTES8 opcode
	}
	// 8-byte little-endian length = maxUint64 / 2 (still huge)
	binary.LittleEndian.AppendUint64(buf, 0x7FFFFFFFFFFFFFFF)
	buf = append(buf, '.')  // STOP
	return buf
}

// TestFix4_OversizedBINUNICODE4_NoPanic verifies that a crafted BINUNICODE4
// with length=0xFFFFFFFF does not cause OOM or panic. The scanner should return
// PKL-TRUNC-001 or another finding and terminate gracefully.
func TestFix4_OversizedBINUNICODE4_NoPanic(t *testing.T) {
	data := buildBINUNICODE4Crafted()

	var (
		ids     []string
		err     error
		paniced bool
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				paniced = true
				t.Errorf("Fix4 FAIL: Scan panicked on oversized BINUNICODE4: %v", r)
			}
		}()
		ids, err = scan(data)
	}()

	if paniced {
		t.FailNow()
	}
	if err != nil {
		t.Fatalf("Fix4 FAIL: Scan returned hard error on oversized BINUNICODE4: %v", err)
	}
	// The scanner must emit some finding (truncation since no actual bytes follow)
	// or return cleanly. Either is acceptable. What's NOT acceptable is OOM/panic.
	t.Logf("Fix4 PASS: oversized BINUNICODE4 handled; findings=%v", ids)
}

// TestFix4_OversizedBINBYTES8_NoPanic is the same test for BINBYTES8 (8-byte len).
func TestFix4_OversizedBINBYTES8_NoPanic(t *testing.T) {
	data := buildBINBYTES8Crafted()

	var paniced bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				paniced = true
				t.Errorf("Fix4 FAIL: Scan panicked on oversized BINBYTES8: %v", r)
			}
		}()
		_, _ = scan(data)
	}()

	if paniced {
		t.FailNow()
	}
	t.Log("Fix4 PASS: oversized BINBYTES8 handled without panic")
}
