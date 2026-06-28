// Package numpy implements a static security scanner for numpy .npy and .npz
// artifacts. It detects object-dtype arrays whose data region is a pickle
// stream, and runs the existing pickle opcode scanner on that region WITHOUT
// executing or unpickling anything.
package numpy

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/t3bik/modelvet/internal/finding"
	"github.com/t3bik/modelvet/internal/pickle"
	"github.com/t3bik/modelvet/internal/safeio"
)

// npy magic: \x93NUMPY
var npyMagic = []byte{0x93, 'N', 'U', 'M', 'P', 'Y'}

const (
	// npyMagicLen is the length of the magic prefix.
	npyMagicLen = 6

	// npyMinHeaderSize is the smallest possible .npy file:
	// 6 magic + 1 major + 1 minor + 2 header-len (v1) = 10 bytes.
	npyMinHeaderSize = 10

	// npyHeaderCap is the maximum header size we will allocate.
	// Real numpy headers are a few hundred bytes; 1 MiB is generous.
	npyHeaderCap = 1 << 20 // 1 MiB

	// maxAllocBytes caps a single safeio allocation for the numpy scanner.
	maxAllocBytes = 256 << 20 // 256 MiB

	// npzMaxEntries caps the number of zip entries enumerated.
	npzMaxEntries = 10_000

	// npzMaxUncompressedEntry is the maximum size we decompress per .npy entry.
	npzMaxUncompressedEntry = 256 << 20 // 256 MiB

	// npzMaxTotalUncompressed is the total cap across all .npy entries.
	npzMaxTotalUncompressed = 512 << 20 // 512 MiB

	// npzBombRatioThreshold: flag when uncompressed/compressed > this.
	npzBombRatioThreshold = 1000
)

// Scanner implements scan.Scanner for .npy and .npz files.
type Scanner struct{}

// New returns a new numpy Scanner.
func New() *Scanner { return &Scanner{} }

// Format returns the format this scanner handles.
func (s *Scanner) Format() finding.Format { return finding.FormatNumpy }

// Scan inspects the artifact. .npz files are entered as zip containers; .npy
// files are parsed directly.
func (s *Scanner) Scan(ra io.ReaderAt, size int64) ([]finding.Finding, error) {
	// Detect .npz by PK magic (ZIP), independent of filename — the caller
	// already routes based on magic+extension. Here we check again to support
	// the case where the scanner is invoked directly in tests.
	if size >= 4 {
		var pk [2]byte
		if _, err := ra.ReadAt(pk[:], 0); err == nil {
			if pk[0] == 'P' && pk[1] == 'K' {
				return scanNpz(ra, size)
			}
		}
	}
	return scanNpy(ra, size)
}

// ── .npy parser ──────────────────────────────────────────────────────────────

// scanNpy parses a single .npy file and returns findings.
func scanNpy(ra io.ReaderAt, size int64) ([]finding.Finding, error) {
	r := safeio.NewReader(ra, size, maxAllocBytes)

	if size < npyMinHeaderSize {
		return []finding.Finding{
			finding.New("NPY-TRUNC-001", 0,
				fmt.Sprintf(".npy file too short (%d bytes, minimum %d)", size, npyMinHeaderSize)),
		}, nil
	}

	// ── magic ─────────────────────────────────────────────────────────────────
	magic, err := r.Bytes(0, int64(npyMagicLen))
	if err != nil {
		return nil, fmt.Errorf("numpy: read magic: %w", err)
	}
	if !bytes.Equal(magic, npyMagic) {
		// Not a .npy file — return no findings and a nil error; detect.go
		// should not have routed here for non-.npy magic, but be safe.
		return nil, fmt.Errorf("numpy: not a .npy file (bad magic)")
	}

	// ── version ───────────────────────────────────────────────────────────────
	versionBuf, err := r.Bytes(npyMagicLen, 2)
	if err != nil {
		return []finding.Finding{
			finding.New("NPY-TRUNC-001", int64(npyMagicLen),
				"file ends before version bytes"),
		}, nil
	}
	major := versionBuf[0]
	minor := versionBuf[1]

	var findings []finding.Finding

	// Known versions: 1.0, 2.0, 3.0.
	if (major != 1 && major != 2 && major != 3) || minor != 0 {
		findings = append(findings, finding.New("NPY-VERSION-001",
			int64(npyMagicLen),
			fmt.Sprintf("unknown .npy version %d.%d (known: 1.0, 2.0, 3.0)", major, minor)))
		// We can still attempt to parse — header-length field position is the
		// only thing that differs, and we only know it for major 1/2/3.
		// For truly unknown majors, stop here.
		if major != 1 && major != 2 && major != 3 {
			return findings, nil
		}
	}

	// ── header length field ───────────────────────────────────────────────────
	// v1.0: uint16 LE at offset 8 → header starts at offset 10.
	// v2.0/v3.0: uint32 LE at offset 8 → header starts at offset 12.
	var headerLen int64
	var dataOff int64

	switch major {
	case 1:
		if size < 10 {
			return append(findings, finding.New("NPY-TRUNC-001", 8,
				"file too short for v1.0 header-length field")), nil
		}
		var buf [2]byte
		if err := r.ReadAt(buf[:], 8); err != nil {
			return append(findings, finding.New("NPY-TRUNC-001", 8,
				"cannot read v1.0 header-length uint16")), nil
		}
		headerLen = int64(binary.LittleEndian.Uint16(buf[:]))
		dataOff = 10 + headerLen

	case 2, 3:
		if size < 12 {
			return append(findings, finding.New("NPY-TRUNC-001", 8,
				"file too short for v2.0/v3.0 header-length field")), nil
		}
		v, err := r.U32(8)
		if err != nil {
			return append(findings, finding.New("NPY-TRUNC-001", 8,
				"cannot read v2.0/v3.0 header-length uint32")), nil
		}
		headerLen = int64(v)
		dataOff = 12 + headerLen
	}

	// ── sanity: header length vs file size ────────────────────────────────────
	// Overflow-safe: check headerLen > size-dataOff (after establishing dataOff <= size).
	// Because dataOff = prefixLen + headerLen, we need: dataOff <= size.
	if headerLen > npyHeaderCap {
		findings = append(findings, finding.New("NPY-HEADER-001",
			8,
			fmt.Sprintf("header length %d exceeds sanity cap %d — possible DoS", headerLen, npyHeaderCap)))
		return findings, nil
	}
	if dataOff > size {
		findings = append(findings, finding.New("NPY-TRUNC-001",
			8,
			fmt.Sprintf("header length %d causes header to extend beyond file size %d", headerLen, size)))
		return findings, nil
	}

	// ── read the header dict ──────────────────────────────────────────────────
	prefixLen := dataOff - headerLen // 10 or 12
	headerBytes, err := r.Bytes(prefixLen, headerLen)
	if err != nil {
		return append(findings, finding.New("NPY-TRUNC-001",
			prefixLen,
			fmt.Sprintf("cannot read header dict (%d bytes): %v", headerLen, err))), nil
	}

	// ── parse descr from header dict ─────────────────────────────────────────
	descr, ok := parseDescr(headerBytes)
	if !ok {
		findings = append(findings, finding.New("NPY-HEADER-001",
			prefixLen,
			"cannot parse 'descr' value from .npy header dict"))
		return findings, nil
	}

	// ── object dtype check ────────────────────────────────────────────────────
	if !isObjectDtype(descr) {
		// Benign dtype — no findings.
		return findings, nil
	}

	// Object dtype found: the data region is a pickle stream.
	findings = append(findings, finding.New("NPY-OBJECT-001",
		dataOff,
		fmt.Sprintf("object dtype %q detected; data region at offset %d is a pickle stream", descr, dataOff)))

	// ── scan the pickle data region ───────────────────────────────────────────
	dataSize := size - dataOff
	if dataSize > 0 {
		pklFindings := scanPickleRegion(ra, dataOff, dataSize)
		findings = append(findings, pklFindings...)
	}

	return findings, nil
}

// scanPickleRegion runs the pickle scanner on the byte range [off, off+size).
// It adapts the region into an io.ReaderAt via a sub-reader so the pickle
// scanner sees it as a standalone stream starting at offset 0.
func scanPickleRegion(ra io.ReaderAt, off, size int64) []finding.Finding {
	sub := &subReaderAt{ra: ra, base: off}
	s := pickle.New()
	findings, _ := s.Scan(sub, size)
	return findings
}

// subReaderAt wraps an io.ReaderAt and shifts all offsets by base.
// This lets a sub-region of a file appear as a standalone stream.
type subReaderAt struct {
	ra   io.ReaderAt
	base int64
}

func (s *subReaderAt) ReadAt(p []byte, off int64) (int, error) {
	return s.ra.ReadAt(p, s.base+off)
}

// ── .npz (zip of .npy) parser ────────────────────────────────────────────────

// scanNpz opens a .npz zip container and scans each .npy entry inside.
// It reuses the same zip-bomb / entry-count / size caps as the pickle zip path.
func scanNpz(ra io.ReaderAt, size int64) ([]finding.Finding, error) {
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return nil, fmt.Errorf("numpy/npz: open zip: %w", err)
	}

	var findings []finding.Finding

	if len(zr.File) > npzMaxEntries {
		findings = append(findings, finding.New("NPY-HEADER-001", -1,
			fmt.Sprintf("zip has %d entries, exceeds cap of %d (zip-bomb signal)", len(zr.File), npzMaxEntries)))
		return findings, nil
	}

	var totalUncompressed uint64

	for _, f := range zr.File {
		// Only scan .npy entries.
		if !strings.HasSuffix(strings.ToLower(path.Base(f.Name)), ".npy") {
			continue
		}

		// Zip-bomb: compression ratio check.
		if f.CompressedSize64 > 0 {
			ratio := f.UncompressedSize64 / f.CompressedSize64
			if ratio > npzBombRatioThreshold {
				findings = append(findings, finding.New("NPY-HEADER-001", -1,
					fmt.Sprintf("npz entry %q has compression ratio %d× (zip-bomb signal)", f.Name, ratio)))
				break
			}
		}

		if f.UncompressedSize64 > npzMaxUncompressedEntry {
			findings = append(findings, finding.New("NPY-HEADER-001", -1,
				fmt.Sprintf("npz entry %q uncompressed size %d exceeds per-entry cap", f.Name, f.UncompressedSize64)))
			continue
		}

		totalUncompressed += f.UncompressedSize64
		if totalUncompressed > npzMaxTotalUncompressed {
			findings = append(findings, finding.New("NPY-HEADER-001", -1,
				"total uncompressed size of .npy entries in .npz exceeds cap"))
			break
		}

		// Decompress into a bounded reader, then scan as .npy.
		rc, err := f.Open()
		if err != nil {
			findings = append(findings, finding.New("NPY-TRUNC-001", -1,
				fmt.Sprintf("npz entry %q: cannot open: %v", f.Name, err)))
			continue
		}

		lr := &io.LimitedReader{R: rc, N: npzMaxUncompressedEntry}
		data, readErr := io.ReadAll(lr)
		_ = rc.Close()
		if readErr != nil {
			findings = append(findings, finding.New("NPY-TRUNC-001", -1,
				fmt.Sprintf("npz entry %q: read error: %v", f.Name, readErr)))
			continue
		}

		entryRA := bytes.NewReader(data)
		entryFindings, _ := scanNpy(entryRA, int64(len(data)))
		findings = append(findings, entryFindings...)
	}

	return findings, nil
}

// ── header parsing helpers ────────────────────────────────────────────────────

// parseDescr extracts the value of the 'descr' key from a numpy header dict.
// The header is an ASCII Python dict literal, e.g.:
//
//	{'descr': '<f4', 'fortran_order': False, 'shape': (3,), }
//
// This is a minimal parser: it locates 'descr': and extracts the quoted value.
// Returns ("", false) if parsing fails.
func parseDescr(header []byte) (descr string, ok bool) {
	s := strings.TrimSpace(string(header))
	// Strip enclosing braces.
	s = strings.TrimRight(s, " \n")

	// Scan for 'descr' key.
	idx := strings.Index(s, "'descr'")
	if idx < 0 {
		// Also try double-quoted form.
		idx = strings.Index(s, `"descr"`)
		if idx < 0 {
			return "", false
		}
	}

	// Advance past the key.
	rest := s[idx+7:] // len("'descr'") == 7
	// Skip whitespace and colon.
	br := bufio.NewReader(strings.NewReader(rest))
	for {
		b, err := br.ReadByte()
		if err != nil {
			return "", false
		}
		if b == ':' {
			break
		}
		if b != ' ' && b != '\t' {
			return "", false
		}
	}
	// Skip whitespace after colon.
	for {
		b, err := br.ReadByte()
		if err != nil {
			return "", false
		}
		if b == '\'' || b == '"' {
			quote := b
			// Read until matching close-quote.
			var val strings.Builder
			for {
				c, err2 := br.ReadByte()
				if err2 != nil {
					return "", false
				}
				if c == quote {
					return val.String(), true
				}
				val.WriteByte(c)
			}
		}
		if b != ' ' && b != '\t' {
			return "", false
		}
	}
}

// isObjectDtype reports whether a numpy dtype descriptor represents the object
// dtype, which causes array data to be stored as a pickle stream.
//
// Object dtype indicators:
//   - "|O"     — explicit object dtype
//   - "O"      — shorthand (rare, but legal)
//   - any descriptor containing 'O' as a standalone field type in a structured
//     dtype, e.g. [('f0', 'O'), ('f1', '<f4')]
//
// For simple scalar dtypes the rules are:
//   - "|O" or "O" → object
//   - anything else → not object
//
// For structured dtypes (lists with 'O' field) we check conservatively.
func isObjectDtype(descr string) bool {
	d := strings.TrimSpace(descr)
	// Simple scalar object dtype.
	if d == "|O" || d == "O" || d == "|O8" {
		return true
	}
	// Structured dtype: a list like "[('name', 'O'), ...]"
	// We check for the pattern "'O'" or "\"O\"" inside the descriptor.
	if strings.HasPrefix(d, "[") {
		if strings.Contains(d, "'O'") || strings.Contains(d, `"O"`) {
			return true
		}
	}
	return false
}
