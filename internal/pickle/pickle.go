// Package pickle implements a static security scanner for Python pickle streams.
// It walks opcode bytes WITHOUT unpickling, building, or executing anything.
package pickle

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/t3bik/modelvet/internal/finding"
)

const (
	// maxStreamBytes caps the total bytes we walk in a single pickle stream.
	// Protects against crafted streams that loop us forever.
	maxStreamBytes = 256 << 20 // 256 MiB

	// maxLineLen caps the length of a single newline-terminated argument line.
	maxLineLen = 64 << 10 // 64 KiB
)

// Scanner implements scan.Scanner for pickle files (raw or zip container).
type Scanner struct{}

// New returns a new pickle Scanner.
func New() *Scanner { return &Scanner{} }

// Format returns the format this scanner handles.
func (s *Scanner) Format() finding.Format { return finding.FormatPickle }

// Scan inspects the artifact. If it is a ZIP container it enters it; otherwise
// it walks the stream directly.
func (s *Scanner) Scan(ra io.ReaderAt, size int64) ([]finding.Finding, error) {
	// Peek the first 2 bytes to distinguish ZIP from raw pickle.
	if size >= 2 {
		var magic [2]byte
		if _, err := ra.ReadAt(magic[:], 0); err == nil {
			if magic[0] == 'P' && magic[1] == 'K' {
				return scanZip(ra, size)
			}
		}
	}
	return scanStream(ra, size)
}

// scanStream walks a raw pickle opcode stream.
func scanStream(ra io.ReaderAt, size int64) ([]finding.Finding, error) {
	lr := io.LimitedReader{R: readerAtToReader(ra, 0), N: maxStreamBytes}
	br := bufio.NewReader(&lr)
	return walkOpcodes(br, size)
}

// strStack tracks the last two string literals pushed onto the pickle stack.
// It is used to resolve STACK_GLOBAL operands without a full VM.
// Capacity is fixed at 2 — exactly what STACK_GLOBAL consumes.
type strStack struct {
	vals [2]string
	n    int // number of valid entries (0, 1, or 2)
}

// push records a new string push, keeping only the last 2.
func (s *strStack) push(v string) {
	if s.n < 2 {
		s.vals[s.n] = v
		s.n++
	} else {
		s.vals[0] = s.vals[1]
		s.vals[1] = v
	}
}

// pop2 returns (module, name, true) if exactly 2 strings are buffered,
// and clears the buffer. Returns ("", "", false) otherwise.
func (s *strStack) pop2() (module, name string, ok bool) {
	if s.n == 2 {
		m, nm := s.vals[0], s.vals[1]
		s.n = 0
		return m, nm, true
	}
	s.n = 0
	return "", "", false
}

// walkOpcodes performs the static opcode disassembly.
func walkOpcodes(r *bufio.Reader, size int64) ([]finding.Finding, error) {
	var findings []finding.Finding
	var globals []globalRef // accumulated GLOBAL/INST/STACK_GLOBAL refs
	hasReduce := false
	hasInst := false
	var ss strStack // lightweight stack tracking for STACK_GLOBAL resolution

	proto := -1 // -1 = not yet seen

	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		op, known := opcodeTable[b]
		if !known {
			findings = append(findings, finding.New("PKL-OPAQUE-001", -1,
				fmt.Sprintf("unrecognised opcode byte 0x%02X — possibly crafted to confuse scanners", b)))
			// Stop walking; we cannot reliably advance past an unknown opcode.
			return findings, nil
		}

		switch op.name {
		case "STOP":
			return append(findings, buildGlobalFindings(globals, hasReduce, hasInst)...), nil

		case "PROTO":
			pb, err := r.ReadByte()
			if err != nil {
				goto truncated
			}
			proto = int(pb)
			if proto < 0 || proto > 5 {
				findings = append(findings, finding.New("PKL-PROTO-001", -1,
					fmt.Sprintf("pickle protocol %d outside known range 0–5", proto)))
			}
			continue

		case "GLOBAL":
			module, name, err := readTwoLines(r)
			if err != nil {
				goto truncated
			}
			globals = append(globals, globalRef{module: module, name: name})
			continue

		case "INST":
			module, name, err := readTwoLines(r)
			if err != nil {
				goto truncated
			}
			globals = append(globals, globalRef{module: module, name: name})
			hasInst = true
			continue

		case "STACK_GLOBAL":
			// Try to resolve module/name from the last two pushed string literals.
			// If both are statically known, classify precisely; otherwise fall back
			// to conservative PKL-GLOBAL-002.
			if module, name, ok := ss.pop2(); ok {
				globals = append(globals, globalRef{module: module, name: name, stackBased: false})
			} else {
				globals = append(globals, globalRef{module: "", name: "", stackBased: true})
			}
			continue

		case "REDUCE":
			hasReduce = true

		case "NEWOBJ", "NEWOBJ_EX", "OBJ":
			hasInst = true
		}

		// For string-push opcodes, capture the value into the string stack
		// before advancing. This powers STACK_GLOBAL resolution.
		// pushString reads the argument, pushes it if non-empty and within
		// the resolvable length limit, otherwise discards and clears the stack
		// (an overlong/empty operand means we cannot statically resolve).
		switch op.name {
		case "SHORT_BINUNICODE", "SHORT_BINSTRING":
			// argBytes1: 1-byte length followed by that many bytes (always ≤255,
			// well within maxResolvableString — always captured).
			s, readErr := readBytes1String(r)
			if readErr != nil {
				goto truncated
			}
			ss.push(s)
			continue
		case "BINUNICODE", "BINSTRING":
			// argBytes4: 4-byte LE length. Returns captured=false when too long.
			s, captured, readErr := readBytes4String(r)
			if readErr != nil {
				goto truncated
			}
			if captured {
				ss.push(s)
			} else {
				ss.n = 0 // overlong — cannot use for resolution; clear stack
			}
			continue
		case "BINUNICODE8":
			// argBytes8: 8-byte LE length. Returns captured=false when too long.
			s, captured, readErr := readBytes8String(r)
			if readErr != nil {
				goto truncated
			}
			if captured {
				ss.push(s)
			} else {
				ss.n = 0 // overlong — cannot use for resolution; clear stack
			}
			continue
		}

		// Advance past the opcode's inline argument.
		if advErr := skipArg(r, op.arg); advErr != nil {
			goto truncated
		}
	}

truncated:
	findings = append(findings, finding.New("PKL-TRUNC-001", -1,
		"opcode stream ended without STOP or an opcode's argument ran past EOF"))
	return append(findings, buildGlobalFindings(globals, hasReduce, hasInst)...), nil
}

// globalRef holds a parsed GLOBAL/INST reference.
type globalRef struct {
	module     string
	name       string
	stackBased bool // from STACK_GLOBAL (module/name unknown)
}

// buildGlobalFindings converts collected global refs and reduction flags to Findings.
func buildGlobalFindings(globals []globalRef, hasReduce, hasInst bool) []finding.Finding {
	var findings []finding.Finding
	hasDeny := false
	hasWatch := false

	for _, g := range globals {
		if g.stackBased {
			// STACK_GLOBAL: module unknown — flag conservatively as watch-list.
			findings = append(findings, finding.New("PKL-GLOBAL-002", -1,
				"STACK_GLOBAL opcode: module/name are runtime values, cannot statically verify"))
			hasWatch = true
			continue
		}
		if isDeny(g.module) {
			findings = append(findings, finding.New("PKL-GLOBAL-001", -1,
				fmt.Sprintf("GLOBAL references dangerous module %q callable %q", g.module, g.name)))
			hasDeny = true
		} else if isWatch(g.module) {
			findings = append(findings, finding.New("PKL-GLOBAL-002", -1,
				fmt.Sprintf("GLOBAL references watch-listed module %q callable %q", g.module, g.name)))
			hasWatch = true
		}
	}

	if hasReduce && (hasDeny || hasWatch || len(globals) > 0) {
		findings = append(findings, finding.New("PKL-REDUCE-001", -1,
			"REDUCE opcode present alongside GLOBAL reference — standard RCE gadget shape"))
	}

	if hasInst && (hasDeny || hasWatch) {
		findings = append(findings, finding.New("PKL-INST-001", -1,
			"INST/OBJ/NEWOBJ with dangerous global — construction-time execution path"))
	}

	return findings
}

// ── argument skipping helpers ─────────────────────────────────────────────────

func skipArg(r *bufio.Reader, kind argKind) error {
	switch kind {
	case argNone:
		return nil
	case argByte:
		_, err := r.ReadByte()
		return err
	case argShort:
		return discard(r, 2)
	case argInt4:
		return discard(r, 4)
	case argInt8:
		return discard(r, 8)
	case argLine, argDecimal, argUnicode:
		return skipLine(r)
	case argLine2:
		if err := skipLine(r); err != nil {
			return err
		}
		return skipLine(r)
	case argInst:
		if err := skipLine(r); err != nil {
			return err
		}
		return skipLine(r)
	case argBytes1:
		lb, err := r.ReadByte()
		if err != nil {
			return err
		}
		return discard(r, int(lb))
	case argBytes4:
		var buf [4]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return err
		}
		n := int64(binary.LittleEndian.Uint32(buf[:]))
		if n > maxStreamBytes {
			return fmt.Errorf("bytes4 length %d exceeds cap", n)
		}
		return discard(r, int(n))
	case argBytes8:
		var buf [8]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return err
		}
		n := binary.LittleEndian.Uint64(buf[:])
		if n > maxStreamBytes {
			return fmt.Errorf("bytes8 length %d exceeds cap", n)
		}
		return discard(r, int(n))
	case argUnicode4:
		var buf [4]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return err
		}
		n := int64(binary.LittleEndian.Uint32(buf[:]))
		if n > maxStreamBytes {
			return fmt.Errorf("unicode4 length %d exceeds cap", n)
		}
		return discard(r, int(n))
	}
	return nil
}

func skipLine(r *bufio.Reader) error {
	for i := 0; i < maxLineLen; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		if b == '\n' {
			return nil
		}
	}
	return fmt.Errorf("line exceeds maxLineLen")
}

func discard(r *bufio.Reader, n int) error {
	if n <= 0 {
		return nil
	}
	discarded, err := r.Discard(n)
	if err != nil {
		if discarded < n {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	return nil
}

// ── string-push helpers for STACK_GLOBAL resolution ──────────────────────────

// maxResolvableString caps the string length we will capture for STACK_GLOBAL
// resolution. Strings longer than this (e.g. raw tensor data accidentally
// labelled as a string) are discarded and the stack entry is left unresolved.
const maxResolvableString = 512

// readBytes1String reads a SHORT_BINUNICODE / SHORT_BINSTRING argument:
// 1-byte length prefix, then that many bytes.
func readBytes1String(r *bufio.Reader) (string, error) {
	lb, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	n := int(lb)
	if n == 0 {
		return "", nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// readBytes4String reads a BINUNICODE / BINSTRING argument:
// 4-byte LE length prefix, then that many bytes.
// Returns (value, captured, error) where captured=false means the string was
// too long to use for STACK_GLOBAL resolution (it was still read/discarded).
func readBytes4String(r *bufio.Reader) (string, bool, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", false, err
	}
	n := int64(binary.LittleEndian.Uint32(lenBuf[:]))
	if n > maxStreamBytes {
		return "", false, fmt.Errorf("bytes4 length %d exceeds cap", n)
	}
	if n > maxResolvableString {
		// Too long to be a module/name — discard but do not capture.
		if err := discard(r, int(n)); err != nil {
			return "", false, err
		}
		return "", false, nil
	}
	if n == 0 {
		return "", true, nil // genuine empty string — captured
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", false, err
	}
	return string(buf), true, nil
}

// readBytes8String reads a BINUNICODE8 argument:
// 8-byte LE length prefix, then that many bytes.
// Returns (value, captured, error); captured=false when too long to resolve.
func readBytes8String(r *bufio.Reader) (string, bool, error) {
	var lenBuf [8]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", false, err
	}
	n := binary.LittleEndian.Uint64(lenBuf[:])
	if n > maxStreamBytes {
		return "", false, fmt.Errorf("bytes8 length %d exceeds cap", n)
	}
	if n > maxResolvableString {
		if err := discard(r, int(n)); err != nil {
			return "", false, err
		}
		return "", false, nil
	}
	if n == 0 {
		return "", true, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", false, err
	}
	return string(buf), true, nil
}

// readTwoLines reads two newline-terminated lines (module and name for GLOBAL/INST).
func readTwoLines(r *bufio.Reader) (module, name string, err error) {
	module, err = readLine(r)
	if err != nil {
		return "", "", err
	}
	name, err = readLine(r)
	if err != nil {
		return "", "", err
	}
	return module, name, nil
}

func readLine(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for i := 0; i < maxLineLen; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			return sb.String(), nil
		}
		sb.WriteByte(b)
	}
	return "", fmt.Errorf("line exceeds maxLineLen")
}

// readerAtToReader wraps an io.ReaderAt as an io.Reader starting at off.
func readerAtToReader(ra io.ReaderAt, off int64) io.Reader {
	return &readerAtReader{ra: ra, off: off}
}

type readerAtReader struct {
	ra  io.ReaderAt
	off int64
}

func (r *readerAtReader) Read(p []byte) (int, error) {
	n, err := r.ra.ReadAt(p, r.off)
	r.off += int64(n)
	return n, err
}

// ── scanZip: PyTorch zip container ────────────────────────────────────────────

// scanZip is delegated to zip.go.
