package numpy_test

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
)

// ── .npy byte builders ────────────────────────────────────────────────────────

// npyMagic is the 6-byte numpy magic: \x93NUMPY.
var npyMagic = []byte{0x93, 'N', 'U', 'M', 'P', 'Y'}

// buildNpy assembles a v1.0 .npy file with the given header dict string and
// data payload.
//
// Layout: magic(6) + major(1) + minor(1) + header_len uint16 LE + header + data.
// The header is padded with spaces to a 64-byte boundary (ending in '\n').
func buildNpy(header string, data []byte) []byte {
	// Pad header to 64-byte boundary: total = 10 + pad + header → multiple of 64.
	// prefixLen = 10 (magic + version + uint16)
	const prefixLen = 10
	// header must end in '\n'; pad with spaces before the '\n'.
	headerBytes := []byte(header)
	// Make total (prefixLen + len(headerBytes)) a multiple of 64.
	for (prefixLen+len(headerBytes))%64 != 0 {
		headerBytes = append([]byte{' '}, headerBytes...) // prepend space
	}
	// Actually numpy pads AFTER the dict literal and before '\n'.
	// Rebuild: the header is exactly headerLen bytes and ends in '\n'.
	// The standard form pads spaces inside the dict (after the last comma).
	// For test purposes, just prepend spaces so total is aligned.

	var buf bytes.Buffer
	buf.Write(npyMagic)
	buf.WriteByte(1) // major
	buf.WriteByte(0) // minor
	hlen := uint16(len(headerBytes))
	_ = binary.Write(&buf, binary.LittleEndian, hlen)
	buf.Write(headerBytes)
	buf.Write(data)
	return buf.Bytes()
}

// buildNpyV2 assembles a v2.0 .npy file (uint32 header length).
func buildNpyV2(header string, data []byte) []byte {
	headerBytes := []byte(header)
	var buf bytes.Buffer
	buf.Write(npyMagic)
	buf.WriteByte(2) // major
	buf.WriteByte(0) // minor
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(headerBytes)))
	buf.Write(headerBytes)
	buf.Write(data)
	return buf.Bytes()
}

// benignNpy returns a .npy with float32 dtype — no object dtype, no findings.
func benignNpy() []byte {
	header := "{'descr': '<f4', 'fortran_order': False, 'shape': (3,), }\n"
	data := make([]byte, 12) // 3 × float32
	return buildNpy(header, data)
}

// objectNpy returns a .npy with object dtype and the given pickle bytes as data.
func objectNpy(pickleData []byte) []byte {
	header := "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }\n"
	return buildNpy(header, pickleData)
}

// malformedHeaderNpy returns a .npy where the header dict is garbage.
func malformedHeaderNpy() []byte {
	header := "NOT A VALID DICT\n"
	return buildNpy(header, nil)
}

// truncatedNpy returns a .npy where the header_len field claims more bytes than exist.
func truncatedNpy() []byte {
	var buf bytes.Buffer
	buf.Write(npyMagic)
	buf.WriteByte(1) // major
	buf.WriteByte(0) // minor
	// Claim a header of 10000 bytes but write nothing after.
	_ = binary.Write(&buf, binary.LittleEndian, uint16(10000))
	// No header bytes follow.
	return buf.Bytes()
}

// unknownVersionNpy returns a .npy with an unrecognised major version.
func unknownVersionNpy() []byte {
	var buf bytes.Buffer
	buf.Write(npyMagic)
	buf.WriteByte(99) // unknown major
	buf.WriteByte(0)
	return buf.Bytes()
}

// ── pickle helper (re-assembles from opcodes — no Python) ────────────────────

// osSystemPickle returns a pickle that calls os.system("id") via REDUCE.
// Assembled entirely from opcode bytes — same as fixtures_test.go in pickle/.
func osSystemPickle() []byte {
	var buf bytes.Buffer
	// PROTO 2
	buf.Write([]byte{0x80, 0x02})
	// GLOBAL "os\nsystem\n"
	buf.WriteByte('c')
	buf.WriteString("os\nsystem\n")
	// MARK
	buf.WriteByte('(')
	// SHORT_BINSTRING "id"
	buf.WriteByte('U')
	buf.WriteByte(0x02)
	buf.WriteString("id")
	// REDUCE
	buf.WriteByte('R')
	// STOP
	buf.WriteByte('.')
	return buf.Bytes()
}

// ── .npz builder ─────────────────────────────────────────────────────────────

// buildNpz creates a zip archive containing the given files (name → bytes).
func buildNpz(entries map[string][]byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			panic(err)
		}
		if _, err := w.Write(data); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
