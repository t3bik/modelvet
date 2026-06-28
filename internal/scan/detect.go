package scan

import (
	"io"
	"path/filepath"
	"strings"

	"github.com/t3bik/modelvet/internal/finding"
)

// DetectedFormat is the result of format detection.
type DetectedFormat struct {
	Format  finding.Format
	ByMagic bool // true if magic bytes matched (stronger signal than extension)
}

// npyMagic is the 6-byte magic prefix for numpy .npy files: \x93NUMPY.
var npyMagic = []byte{0x93, 'N', 'U', 'M', 'P', 'Y'}

// Detect identifies the format of the artifact at ra/size using magic bytes
// (primary) and filename extension (fallback). Returns FormatUnknown if
// neither matches.
//
// Special case: .npz files carry PK (ZIP) magic but must route to the numpy
// scanner, not the generic pickle/PyTorch zip scanner. Extension check for
// ".npz" is therefore applied BEFORE the generic PK magic check.
func Detect(ra io.ReaderAt, size int64, filename string) DetectedFormat {
	ext := strings.ToLower(filepath.Ext(filename))

	// .npz: extension checked FIRST — it is a ZIP but must route to numpy,
	// not the generic pickle zip path. Content is still confirmed by PK magic.
	if ext == ".npz" {
		if size >= 2 {
			var pk [2]byte
			if _, err := ra.ReadAt(pk[:], 0); err == nil && pk[0] == 'P' && pk[1] == 'K' {
				return DetectedFormat{Format: finding.FormatNumpy, ByMagic: true}
			}
		}
		return DetectedFormat{Format: finding.FormatNumpy, ByMagic: false}
	}

	// .npy: strong magic \x93NUMPY wins over any extension.
	if size >= 6 {
		var m [6]byte
		if _, err := ra.ReadAt(m[:], 0); err == nil {
			if m[0] == npyMagic[0] && m[1] == npyMagic[1] && m[2] == npyMagic[2] &&
				m[3] == npyMagic[3] && m[4] == npyMagic[4] && m[5] == npyMagic[5] {
				return DetectedFormat{Format: finding.FormatNumpy, ByMagic: true}
			}
		}
	}

	// Try magic-byte detection for other formats.
	if size >= 4 {
		var magic [4]byte
		if _, err := ra.ReadAt(magic[:], 0); err == nil {
			// GGUF: first 4 bytes == "GGUF"
			if magic[0] == 'G' && magic[1] == 'G' && magic[2] == 'U' && magic[3] == 'F' {
				return DetectedFormat{Format: finding.FormatGGUF, ByMagic: true}
			}
			// ZIP (PyTorch .pt/.pth): PK magic — only after .npz extension is ruled out above.
			if magic[0] == 'P' && magic[1] == 'K' {
				return DetectedFormat{Format: finding.FormatPickle, ByMagic: true}
			}
		}
	}

	// safetensors: heuristic — extension is primary; confirm by 8-byte length + '{'.
	if ext == ".safetensors" {
		if size >= 9 {
			var peek [9]byte
			if _, err := ra.ReadAt(peek[:], 0); err == nil {
				if peek[8] == '{' {
					return DetectedFormat{Format: finding.FormatSafetensors, ByMagic: true}
				}
			}
		}
		// Extension alone is sufficient for safetensors.
		return DetectedFormat{Format: finding.FormatSafetensors, ByMagic: false}
	}

	// pickle: check protocol magic (0x80 followed by version 1–5, or classic opcodes).
	if size >= 2 {
		var pm [2]byte
		if _, err := ra.ReadAt(pm[:], 0); err == nil {
			if pm[0] == 0x80 && pm[1] >= 1 && pm[1] <= 5 {
				return DetectedFormat{Format: finding.FormatPickle, ByMagic: true}
			}
		}
	}

	// Extension fallback.
	switch ext {
	case ".gguf":
		return DetectedFormat{Format: finding.FormatGGUF}
	case ".npy":
		return DetectedFormat{Format: finding.FormatNumpy}
	case ".pkl", ".pickle":
		return DetectedFormat{Format: finding.FormatPickle}
	case ".pt", ".pth", ".bin", ".zip":
		return DetectedFormat{Format: finding.FormatPickle}
	}

	return DetectedFormat{Format: finding.FormatUnknown}
}
