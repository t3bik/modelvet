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

// Detect identifies the format of the artifact at ra/size using magic bytes
// (primary) and filename extension (fallback). Returns FormatUnknown if
// neither matches.
func Detect(ra io.ReaderAt, size int64, filename string) DetectedFormat {
	ext := strings.ToLower(filepath.Ext(filename))

	// Try magic-byte detection first.
	if size >= 4 {
		var magic [4]byte
		if _, err := ra.ReadAt(magic[:], 0); err == nil {
			// GGUF: first 4 bytes == "GGUF"
			if magic[0] == 'G' && magic[1] == 'G' && magic[2] == 'U' && magic[3] == 'F' {
				return DetectedFormat{Format: finding.FormatGGUF, ByMagic: true}
			}
			// ZIP (PyTorch .pt/.pth): PK magic
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
	case ".pkl", ".pickle":
		return DetectedFormat{Format: finding.FormatPickle}
	case ".pt", ".pth", ".bin", ".zip":
		return DetectedFormat{Format: finding.FormatPickle}
	}

	return DetectedFormat{Format: finding.FormatUnknown}
}
