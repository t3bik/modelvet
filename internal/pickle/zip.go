package pickle

import (
	"archive/zip"
	"bufio"
	"fmt"
	"io"
	"path"

	"github.com/t3bik/modelvet/internal/finding"
)

const (
	// zipMaxEntries caps the number of zip entries we enumerate.
	zipMaxEntries = 10_000

	// zipMaxUncompressedEntry is the maximum uncompressed size we decompress
	// per data.pkl entry (32 MiB — pickles are tiny; weights are not decompressed).
	zipMaxUncompressedEntry = 32 << 20

	// zipMaxTotalUncompressed is the total cap across all data.pkl entries.
	zipMaxTotalUncompressed = 128 << 20

	// zipBombRatioThreshold: if uncompressed/compressed > this, flag.
	zipBombRatioThreshold = 1000
)

// scanZip opens a PyTorch-style zip container and scans each data.pkl inside.
func scanZip(ra io.ReaderAt, size int64) ([]finding.Finding, error) {
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return nil, fmt.Errorf("pickle/zip: open: %w", err)
	}

	var findings []finding.Finding

	if len(zr.File) > zipMaxEntries {
		findings = append(findings, finding.New("PKL-ZIP-001", -1,
			fmt.Sprintf("zip has %d entries, exceeds cap of %d (zip-bomb signal)", len(zr.File), zipMaxEntries)))
		return findings, nil
	}

	foundPKL := false
	var totalUncompressed uint64
	earlyExit := false

	for _, f := range zr.File {
		// Only decompress data.pkl entries; weight files are never inflated.
		base := path.Base(f.Name)
		if base != "data.pkl" {
			continue
		}

		// Zip-bomb: high compression ratio check.
		if f.CompressedSize64 > 0 {
			ratio := f.UncompressedSize64 / f.CompressedSize64
			if ratio > zipBombRatioThreshold {
				findings = append(findings, finding.New("PKL-ZIP-001", -1,
					fmt.Sprintf("entry %q has compression ratio %d× (zip-bomb signal)", f.Name, ratio)))
				earlyExit = true
				break
			}
		}

		if f.UncompressedSize64 > zipMaxUncompressedEntry {
			findings = append(findings, finding.New("PKL-ZIP-001", -1,
				fmt.Sprintf("entry %q uncompressed size %d exceeds per-entry cap", f.Name, f.UncompressedSize64)))
			continue
		}

		totalUncompressed += f.UncompressedSize64
		if totalUncompressed > zipMaxTotalUncompressed {
			findings = append(findings, finding.New("PKL-ZIP-001", -1,
				"total uncompressed size of data.pkl entries exceeds cap"))
			earlyExit = true
			break
		}

		foundPKL = true

		// Open and scan through an io.LimitedReader (authoritative guard).
		rc, err := f.Open()
		if err != nil {
			findings = append(findings, finding.New("PKL-TRUNC-001", -1,
				fmt.Sprintf("entry %q: open: %v", f.Name, err)))
			continue
		}
		lr := &io.LimitedReader{R: rc, N: zipMaxUncompressedEntry}
		br := bufio.NewReader(lr)
		pFindings, _ := walkOpcodes(br, int64(f.UncompressedSize64))
		_ = rc.Close()
		findings = append(findings, pFindings...)
	}

	// A PK-magic file with no data.pkl is suspicious (DESIGN §13).
	if !foundPKL && !earlyExit {
		findings = append(findings, finding.New("PKL-ZIP-002", -1,
			"zip container contains no data.pkl entry — not a recognised PyTorch model archive"))
	}

	return findings, nil
}
