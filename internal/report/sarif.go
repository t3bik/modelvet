package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/t3bik/modelvet/internal/finding"
	"github.com/t3bik/modelvet/internal/scan"
)

// SARIF 2.1.0 — minimal subset required by GitHub code scanning.
// We hand-roll the ~5 structs rather than pulling in a third-party SARIF library
// (keeping zero runtime deps, per the design).

const sarifVersion = "2.1.0"
const sarifSchema = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"

type sarifWriter struct {
	w io.Writer
}

func (s *sarifWriter) Write(result scan.Result) error {
	log := sarifLog{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs:    []sarifRun{buildRun(result)},
	}
	enc := json.NewEncoder(s.w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("sarif writer: %w", err)
	}
	return nil
}

func buildRun(result scan.Result) sarifRun {
	// Collect unique rules.
	ruleSet := make(map[string]finding.Rule)
	for _, f := range result.Findings {
		if r, ok := finding.Catalog[f.RuleID]; ok {
			ruleSet[f.RuleID] = r
		}
	}
	var rules []sarifRule
	for _, r := range ruleSet {
		rules = append(rules, sarifRule{
			ID: r.ID,
			Name: sarifMessage{Text: r.Title},
			FullDescription: sarifMessage{Text: r.Title + " — " + r.Remediation},
			DefaultConfiguration: sarifConfiguration{Level: severityToSARIF(r.Severity)},
		})
	}

	var results []sarifResult
	for _, f := range result.Findings {
		res := sarifResult{
			RuleID:  f.RuleID,
			Level:   severityToSARIF(f.Severity),
			Message: sarifMessage{Text: f.Detail},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{URI: fileURI(f.Path)},
						Region:           offsetRegion(f.Offset),
					},
				},
			},
		}
		results = append(results, res)
	}

	return sarifRun{
		Tool: sarifTool{
			Driver: sarifDriver{
				Name:           "modelvet",
				InformationURI: "https://github.com/t3bik/modelvet",
				Rules:          rules,
			},
		},
		Results: results,
	}
}

// severityToSARIF maps finding.Severity to a SARIF level string.
// SARIF levels: "error", "warning", "note".
func severityToSARIF(s finding.Severity) string {
	switch {
	case s >= finding.High:
		return "error"
	case s >= finding.Medium:
		return "warning"
	default:
		return "note"
	}
}

func fileURI(path string) string {
	if path == "" {
		return "unknown"
	}
	// Ensure file:// prefix for absolute paths.
	if len(path) > 0 && path[0] == '/' {
		return "file://" + path
	}
	return path
}

func offsetRegion(offset int64) sarifRegion {
	if offset < 0 {
		return sarifRegion{}
	}
	return sarifRegion{ByteOffset: offset, ByteLength: 1}
}

// ── SARIF structs ─────────────────────────────────────────────────────────────

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string               `json:"id"`
	Name                 sarifMessage         `json:"name"`
	FullDescription      sarifMessage         `json:"fullDescription"`
	DefaultConfiguration sarifConfiguration   `json:"defaultConfiguration"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	ByteOffset int64 `json:"byteOffset,omitempty"`
	ByteLength int64 `json:"byteLength,omitempty"`
}
