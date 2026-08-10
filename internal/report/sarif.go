// Package report renders probe results as SARIF and as a terminal-friendly
// text summary, and implements the severity gate used for CI exit codes.
package report

import (
	"encoding/json"
	"io"

	"quirn/internal/probe"
)

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
const sarifVersion = "2.1.0"

// sarifLog mirrors the minimal subset of the SARIF 2.1.0 object model quirn
// needs: one run, one tool driver, and a flat list of results.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription sarifMultiformat `json:"shortDescription"`
}

type sarifMultiformat struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMultiformat `json:"message"`
	Locations []sarifLocation  `json:"locations"`
}

// sarifLocation is a placeholder physical location. Findings from an LLM
// red-team probe are not tied to a source file, but SARIF viewers (and the
// GitHub Security tab) expect at least one location per result, so we point
// at a synthetic "target" location.
type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// severityToLevel maps quirn's severity strings to SARIF result levels.
// SARIF only has "none", "note", "warning", "error" — low maps to "note",
// medium/high/critical escalate through "warning"/"error".
func severityToLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "none"
	}
}

// WriteSARIF renders results as a minimal valid SARIF 2.1.0 log to w.
func WriteSARIF(w io.Writer, results []probe.Result, target string) error {
	rules := make([]sarifRule, 0, len(results))
	seen := make(map[string]bool)
	sarifResults := make([]sarifResult, 0, len(results))

	for _, r := range results {
		if !seen[r.ProbeID] {
			seen[r.ProbeID] = true
			rules = append(rules, sarifRule{
				ID:               r.OWASP,
				Name:             r.Name,
				ShortDescription: sarifMultiformat{Text: r.Name + " (" + r.OWASP + ")"},
			})
		}

		if !r.Vulnerable {
			continue
		}

		sarifResults = append(sarifResults, sarifResult{
			RuleID:  r.OWASP,
			Level:   severityToLevel(r.Severity),
			Message: sarifMultiformat{Text: r.Evidence},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: target},
					},
				},
			},
		})
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "quirn",
						InformationURI: "https://github.com/wroughtery/quirn",
						Version:        "0.0.1",
						Rules:          rules,
					},
				},
				Results: sarifResults,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
