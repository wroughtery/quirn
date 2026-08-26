package report

import (
	"encoding/json"
	"io"

	"quirn/internal/probe"
)

// Envelope is the top-level structure of the JSON report. It wraps the raw
// findings with tool metadata and pre-computed summary counts so downstream
// consumers (CI dashboards, the future v1 UI) get a stable, self-describing
// document without recomputing aggregates. It is deterministic: it carries no
// timestamp, so two identical scans produce byte-identical output.
type Envelope struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Target   string         `json:"target"`
	Summary  Summary        `json:"summary"`
	Findings []probe.Result `json:"findings"`
}

// Summary holds aggregate counts over the findings. The categories are
// mutually exclusive and sum to Probes.
type Summary struct {
	Probes       int `json:"probes"`
	Vulnerable   int `json:"vulnerable"` // new (non-baselined) vulnerable findings
	Baselined    int `json:"baselined"`  // vulnerable but suppressed by a baseline
	Inconclusive int `json:"inconclusive"`
	OK           int `json:"ok"`
	// Overall posture score across all probes: 0-100 (higher is safer) and its
	// A-F letter. Fail-closed — see Score.
	Score       int    `json:"score"`
	Grade       string `json:"grade"`
	GradeReason string `json:"grade_reason"`
}

// WriteJSON renders results as a structured JSON envelope to w.
func WriteJSON(w io.Writer, results []probe.Result, target, version string) error {
	env := Envelope{
		Tool:     "quirn",
		Version:  version,
		Target:   target,
		Summary:  summarize(results),
		Findings: results,
	}
	// Marshal an empty slice as [] rather than null so the schema is stable.
	if env.Findings == nil {
		env.Findings = []probe.Result{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}

// summarize counts results into the mutually-exclusive summary categories.
func summarize(results []probe.Result) Summary {
	var s Summary
	s.Probes = len(results)
	for _, r := range results {
		switch {
		case r.Vulnerable && r.Baselined:
			s.Baselined++
		case r.Vulnerable:
			s.Vulnerable++
		case r.Inconclusive:
			s.Inconclusive++
		default:
			s.OK++
		}
	}
	p := Score(results)
	s.Score = p.Score
	s.Grade = p.Letter
	s.GradeReason = p.Reason
	return s
}
