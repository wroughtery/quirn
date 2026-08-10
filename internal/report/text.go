package report

import (
	"fmt"
	"io"

	"quirn/internal/probe"
)

// severityRank orders severities from lowest to highest for gating and
// sorting purposes. Unknown severities rank below "low".
var severityRank = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// WriteText renders a terminal-friendly summary table of results to w.
func WriteText(w io.Writer, results []probe.Result) {
	fmt.Fprintf(w, "%-24s %-8s %-28s %-10s %s\n", "PROBE", "OWASP", "NAME", "SEVERITY", "STATUS")
	fmt.Fprintln(w, "----------------------------------------------------------------------------------------")

	vulnCount := 0
	for _, r := range results {
		status := "ok"
		if r.Vulnerable {
			status = "VULNERABLE"
			vulnCount++
		}
		fmt.Fprintf(w, "%-24s %-8s %-28s %-10s %s\n", r.ProbeID, r.OWASP, r.Name, r.Severity, status)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%d probe(s) run, %d finding(s)\n", len(results), vulnCount)
}

// GateFailed reports whether any result at or above the failOn severity
// threshold was found to be vulnerable. An empty or unrecognized failOn
// value falls back to "high". Results with an unrecognized severity never
// trigger the gate.
func GateFailed(results []probe.Result, failOn string) bool {
	threshold, ok := severityRank[failOn]
	if !ok {
		threshold = severityRank["high"]
	}

	for _, r := range results {
		if !r.Vulnerable {
			continue
		}
		rank, ok := severityRank[r.Severity]
		if !ok {
			continue
		}
		if rank >= threshold {
			return true
		}
	}
	return false
}
