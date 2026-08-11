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
	fmt.Fprintf(w, "%-24s %-8s %-34s %-10s %s\n", "PROBE", "OWASP", "NAME", "SEVERITY", "STATUS")
	fmt.Fprintln(w, "--------------------------------------------------------------------------------------------")

	vulnCount := 0
	baselinedCount := 0
	inconclusiveCount := 0
	for _, r := range results {
		status := "ok"
		switch {
		case r.Vulnerable && r.Baselined:
			status = "BASELINED"
			baselinedCount++
		case r.Vulnerable:
			status = "VULNERABLE"
			vulnCount++
		case r.Inconclusive:
			status = "INCONCLUSIVE"
			inconclusiveCount++
		}
		fmt.Fprintf(w, "%-24s %-8s %-34s %-10s %s\n", r.ProbeID, r.OWASP, r.Name, r.Severity, status)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%d probe(s) run, %d new finding(s), %d baselined, %d inconclusive\n",
		len(results), vulnCount, baselinedCount, inconclusiveCount)
}

// ValidSeverity reports whether s is a severity quirn understands. Callers use
// it to reject a mistyped --fail-on before spending a scan.
func ValidSeverity(s string) bool {
	_, ok := severityRank[s]
	return ok
}

// AllInconclusive reports whether every result failed to reach a verdict (the
// target was unreachable, unauthorized, or too slow to score). An empty slice
// returns false: there was nothing to test, which is a different condition.
// A run that is entirely inconclusive tested nothing and must not be reported
// as a clean pass.
func AllInconclusive(results []probe.Result) bool {
	if len(results) == 0 {
		return false
	}
	for _, r := range results {
		if !r.Inconclusive {
			return false
		}
	}
	return true
}

// AnyInconclusive reports whether at least one result failed to reach a verdict.
func AnyInconclusive(results []probe.Result) bool {
	for _, r := range results {
		if r.Inconclusive {
			return true
		}
	}
	return false
}

// GateFailed reports whether any result at or above the failOn severity
// threshold was found to be vulnerable. An empty or unrecognized failOn
// value falls back to "high". Baselined findings are excluded (a baseline
// accepts them), and results with an unrecognized severity never trigger the
// gate.
func GateFailed(results []probe.Result, failOn string) bool {
	threshold, ok := severityRank[failOn]
	if !ok {
		threshold = severityRank["high"]
	}

	for _, r := range results {
		if !r.Vulnerable || r.Baselined {
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
