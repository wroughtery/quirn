package report

import (
	"fmt"

	"github.com/wroughtery/quirn/internal/probe"
)

// Posture is the overall security score for one target across all probes it was
// run against. It rolls the per-probe verdicts into a single 0-100 number and an
// A-F letter so two scans are comparable at a glance, while the underlying table
// still carries the detail.
//
// The score is deliberately FAIL-CLOSED: an inconclusive probe (the judge/target
// could not be scored) is treated as unknown risk, never as a pass — it deducts
// points and, on its own, caps the grade below A. A clean, fully-scored run is
// the only way to earn an A. Baselined findings are accepted risk (like the
// gate) and do not deduct.
type Posture struct {
	Score  int    // 0-100, higher is safer
	Letter string // A-F
	// Reason is a short human-readable basis for the grade (the dominant factor),
	// e.g. "1 confirmed break" or "2 high findings" or "all clear".
	Reason string
}

// severity deduction weights, subtracted from a starting 100 per new
// (non-baselined) vulnerable finding. A deterministic CONFIRMED break is treated
// as worse than any judged finding of the same severity — it is proof, not
// inference — so it carries its own heavier weight. An inconclusive probe
// deducts a smaller fixed amount (unknown, not proven-broken).
const (
	weightConfirmed    = 60
	weightCritical     = 45
	weightHigh         = 25
	weightMedium       = 12
	weightLow          = 5
	weightUnknownSev   = 12 // vulnerable finding with an unrecognized severity
	weightInconclusive = 8
)

// grade ceilings: hard caps that a single serious outcome imposes regardless of
// the arithmetic, so the letter can never overstate safety. A confirmed or
// critical break forces F; a high finding caps at D; any inconclusive caps at B
// (an A asserts "fully scored and clean", which an unknown contradicts).
const (
	ceilConfirmedOrCritical = 39 // F
	ceilHigh                = 69 // D
	ceilInconclusive        = 89 // B
)

// Score computes the overall Posture for a set of probe results. It is
// deterministic and side-effect free.
func Score(results []probe.Result) Posture {
	score := 100
	ceiling := 100

	confirmed := 0
	criticalVuln := 0
	highVuln := 0
	otherVuln := 0
	inconclusive := 0

	for _, r := range results {
		switch {
		case r.Vulnerable && r.Baselined:
			// Accepted risk: no deduction, mirrors the severity gate.
			continue
		case r.Vulnerable:
			if r.Grade == "CONFIRMED" {
				score -= weightConfirmed
				confirmed++
				continue
			}
			switch r.Severity {
			case "critical":
				score -= weightCritical
				criticalVuln++
			case "high":
				score -= weightHigh
				highVuln++
			case "medium":
				score -= weightMedium
				otherVuln++
			case "low":
				score -= weightLow
				otherVuln++
			default:
				score -= weightUnknownSev
				otherVuln++
			}
		case r.Inconclusive:
			score -= weightInconclusive
			inconclusive++
		}
	}

	if confirmed > 0 || criticalVuln > 0 {
		ceiling = ceilConfirmedOrCritical
	} else if highVuln > 0 {
		ceiling = ceilHigh
	} else if inconclusive > 0 {
		ceiling = ceilInconclusive
	}

	if score > ceiling {
		score = ceiling
	}
	if score < 0 {
		score = 0
	}

	return Posture{
		Score:  score,
		Letter: letterFor(score),
		Reason: postureReason(confirmed, criticalVuln, highVuln, otherVuln, inconclusive),
	}
}

// letterFor maps a 0-100 score to an A-F letter on the conventional band.
func letterFor(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// postureReason names the single dominant factor behind the grade, worst first,
// so the headline explains itself without the reader scanning the table.
func postureReason(confirmed, critical, high, other, inconclusive int) string {
	switch {
	case confirmed > 0:
		return fmt.Sprintf("%d confirmed break(s)", confirmed)
	case critical > 0:
		return fmt.Sprintf("%d critical finding(s)", critical)
	case high > 0:
		return fmt.Sprintf("%d high finding(s)", high)
	case other > 0:
		return fmt.Sprintf("%d finding(s)", other)
	case inconclusive > 0:
		return fmt.Sprintf("%d inconclusive (unknown risk)", inconclusive)
	default:
		return "all clear"
	}
}
