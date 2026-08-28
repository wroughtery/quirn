package report

import (
	"testing"

	"github.com/wroughtery/quirn/internal/probe"
)

func res(sev string, vuln, inconc, baselined bool, grade string) probe.Result {
	return probe.Result{ProbeID: "p", OWASP: "LLM01", Name: "p", Severity: sev, Vulnerable: vuln, Inconclusive: inconc, Baselined: baselined, Grade: grade}
}

func TestScorePosture(t *testing.T) {
	tests := []struct {
		name       string
		results    []probe.Result
		wantLetter string
		wantScore  int
	}{
		{"all clear", []probe.Result{res("high", false, false, false, ""), res("low", false, false, false, "")}, "A", 100},
		{"one low finding", []probe.Result{res("low", true, false, false, "")}, "A", 95},
		{"one medium finding", []probe.Result{res("medium", true, false, false, "")}, "B", 88},
		{"one high finding caps at D", []probe.Result{res("high", true, false, false, "")}, "D", 69},
		{"critical forces F", []probe.Result{res("critical", true, false, false, "")}, "F", 39},
		{"confirmed forces F", []probe.Result{res("high", true, false, false, "CONFIRMED")}, "F", 39},
		{"inconclusive caps below A", []probe.Result{res("high", false, true, false, "")}, "B", 89},
		{"clean but one inconclusive is not an A", []probe.Result{res("low", false, false, false, ""), res("high", false, true, false, "")}, "B", 89},
		{"baselined vuln does not deduct", []probe.Result{res("critical", true, false, true, "")}, "A", 100},
		{"floor at zero", []probe.Result{res("critical", true, false, false, ""), res("critical", true, false, false, ""), res("critical", true, false, false, "")}, "F", 0},
		{"empty is clean A", nil, "A", 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Score(tt.results)
			if p.Letter != tt.wantLetter {
				t.Errorf("Letter = %q, want %q (score %d)", p.Letter, tt.wantLetter, p.Score)
			}
			if p.Score != tt.wantScore {
				t.Errorf("Score = %d, want %d", p.Score, tt.wantScore)
			}
			if p.Reason == "" {
				t.Error("Reason should never be empty")
			}
		})
	}
}

// A confirmed break must outrank a mere high finding in the headline reason even
// when both are present.
func TestScoreReasonPrefersWorst(t *testing.T) {
	p := Score([]probe.Result{res("high", true, false, false, ""), res("critical", true, false, false, "CONFIRMED")})
	if p.Letter != "F" {
		t.Fatalf("want F, got %s", p.Letter)
	}
	if want := "1 confirmed break(s)"; p.Reason != want {
		t.Errorf("Reason = %q, want %q", p.Reason, want)
	}
}
