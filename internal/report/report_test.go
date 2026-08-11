package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"quirn/internal/probe"
)

func vuln(id, owasp, sev string) probe.Result {
	return probe.Result{ProbeID: id, OWASP: owasp, Name: id, Severity: sev, Vulnerable: true, Evidence: "[a] VULNERABLE: x"}
}

func TestGateFailed(t *testing.T) {
	tests := []struct {
		name    string
		results []probe.Result
		failOn  string
		want    bool
	}{
		{"no findings", []probe.Result{{ProbeID: "p", Severity: "high"}}, "high", false},
		{"high finding at high gate", []probe.Result{vuln("p", "LLM01", "high")}, "high", true},
		{"medium finding at high gate", []probe.Result{vuln("p", "LLM07", "medium")}, "high", false},
		{"medium finding at medium gate", []probe.Result{vuln("p", "LLM07", "medium")}, "medium", true},
		{"critical at high gate", []probe.Result{vuln("p", "LLM01", "critical")}, "high", true},
		{"unknown failOn falls back to high", []probe.Result{vuln("p", "LLM07", "medium")}, "bogus", false},
		{"unknown severity never gates", []probe.Result{vuln("p", "LLM01", "spicy")}, "low", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GateFailed(tt.results, tt.failOn); got != tt.want {
				t.Errorf("GateFailed = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGateFailedSkipsBaselined(t *testing.T) {
	r := vuln("p", "LLM01", "critical")
	r.Baselined = true
	if GateFailed([]probe.Result{r}, "low") {
		t.Error("baselined finding must not trip the gate")
	}
}

func TestSeverityToLevel(t *testing.T) {
	cases := map[string]string{
		"critical": "error", "high": "error", "medium": "warning",
		"low": "note", "unknown": "none",
	}
	for sev, want := range cases {
		if got := severityToLevel(sev); got != want {
			t.Errorf("severityToLevel(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestWriteSARIFExcludesBaselinedAndNonVuln(t *testing.T) {
	baselined := vuln("p2", "LLM02", "high")
	baselined.Baselined = true
	results := []probe.Result{
		vuln("p1", "LLM01", "high"),
		baselined,
		{ProbeID: "p3", OWASP: "LLM07", Name: "p3", Severity: "medium"}, // not vulnerable
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, results, "http://target"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var log map[string]any
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	runs := log["runs"].([]any)
	run := runs[0].(map[string]any)
	sarifResults := run["results"].([]any)
	if len(sarifResults) != 1 {
		t.Fatalf("want 1 SARIF result (only the new vuln), got %d", len(sarifResults))
	}
	// It must be the NEW finding (p1) that survived, not the baselined one (p2).
	// Counting alone would miss an inverted filter that drops p1 and emits p2.
	if got := sarifResults[0].(map[string]any)["ruleId"].(string); got != "p1" {
		t.Errorf("surviving SARIF result ruleId = %q, want p1 (the new finding)", got)
	}
	// Rules should be listed for every distinct probe, even non-vulnerable ones,
	// each with a unique id (keyed on probe id, not the OWASP class).
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if len(rules) != 3 {
		t.Errorf("want 3 rules (one per distinct probe), got %d", len(rules))
	}
	seen := map[string]bool{}
	for _, ru := range rules {
		id := ru.(map[string]any)["id"].(string)
		if seen[id] {
			t.Errorf("duplicate SARIF rule id %q (must be unique within the driver)", id)
		}
		seen[id] = true
	}
}

func TestGateFailedIgnoresInconclusive(t *testing.T) {
	// An inconclusive probe must never trip the severity gate (the judge never
	// defaults to vulnerable). Regression guard against making flaky scans red.
	r := probe.Result{ProbeID: "p", OWASP: "LLM01", Name: "p", Severity: "critical", Inconclusive: true}
	if GateFailed([]probe.Result{r}, "low") {
		t.Error("inconclusive result must not trip the gate")
	}
}

func TestAllInconclusive(t *testing.T) {
	if AllInconclusive(nil) {
		t.Error("empty results is not all-inconclusive (nothing was tested)")
	}
	inc := probe.Result{Inconclusive: true}
	if !AllInconclusive([]probe.Result{inc, inc}) {
		t.Error("all-inconclusive slice should report true")
	}
	mixed := []probe.Result{inc, {Vulnerable: true}}
	if AllInconclusive(mixed) {
		t.Error("a vulnerable result means not all-inconclusive")
	}
	if !AnyInconclusive(mixed) {
		t.Error("AnyInconclusive should see the inconclusive one")
	}
	if AnyInconclusive([]probe.Result{{Vulnerable: true}}) {
		t.Error("AnyInconclusive false when none inconclusive")
	}
}

func TestValidSeverity(t *testing.T) {
	for _, s := range []string{"low", "medium", "high", "critical"} {
		if !ValidSeverity(s) {
			t.Errorf("ValidSeverity(%q) = false", s)
		}
	}
	for _, s := range []string{"", "Critical", "bogus", "HIGH"} {
		if ValidSeverity(s) {
			t.Errorf("ValidSeverity(%q) = true, want false", s)
		}
	}
}

func TestWriteMarkdownAllInconclusive(t *testing.T) {
	inc := probe.Result{ProbeID: "p", OWASP: "LLM01", Name: "p", Severity: "high", Inconclusive: true}
	var buf bytes.Buffer
	WriteMarkdown(&buf, []probe.Result{inc, inc}, "http://target")
	out := buf.String()
	if strings.Contains(out, "No new vulnerabilities found") {
		t.Errorf("all-inconclusive run must not show the green banner:\n%s", out)
	}
	if !strings.Contains(out, "No verdict reached") {
		t.Errorf("all-inconclusive run should warn no verdict was reached:\n%s", out)
	}
}

func TestWriteTextCounts(t *testing.T) {
	baselined := vuln("p2", "LLM02", "high")
	baselined.Baselined = true
	results := []probe.Result{
		vuln("p1", "LLM01", "high"),
		baselined,
		{ProbeID: "p3", OWASP: "LLM07", Name: "p3", Severity: "medium", Inconclusive: true},
	}
	var buf bytes.Buffer
	WriteText(&buf, results)
	out := buf.String()
	if !strings.Contains(out, "1 new finding(s), 1 baselined, 1 inconclusive") {
		t.Errorf("summary line wrong:\n%s", out)
	}
	if !strings.Contains(out, "BASELINED") || !strings.Contains(out, "VULNERABLE") || !strings.Contains(out, "INCONCLUSIVE") {
		t.Errorf("missing a status label:\n%s", out)
	}
}

func TestWriteMarkdown(t *testing.T) {
	baselined := vuln("p2", "LLM02", "high")
	baselined.Baselined = true
	results := []probe.Result{
		vuln("p1", "LLM01", "high"),
		baselined,
	}
	var buf bytes.Buffer
	WriteMarkdown(&buf, results, "http://target")
	out := buf.String()

	for _, want := range []string{
		"## 🛡️ Quirn LLM red-team scorecard",
		"`http://target`",
		"1 new vulnerability found",
		"2 probe(s) run — 1 new, 1 baselined, 0 inconclusive",
		"| Probe | OWASP | Severity | Status |",
		"❌ Vulnerable",
		"➖ Baselined",
		"### Findings",
		"<details>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q\n---\n%s", want, out)
		}
	}
}

func TestWriteMarkdownCleanRun(t *testing.T) {
	results := []probe.Result{{ProbeID: "p", OWASP: "LLM01", Name: "p", Severity: "high"}}
	var buf bytes.Buffer
	WriteMarkdown(&buf, results, "")
	out := buf.String()
	if !strings.Contains(out, "No new vulnerabilities found") {
		t.Errorf("clean run should report no vulns:\n%s", out)
	}
	if strings.Contains(out, "### Findings") {
		t.Errorf("clean run should have no findings section:\n%s", out)
	}
}

func TestMarkdownEscapesPipes(t *testing.T) {
	r := vuln("p", "LLM01", "high")
	r.Name = "a|b"
	var buf bytes.Buffer
	WriteMarkdown(&buf, []probe.Result{r}, "")
	if !strings.Contains(buf.String(), `a\|b`) {
		t.Error("pipe in probe name should be escaped in the table")
	}
}
