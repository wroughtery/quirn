package probe

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wroughtery/quirn/internal/llm"
)

// knownSeverities mirrors the gate's severityRank keys (report package). Kept
// local to avoid an import cycle (report imports probe). A probe whose severity
// is not in this set would be silently un-gateable.
var knownSeverities = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}

// scriptedModel serves both target and judge from one endpoint and lets a test
// script per-attack behaviour. It tells target from judge calls by the rubric
// text present only in judge requests. A target call whose body contains any
// failTargets substring returns HTTP 500 (driving the probe's inconclusive
// path); a judge call returns "VERDICT: <verdicts[k]>" for the first key k
// found in the request body, defaulting to SAFE.
type scriptedModel struct {
	failTargets []string
	verdicts    map[string]string // payload-substring -> "VULNERABLE" | "SAFE"
}

func (m scriptedModel) client(t *testing.T) *llm.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s := string(body)
		isJudge := strings.Contains(s, "security judge")

		if !isJudge {
			for _, f := range m.failTargets {
				if strings.Contains(s, f) {
					w.WriteHeader(http.StatusInternalServerError)
					io.WriteString(w, "target down")
					return
				}
			}
			writeContent(w, "target reply")
			return
		}

		verdict := "SAFE"
		for k, v := range m.verdicts {
			if strings.Contains(s, k) {
				verdict = v
				break
			}
		}
		writeContent(w, "VERDICT: "+verdict+"\nscripted")
	}))
	t.Cleanup(srv.Close)
	c := llm.NewClient(srv.URL, "")
	c.BackoffBase = time.Millisecond // keep the retry backoff negligible in tests
	return c
}

func writeContent(w http.ResponseWriter, content string) {
	b, _ := json.Marshal(content)
	io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":`+string(b)+`}}]}`)
}

func runInjection(t *testing.T, m scriptedModel) Result {
	t.Helper()
	cfg := Config{Target: "x", Model: "m", JudgeModel: "j"}
	return NewInjectionProbe().Run(context.Background(), m.client(t), cfg)
}

func TestProbeVulnerableWhenJudgeSaysSo(t *testing.T) {
	r := runInjection(t, scriptedModel{verdicts: map[string]string{"PWNED": "VULNERABLE"}})
	if !r.Vulnerable || r.Inconclusive {
		t.Fatalf("want vulnerable and not inconclusive, got %+v", r)
	}
	if r.OWASP != "LLM01" || r.Severity != "high" {
		t.Errorf("unexpected metadata: %+v", r)
	}
}

func TestProbeSafe(t *testing.T) {
	r := runInjection(t, scriptedModel{}) // all judge calls default SAFE
	if r.Vulnerable || r.Inconclusive {
		t.Fatalf("want safe (not vulnerable, not inconclusive), got %+v", r)
	}
}

// TestAllAttacksAreSent pins that every payload in the set actually runs: only
// the spoofed-policy-update attack (keyed on "DEVELOPER PATCH NOTE") is scripted
// vulnerable, so the probe can only come back Vulnerable if that third attack
// was sent. Truncating the attack loop would make this fail.
func TestAllAttacksAreSent(t *testing.T) {
	r := runInjection(t, scriptedModel{verdicts: map[string]string{"DEVELOPER PATCH NOTE": "VULNERABLE"}})
	if !r.Vulnerable {
		t.Fatalf("spoofed-policy-update is the vulnerable attack; probe must have run it: %+v\nevidence:\n%s", r, r.Evidence)
	}
}

// TestVulnerableWinsOverInconclusive exercises a genuinely mixed fold: the
// payload-splitting target call fails (inconclusive) while spoofed-policy-update
// is judged vulnerable. The invariant is Vulnerable && !Inconclusive.
func TestVulnerableWinsOverInconclusive(t *testing.T) {
	r := runInjection(t, scriptedModel{
		failTargets: []string{"formatting drill"},                            // payload-splitting -> inconclusive
		verdicts:    map[string]string{"DEVELOPER PATCH NOTE": "VULNERABLE"}, // spoofed-policy-update -> vulnerable
	})
	if !r.Vulnerable {
		t.Fatalf("a confirmed vuln must win over inconclusive attempts: %+v", r)
	}
	if r.Inconclusive {
		t.Errorf("Vulnerable and Inconclusive must be mutually exclusive: %+v", r)
	}
	if !strings.Contains(r.Evidence, "target request failed") || !strings.Contains(r.Evidence, "VULNERABLE") {
		t.Errorf("evidence should record both the failed attempt and the finding:\n%s", r.Evidence)
	}
}

// TestInconclusiveWhenSomeFailAndRestSafe: no vuln, at least one attempt could
// not be scored -> Inconclusive.
func TestInconclusiveWhenSomeFailAndRestSafe(t *testing.T) {
	r := runInjection(t, scriptedModel{
		failTargets: []string{"formatting drill"}, // one inconclusive
		// others default SAFE
	})
	if r.Vulnerable {
		t.Fatalf("no attempt was vulnerable: %+v", r)
	}
	if !r.Inconclusive {
		t.Errorf("a failed attempt with the rest safe should be inconclusive: %+v", r)
	}
}

func TestAllProbesWellFormed(t *testing.T) {
	probes := All()
	if len(probes) != 6 {
		t.Fatalf("want 6 probes, got %d", len(probes))
	}
	seenID := map[string]bool{}
	seenOWASP := map[string]bool{}
	for _, p := range probes {
		if p.ID() == "" || p.Name() == "" || p.OWASP() == "" {
			t.Errorf("probe has empty field: %+v", p)
		}
		if seenID[p.ID()] {
			t.Errorf("duplicate probe ID %q", p.ID())
		}
		seenID[p.ID()] = true
		if seenOWASP[p.OWASP()] {
			t.Errorf("duplicate OWASP id %q", p.OWASP())
		}
		seenOWASP[p.OWASP()] = true

		// Severity must be a value the gate recognizes; an unknown severity is
		// silently skipped by GateFailed, so a typo here would make the probe
		// un-gateable.
		if !knownSeverities[p.Severity()] {
			t.Errorf("probe %q has unknown severity %q", p.ID(), p.Severity())
		}
		// The seeded Result must carry that same severity.
		if res := p.Run(context.Background(), nil, Config{}); res.Severity != p.Severity() {
			t.Errorf("probe %q Run severity %q != Severity() %q", p.ID(), res.Severity, p.Severity())
		}
	}
	for _, want := range []string{"LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM09"} {
		if !seenOWASP[want] {
			t.Errorf("missing OWASP class %q", want)
		}
	}
}

func TestStableID(t *testing.T) {
	r := Result{ProbeID: "prompt-injection"}
	if r.StableID() != "prompt-injection" {
		t.Errorf("StableID = %q", r.StableID())
	}
}
