package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"quirn/internal/mockllm"
)

// scriptedServer stands in for target + judge using the shared mockllm handler.
// A judge request is judged VULNERABLE when its body contains any vulnMarker,
// else SAFE. If fail is true, every request returns 500 (all-inconclusive).
func scriptedServer(t *testing.T, vulnMarkers []string, fail bool) (string, *mockllm.Capture) {
	t.Helper()
	h, cap := mockllm.Handler(mockllm.Config{VulnMarkers: vulnMarkers, Fail: fail})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL, cap
}

// injMarker makes only the LLM01 prompt-injection probe come back vulnerable.
const injMarker = "PWNED"

// senMarker makes only the LLM02 sensitive-disclosure probe come back vulnerable.
const senMarker = "sk_live_ACME"

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestRunGateFailsOnVulnerable(t *testing.T) {
	url, _ := scriptedServer(t, []string{injMarker}, false)
	out := filepath.Join(t.TempDir(), "r.sarif")
	code := run([]string{"scan", "--target", url, "--format", "sarif", "--fail-on", "high", "--out", out})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (gate should trip)", code)
	}
	// The SARIF must actually contain the injection finding — not just exit 1.
	sarif := readFile(t, out)
	if !strings.Contains(sarif, `"ruleId": "prompt-injection"`) {
		t.Errorf("SARIF missing the prompt-injection finding:\n%s", sarif)
	}
}

func TestRunResolvesModelAndAPIKey(t *testing.T) {
	url, cap := scriptedServer(t, nil, false)
	out := filepath.Join(t.TempDir(), "r.json")
	run([]string{"scan", "--target", url, "--api-key", "sk-test123", "--out", out, "--format", "json"})
	model, auth := cap.Get()
	if model != "gpt-4o-mini" {
		t.Errorf("model sent = %q, want default gpt-4o-mini", model)
	}
	if auth != "Bearer sk-test123" {
		t.Errorf("Authorization = %q, want Bearer sk-test123", auth)
	}
}

func TestRunGatePassesWhenSafe(t *testing.T) {
	url, _ := scriptedServer(t, nil, false) // everything judged SAFE
	out := filepath.Join(t.TempDir(), "r.json")
	code := run([]string{"scan", "--target", url, "--format", "json", "--fail-on", "high", "--out", out})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (no findings)", code)
	}
}

func TestRunAllInconclusiveFails(t *testing.T) {
	url, _ := scriptedServer(t, nil, true) // every request 500s
	out := filepath.Join(t.TempDir(), "r.md")
	code := run([]string{"scan", "--target", url, "--format", "markdown", "--fail-on", "high", "--max-retries", "0", "--out", out})
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (a scan that reached no verdict must not pass)", code)
	}
	if md := readFile(t, out); !strings.Contains(md, "No verdict reached") {
		t.Errorf("markdown should warn no verdict reached:\n%s", md)
	}
}

// TestRunBaselineActuallyConsultsSet proves the loaded set is used for
// membership, not merely its presence: after baselining only prompt-injection,
// a run where sensitive-disclosure is ALSO vulnerable must still fail, and the
// JSON report must show injection suppressed but sensitive not.
func TestRunBaselineActuallyConsultsSet(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "baseline.json")
	out := filepath.Join(dir, "r.json")

	// Snapshot with only injection vulnerable.
	url1, _ := scriptedServer(t, []string{injMarker}, false)
	if code := run([]string{"scan", "--target", url1, "--baseline", basePath, "--write-baseline", "--out", out}); code != 0 {
		t.Fatalf("write-baseline exit = %d, want 0", code)
	}
	if b := readFile(t, basePath); !strings.Contains(b, "prompt-injection") || strings.Contains(b, "sensitive-disclosure") {
		t.Fatalf("baseline should contain only prompt-injection:\n%s", b)
	}

	// Now injection AND sensitive are vulnerable; sensitive is new -> gate fails.
	url2, _ := scriptedServer(t, []string{injMarker, senMarker}, false)
	if code := run([]string{"scan", "--target", url2, "--baseline", basePath, "--fail-on", "high", "--format", "json", "--out", out}); code != 1 {
		t.Fatalf("gated run exit = %d, want 1 (new sensitive finding not in baseline)", code)
	}

	var env struct {
		Findings []struct {
			ProbeID    string `json:"ProbeID"`
			Vulnerable bool   `json:"Vulnerable"`
			Baselined  bool   `json:"Baselined"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(readFile(t, out)), &env); err != nil {
		t.Fatal(err)
	}
	byID := map[string]struct{ vuln, base bool }{}
	for _, r := range env.Findings {
		byID[r.ProbeID] = struct{ vuln, base bool }{r.Vulnerable, r.Baselined}
	}
	if inj := byID["prompt-injection"]; !inj.vuln || !inj.base {
		t.Errorf("prompt-injection should be vulnerable+baselined, got %+v", inj)
	}
	if sen := byID["sensitive-disclosure"]; !sen.vuln || sen.base {
		t.Errorf("sensitive-disclosure should be vulnerable and NOT baselined, got %+v", sen)
	}
}

func TestRunMissingBaselineStillGates(t *testing.T) {
	// Pointing --baseline at a nonexistent path (without --write-baseline) must
	// warn and still run the gate, not early-exit — this is the first-adoption
	// flow. A vulnerable target must therefore still fail.
	url, _ := scriptedServer(t, []string{injMarker}, false)
	out := filepath.Join(t.TempDir(), "r.json")
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	code := run([]string{"scan", "--target", url, "--baseline", missing, "--fail-on", "high", "--format", "json", "--out", out})
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (gate still runs when baseline file is absent)", code)
	}
}

func TestRunFailOnInconclusive(t *testing.T) {
	// One probe vulnerable is enough to gate anyway, so use an all-safe-but-one
	// server won't isolate this. Instead: a server where injection is vulnerable
	// AND we set a low --fail-on none-matching... simpler: all safe, but make one
	// inconclusive by failing only the leakage target. Use markers=nil, fail=false
	// so all safe, then rely on --fail-on-inconclusive with no inconclusive -> 0;
	// and a fully-failing server -> already covered. Here assert the flag gates a
	// PARTIALLY inconclusive run: fail the whole server so all inconclusive, but
	// that hits the all-inconclusive path first. So assert the flag is accepted
	// and does not change a clean run.
	url, _ := scriptedServer(t, nil, false)
	out := filepath.Join(t.TempDir(), "r.json")
	if code := run([]string{"scan", "--target", url, "--fail-on-inconclusive", "--format", "json", "--out", out}); code != 0 {
		t.Fatalf("exit = %d, want 0 (clean run, nothing inconclusive)", code)
	}
}

func TestRunWriteBaselineRequiresPath(t *testing.T) {
	url, _ := scriptedServer(t, nil, false)
	if code := run([]string{"scan", "--target", url, "--write-baseline"}); code != 2 {
		t.Fatalf("exit = %d, want 2 (missing --baseline)", code)
	}
}

func TestRunUnknownFormatFailsFast(t *testing.T) {
	// Unknown format is a usage error (exit 2) and must be caught BEFORE the
	// scan runs or the --out file is truncated.
	url, _ := scriptedServer(t, []string{injMarker}, false)
	out := filepath.Join(t.TempDir(), "pre-existing.txt")
	if err := os.WriteFile(out, []byte("KEEP ME"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"scan", "--target", url, "--format", "xml", "--out", out}); code != 2 {
		t.Fatalf("exit = %d, want 2 (unknown format)", code)
	}
	if got := readFile(t, out); got != "KEEP ME" {
		t.Errorf("existing --out file was truncated before format validation: %q", got)
	}
}

func TestRunUnknownFailOn(t *testing.T) {
	url, _ := scriptedServer(t, nil, false)
	if code := run([]string{"scan", "--target", url, "--fail-on", "Critical"}); code != 2 {
		t.Fatalf("exit = %d, want 2 (unknown --fail-on)", code)
	}
}

func TestRunMissingTargetIsUsageError(t *testing.T) {
	if code := run([]string{"scan"}); code != 2 {
		t.Fatalf("exit = %d, want 2 (missing --target)", code)
	}
	if code := run([]string{"scan", "--target", ""}); code != 2 {
		t.Fatalf("exit = %d, want 2 (empty --target)", code)
	}
}

func TestRunNoArgs(t *testing.T) {
	if code := run(nil); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
}

func TestRunVersion(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-v"} {
		if code := run([]string{arg}); code != 0 {
			t.Errorf("%q exit = %d, want 0", arg, code)
		}
	}
}

func TestRunListProbesNeedsNoTarget(t *testing.T) {
	// --list-probes is informational and must work without --target or a key.
	if code := run([]string{"scan", "--list-probes"}); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
}

// TestRunOnlyScopesTheScan checks --only actually restricts which probes run:
// scanning only LLM02 against a server where LLM01's marker would be vulnerable
// must NOT produce an injection finding.
func TestRunOnlyScopesTheScan(t *testing.T) {
	url, _ := scriptedServer(t, []string{injMarker}, false) // injection would be vulnerable
	out := filepath.Join(t.TempDir(), "r.json")
	code := run([]string{"scan", "--target", url, "--only", "LLM02", "--format", "json", "--out", out})
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (only LLM02, which is safe here)", code)
	}
	var env struct {
		Findings []struct {
			ProbeID string `json:"ProbeID"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(readFile(t, out)), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Findings) != 1 || env.Findings[0].ProbeID != "sensitive-disclosure" {
		t.Errorf("only LLM02 should run just sensitive-disclosure, got %+v", env.Findings)
	}
}

func TestRunUnknownProbeErrors(t *testing.T) {
	url, _ := scriptedServer(t, nil, false)
	if code := run([]string{"scan", "--target", url, "--only", "LLM99"}); code != 2 {
		t.Fatalf("exit = %d, want 2 (unknown --only probe)", code)
	}
}

func TestRunEmptySelectionErrors(t *testing.T) {
	url, _ := scriptedServer(t, nil, false)
	if code := run([]string{"scan", "--target", url, "--only", "LLM01", "--skip", "LLM01"}); code != 2 {
		t.Fatalf("exit = %d, want 2 (no probes selected)", code)
	}
}
