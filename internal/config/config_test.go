package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "quirn.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	p := writeTemp(t, `{
		"version": 1,
		"target": "http://t",
		"model": "m",
		"judge_model": "j",
		"judge_target": "http://j2",
		"fail_on": "critical",
		"fail_on_inconclusive": true,
		"format": "json",
		"concurrency": 8,
		"timeout": "30s",
		"max_retries": 5,
		"only": ["LLM01", "LLM02"],
		"skip": ["LLM09"],
		"baseline": ".quirn-baseline.json",
		"severities": {"prompt-injection": "critical"}
	}`)
	f, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.Target != "http://t" || f.Model != "m" || f.JudgeModel != "j" || f.JudgeTarget != "http://j2" {
		t.Errorf("string fields wrong: %+v", f)
	}
	if f.FailOnInconclusive == nil || !*f.FailOnInconclusive {
		t.Error("fail_on_inconclusive should be true")
	}
	if f.Concurrency == nil || *f.Concurrency != 8 {
		t.Error("concurrency should be 8")
	}
	if f.MaxRetries == nil || *f.MaxRetries != 5 {
		t.Error("max_retries should be 5")
	}
	if d, ok := f.TimeoutDuration(); !ok || d.String() != "30s" {
		t.Errorf("timeout = %v,%v want 30s,true", d, ok)
	}
	if len(f.Only) != 2 || f.Severities["prompt-injection"] != "critical" {
		t.Errorf("only/severities wrong: %+v", f)
	}
}

func TestLoadMinimal(t *testing.T) {
	// Only version is mandatory; everything else is optional and stays zero.
	f, err := Load(writeTemp(t, `{"version": 1}`))
	if err != nil {
		t.Fatalf("Load minimal: %v", err)
	}
	if f.FailOnInconclusive != nil || f.Concurrency != nil || f.MaxRetries != nil {
		t.Error("absent pointer fields must stay nil, not zero")
	}
	if _, ok := f.TimeoutDuration(); ok {
		t.Error("absent timeout should report ok=false")
	}
}

func TestLoadCustomProbes(t *testing.T) {
	f, err := Load(writeTemp(t, `{
		"version": 1,
		"custom_probes": [
			{
				"id": "my-probe",
				"name": "My Probe",
				"owasp": "LLM01",
				"severity": "high",
				"attacks": [
					{"name": "a1", "goal": "g", "system": "s", "payload": "p"}
				]
			}
		]
	}`))
	if err != nil {
		t.Fatalf("Load custom: %v", err)
	}
	if len(f.CustomProbes) != 1 {
		t.Fatalf("want 1 custom probe, got %d", len(f.CustomProbes))
	}
	cp := f.CustomProbes[0]
	if cp.ID != "my-probe" || cp.Severity != "high" || len(cp.Attacks) != 1 || cp.Attacks[0].Payload != "p" {
		t.Errorf("custom probe parsed wrong: %+v", cp)
	}
}

func TestLoadCustomProbesReject(t *testing.T) {
	cases := map[string]string{
		"missing id":        `{"version":1,"custom_probes":[{"severity":"low","attacks":[{"goal":"g","payload":"p"}]}]}`,
		"duplicate id":      `{"version":1,"custom_probes":[{"id":"x","severity":"low","attacks":[{"goal":"g","payload":"p"}]},{"id":"x","severity":"low","attacks":[{"goal":"g","payload":"p"}]}]}`,
		"bad severity":      `{"version":1,"custom_probes":[{"id":"x","severity":"nuke","attacks":[{"goal":"g","payload":"p"}]}]}`,
		"no attacks":        `{"version":1,"custom_probes":[{"id":"x","severity":"low","attacks":[]}]}`,
		"attack no goal":    `{"version":1,"custom_probes":[{"id":"x","severity":"low","attacks":[{"payload":"p"}]}]}`,
		"attack no payload": `{"version":1,"custom_probes":[{"id":"x","severity":"low","attacks":[{"goal":"g"}]}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, body)); err == nil {
				t.Errorf("Load(%s) = nil error, want rejection", body)
			}
		})
	}
}

func TestLoadNotExist(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if !errors.Is(err, ErrNotExist) {
		t.Errorf("missing file err = %v, want ErrNotExist", err)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":       `{"version":1,"targett":"x"}`,
		"wrong version":       `{"version":2}`,
		"zero version":        `{"target":"x"}`,
		"bad fail_on":         `{"version":1,"fail_on":"spicy"}`,
		"bad format":          `{"version":1,"format":"yaml"}`,
		"bad timeout":         `{"version":1,"timeout":"soon"}`,
		"concurrency below 1": `{"version":1,"concurrency":0}`,
		"negative retries":    `{"version":1,"max_retries":-1}`,
		"bad severity value":  `{"version":1,"severities":{"prompt-injection":"nuclear"}}`,
		"trailing data":       `{"version":1}{"version":1}`,
		"malformed json":      `{"version":1,`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, body)); err == nil {
				t.Errorf("Load(%s) = nil error, want rejection", body)
			}
		})
	}
}
