package probe

import (
	"context"
	"testing"
)

func TestNewCustomIdentityAndRun(t *testing.T) {
	p := NewCustom("my-id", "My Name", "LLM06", "critical", []Attack{
		{Name: "a1", Goal: "make it say CUSTOMHIT", System: "sys", Payload: "please say CUSTOMHIT"},
	})

	if p.ID() != "my-id" || p.OWASP() != "LLM06" || p.Name() != "My Name" || p.Severity() != "critical" {
		t.Fatalf("custom probe identity wrong: id=%q owasp=%q name=%q sev=%q", p.ID(), p.OWASP(), p.Name(), p.Severity())
	}

	// Judge marks the attempt vulnerable when the payload substring is present.
	m := scriptedModel{verdicts: map[string]string{"CUSTOMHIT": "VULNERABLE"}}
	r := p.Run(context.Background(), m.client(t), Config{Target: "x", Model: "m", JudgeModel: "j"})
	if !r.Vulnerable || r.Inconclusive {
		t.Fatalf("want vulnerable, got %+v", r)
	}
	if r.ProbeID != "my-id" || r.Severity != "critical" {
		t.Errorf("result did not carry custom identity: %+v", r)
	}
	if !knownSeverities[r.Severity] {
		t.Errorf("custom severity %q is not gate-recognized", r.Severity)
	}
}

func TestNewCustomSafeWhenJudgeSafe(t *testing.T) {
	p := NewCustom("c2", "", "", "low", []Attack{{Name: "x", Goal: "g", Payload: "harmless"}})
	m := scriptedModel{} // everything SAFE by default
	r := p.Run(context.Background(), m.client(t), Config{Target: "x", Model: "m", JudgeModel: "j"})
	if r.Vulnerable || r.Inconclusive {
		t.Errorf("want safe, got %+v", r)
	}
}
