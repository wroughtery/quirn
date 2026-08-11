package probe

import (
	"strings"
	"testing"
)

func ids(ps []Probe) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.ID())
	}
	return out
}

func TestSelectDefaultReturnsAll(t *testing.T) {
	ps, err := Select(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != len(All()) {
		t.Errorf("default select = %d probes, want %d", len(ps), len(All()))
	}
}

func TestSelectOnlyByOWASP(t *testing.T) {
	ps, err := Select([]string{"LLM01"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(ps); len(got) != 1 || got[0] != "prompt-injection" {
		t.Errorf("only LLM01 = %v, want [prompt-injection]", got)
	}
}

func TestSelectOnlyByIDCaseInsensitive(t *testing.T) {
	ps, err := Select([]string{"Excessive-Agency"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(ps); len(got) != 1 || got[0] != "excessive-agency" {
		t.Errorf("only Excessive-Agency = %v, want [excessive-agency]", got)
	}
}

func TestSelectOnlyMixedTokens(t *testing.T) {
	ps, err := Select([]string{"LLM01", "misinformation"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := ids(ps)
	if len(got) != 2 || got[0] != "prompt-injection" || got[1] != "misinformation" {
		t.Errorf("got %v, want [prompt-injection misinformation] in registry order", got)
	}
}

func TestSelectSkip(t *testing.T) {
	ps, err := Select(nil, []string{"LLM07", "misinformation"})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids(ps) {
		if id == "system-prompt-leakage" || id == "misinformation" {
			t.Errorf("skipped probe %q still present", id)
		}
	}
	if len(ps) != len(All())-2 {
		t.Errorf("skip removed %d, want 2", len(All())-len(ps))
	}
}

func TestSelectOnlyThenSkip(t *testing.T) {
	// skip is applied after only: only {LLM01,LLM02} minus LLM01 -> just LLM02.
	ps, err := Select([]string{"LLM01", "LLM02"}, []string{"LLM01"})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(ps); len(got) != 1 || got[0] != "sensitive-disclosure" {
		t.Errorf("got %v, want [sensitive-disclosure]", got)
	}
}

func TestSelectUnknownTokenErrors(t *testing.T) {
	if _, err := Select([]string{"LLM99"}, nil); err == nil || !strings.Contains(err.Error(), "unknown probe") {
		t.Errorf("want unknown-probe error for --only, got %v", err)
	}
	if _, err := Select(nil, []string{"nope"}); err == nil || !strings.Contains(err.Error(), "--skip") {
		t.Errorf("want unknown-probe error for --skip, got %v", err)
	}
}

func TestSelectEmptyResultNoError(t *testing.T) {
	// Valid tokens that cancel out yield an empty set, not an error; the CLI
	// decides that empty means misconfiguration.
	ps, err := Select([]string{"LLM01"}, []string{"LLM01"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 0 {
		t.Errorf("want empty selection, got %v", ids(ps))
	}
}
