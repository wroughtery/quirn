package judge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"quirn/internal/llm"
)

func TestParseVerdict(t *testing.T) {
	tests := []struct {
		name           string
		reply          string
		wantVulnerable bool
		wantInconc     bool
	}{
		{"vulnerable", "VERDICT: VULNERABLE\nit complied", true, false},
		{"safe", "VERDICT: SAFE\nrefused", false, false},
		{"lowercase", "verdict: vulnerable\nyep", true, false},
		{"trailing junk on line 1", "VERDICT: VULNERABLE now\nreason", true, false},
		{"leading whitespace", "   VERDICT: SAFE\n  it declined", false, false},
		{"markdown bold vulnerable", "**VERDICT: VULNERABLE**\nleaked", true, false},
		{"backtick safe", "`VERDICT: SAFE`\nrefused", false, false},
		{"numbered list vulnerable", "1. VERDICT: VULNERABLE\nyes", true, false},
		{"bare token vulnerable", "VULNERABLE", true, false},
		{"bare token safe", "SAFE", false, false},
		{"empty", "", false, true},
		{"whitespace only", "   \n  ", false, true},
		{"unparseable", "I think it was fine, honestly", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := parseVerdict(tt.reply)
			if v.Vulnerable != tt.wantVulnerable {
				t.Errorf("Vulnerable = %v, want %v", v.Vulnerable, tt.wantVulnerable)
			}
			if v.Inconclusive != tt.wantInconc {
				t.Errorf("Inconclusive = %v, want %v", v.Inconclusive, tt.wantInconc)
			}
			if v.Vulnerable && v.Inconclusive {
				t.Error("Vulnerable and Inconclusive both set (must be mutually exclusive)")
			}
			if v.Reason == "" {
				t.Error("Reason should never be empty")
			}
		})
	}
}

func newJudgeServer(t *testing.T, content string, status int) *llm.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != 0 {
			w.WriteHeader(status)
			io.WriteString(w, "boom")
			return
		}
		b, _ := json.Marshal(content)
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":`+string(b)+`}}]}`)
	}))
	t.Cleanup(srv.Close)
	c := llm.NewClient(srv.URL, "")
	c.BackoffBase = time.Millisecond // negligible retry backoff in tests
	return c
}

func TestScoreVulnerable(t *testing.T) {
	j := New(newJudgeServer(t, "VERDICT: VULNERABLE\nleaked the secret", 0), "judge")
	v := j.Score(context.Background(), "goal", "payload", "response")
	if !v.Vulnerable {
		t.Fatalf("want vulnerable, got %+v", v)
	}
}

func TestScoreSafe(t *testing.T) {
	j := New(newJudgeServer(t, "VERDICT: SAFE\nrefused", 0), "judge")
	v := j.Score(context.Background(), "goal", "payload", "response")
	if v.Vulnerable || v.Inconclusive {
		t.Fatalf("want safe, got %+v", v)
	}
}

func TestScoreTransportErrorIsInconclusive(t *testing.T) {
	j := New(newJudgeServer(t, "", http.StatusInternalServerError), "judge")
	v := j.Score(context.Background(), "goal", "payload", "response")
	if !v.Inconclusive || v.Vulnerable {
		t.Fatalf("want inconclusive (never vulnerable) on judge error, got %+v", v)
	}
}

func TestScoreNilJudge(t *testing.T) {
	var j *Judge
	v := j.Score(context.Background(), "g", "p", "r")
	if !v.Inconclusive {
		t.Fatalf("want inconclusive on nil judge, got %+v", v)
	}
}

// TestScoreSendsRubricAndModel pins that Score sends the judge model and places
// goal, payload, and response into the rubric in the right order — a swap
// (e.g. payload<->response) would silently corrupt every verdict, and an empty
// model would 400 a real endpoint.
func TestScoreSendsRubricAndModel(t *testing.T) {
	var gotModel string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req struct {
			Model    string `json:"model"`
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(b, &req)
		gotModel = req.Model
		if len(req.Messages) > 0 {
			gotBody = req.Messages[0].Content
		}
		out, _ := json.Marshal("VERDICT: SAFE\nok")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":`+string(out)+`}}]}`)
	}))
	t.Cleanup(srv.Close)

	j := New(llm.NewClient(srv.URL, ""), "my-judge-model")
	j.Score(context.Background(), "GOALTOKEN", "PAYLOADTOKEN", "RESPONSETOKEN")

	if gotModel != "my-judge-model" {
		t.Errorf("judge model = %q, want my-judge-model", gotModel)
	}
	// The rubric labels the three slots; assert each token lands under its label
	// and in the documented order goal -> payload -> response.
	gi := strings.Index(gotBody, "GOALTOKEN")
	pi := strings.Index(gotBody, "PAYLOADTOKEN")
	ri := strings.Index(gotBody, "RESPONSETOKEN")
	if gi < 0 || pi < 0 || ri < 0 {
		t.Fatalf("rubric missing a slot: goal=%d payload=%d response=%d\n%s", gi, pi, ri, gotBody)
	}
	if !(gi < pi && pi < ri) {
		t.Errorf("rubric slots out of order: goal=%d payload=%d response=%d", gi, pi, ri)
	}
}
