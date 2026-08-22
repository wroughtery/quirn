package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"quirn/internal/llm"
)

// turnServer records the full message array of every target call and the last
// judge prompt, so a test can prove multi-turn conversations are assembled in
// order (user/assistant/user…). Target replies are "reply1", "reply2", … so an
// appended assistant turn is identifiable in the next call's messages. failOn, if
// matched in a target user turn, makes that call 500 (drives the inconclusive
// path). The judge always returns verdict.
type turnServer struct {
	mu          sync.Mutex
	targetCalls [][]llm.Message
	judgeCount  int
	lastJudge   string
	verdict     string
	failOn      string
}

func newTurnServer(t *testing.T, verdict, failOn string) (*turnServer, *llm.Client) {
	t.Helper()
	ts := &turnServer{verdict: verdict, failOn: failOn}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s := string(body)
		var req struct {
			Messages []llm.Message `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)

		if strings.Contains(s, "security judge") {
			ts.mu.Lock()
			ts.judgeCount++
			ts.lastJudge = s
			ts.mu.Unlock()
			writeContent(w, "VERDICT: "+ts.verdict+"\nscripted")
			return
		}

		ts.mu.Lock()
		ts.targetCalls = append(ts.targetCalls, req.Messages)
		n := len(ts.targetCalls)
		fail := ts.failOn != "" && strings.Contains(s, ts.failOn)
		ts.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, "target down")
			return
		}
		writeContent(w, fmt.Sprintf("reply%d", n))
	}))
	t.Cleanup(srv.Close)
	c := llm.NewClient(srv.URL, "")
	c.BackoffBase = time.Millisecond
	c.MaxRetries = 0
	return ts, c
}

func (ts *turnServer) calls() [][]llm.Message {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.targetCalls
}
func (ts *turnServer) judges() (int, string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.judgeCount, ts.lastJudge
}

func multiTurnProbe() Probe {
	return NewCustom("mt", "Multi-Turn", "CUSTOM", "high", []Attack{{
		Name:      "escalate",
		Goal:      "make the target comply after priming",
		Payload:   "turn-one",
		Followups: []string{"turn-two", "turn-three"},
	}})
}

// A multi-turn attack sends its turns in order, appending each reply as an
// assistant message so the next turn sees it, and judges the final reply.
func TestMultiTurnSendsTurnsInOrder(t *testing.T) {
	ts, c := newTurnServer(t, "SAFE", "")
	multiTurnProbe().Run(context.Background(), c, Config{Model: "m", JudgeModel: "j"})

	calls := ts.calls()
	if len(calls) != 3 {
		t.Fatalf("target calls = %d, want 3 (one per user turn)", len(calls))
	}
	// Turn 1: just the user turn.
	if got := roles(calls[0]); got != "user" {
		t.Errorf("call 1 roles = %q, want \"user\"", got)
	}
	// Turn 2: user, assistant(reply1), user.
	if got := roles(calls[1]); got != "user,assistant,user" {
		t.Errorf("call 2 roles = %q, want user,assistant,user", got)
	}
	if calls[1][1].Content != "reply1" {
		t.Errorf("call 2 assistant content = %q, want reply1 (prior reply appended)", calls[1][1].Content)
	}
	// Turn 3 carries the whole escalation.
	if got := roles(calls[2]); got != "user,assistant,user,assistant,user" {
		t.Errorf("call 3 roles = %q, want the full 5-message escalation", got)
	}
	if calls[2][4].Content != "turn-three" {
		t.Errorf("call 3 final user turn = %q, want turn-three", calls[2][4].Content)
	}

	// The judge runs once, on the FINAL reply, and sees the joined turns.
	n, jp := ts.judges()
	if n != 1 {
		t.Fatalf("judge calls = %d, want 1 (final reply only)", n)
	}
	if !strings.Contains(jp, "reply3") {
		t.Errorf("judge did not score the final reply (reply3):\n%s", jp)
	}
	for _, turn := range []string{"turn-one", "turn-two", "turn-three"} {
		if !strings.Contains(jp, turn) {
			t.Errorf("judge payload missing turn %q (should show the escalation)", turn)
		}
	}
}

// A single-turn attack is byte-identical to the old path: one target call, and
// the judge payload is exactly the lone turn with no multi-turn separator.
func TestSingleTurnUnchanged(t *testing.T) {
	ts, c := newTurnServer(t, "SAFE", "")
	p := NewCustom("st", "Single", "CUSTOM", "high", []Attack{{
		Name: "one", Goal: "g", Payload: "only-turn",
	}})
	p.Run(context.Background(), c, Config{Model: "m", JudgeModel: "j"})

	if calls := ts.calls(); len(calls) != 1 || roles(calls[0]) != "user" {
		t.Fatalf("single-turn should make exactly one user-only call, got %d", len(calls))
	}
	_, jp := ts.judges()
	if strings.Contains(jp, turnSeparator) {
		t.Error("single-turn judge payload must not contain the multi-turn separator")
	}
	if !strings.Contains(jp, "only-turn") {
		t.Errorf("judge payload should carry the single turn verbatim:\n%s", jp)
	}
}

// A transport error partway through a multi-turn sequence yields Inconclusive —
// never a false SAFE — and the judge is not consulted for that attack.
func TestMultiTurnTransportErrorInconclusive(t *testing.T) {
	ts, c := newTurnServer(t, "SAFE", "BOOM")
	p := NewCustom("mt", "MT", "CUSTOM", "high", []Attack{{
		Name: "escalate", Goal: "g",
		Payload:   "turn-one",
		Followups: []string{"BOOM-turn-two", "turn-three"},
	}})
	res := p.Run(context.Background(), c, Config{Model: "m", JudgeModel: "j"})

	if res.Vulnerable {
		t.Error("a mid-sequence transport error must not produce a vulnerable verdict")
	}
	if !res.Inconclusive {
		t.Error("a mid-sequence transport error should be inconclusive")
	}
	if n, _ := ts.judges(); n != 0 {
		t.Errorf("judge should not run when a turn failed; ran %d times", n)
	}
	// The third turn must never be sent after the second failed.
	if calls := ts.calls(); len(calls) != 2 {
		t.Errorf("target calls = %d, want 2 (sequence stops at the failed turn)", len(calls))
	}
}

// roles joins the message roles of one call for compact assertions.
func roles(msgs []llm.Message) string {
	var r []string
	for _, m := range msgs {
		r = append(r, m.Role)
	}
	return strings.Join(r, ",")
}
