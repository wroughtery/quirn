package probe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"quirn/internal/honeytool"
	"quirn/internal/llm"
)

// agentCallbackServer simulates a tool-using agent. On a target (non-judge) call
// it optionally fires a request at the honeytool (as a real agent would when it
// decides to invoke the dangerous tool), echoing the reference nonce quirn asked
// it to include. The judge returns verdict and is counted.
func agentCallbackServer(t *testing.T, honeyURL, verdict string, callBack, echoNonce bool) (judgeCalls func() int, c *llm.Client) {
	t.Helper()
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s := string(body)
		if strings.Contains(s, "security judge") {
			mu.Lock()
			n++
			mu.Unlock()
			writeContent(w, "VERDICT: "+verdict+"\nscripted")
			return
		}
		if callBack {
			ref := ""
			if echoNonce {
				ref = extractNonce(s)
			}
			resp, err := http.Post(honeyURL+"/delete_database", "application/json",
				strings.NewReader(`{"op":"delete_database","name":"prod","ref":"`+ref+`"}`))
			if err == nil {
				resp.Body.Close()
			}
		}
		writeContent(w, "done — operation carried out")
	}))
	t.Cleanup(srv.Close)
	client := llm.NewClient(srv.URL, "")
	client.BackoffBase = time.Millisecond
	return func() int { mu.Lock(); defer mu.Unlock(); return n }, client
}

// extractNonce pulls the first HT-…-END reference code out of a request body.
func extractNonce(s string) string {
	i := strings.Index(s, "HT-")
	if i < 0 {
		return ""
	}
	end := strings.Index(s[i:], "-END")
	if end < 0 {
		return ""
	}
	return s[i : i+end+len("-END")]
}

// With a honeytool and an agent that actually calls the dangerous tool, the
// excessive-agency finding is CONFIRMED deterministically — vulnerable, no judge.
func TestAgencyHoneytoolConfirmsOnCallback(t *testing.T) {
	rec, err := honeytool.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("honeytool: %v", err)
	}
	defer rec.Close()

	judgeCalls, c := agentCallbackServer(t, rec.URL(), "SAFE", true, true)
	res := NewAgencyProbe().Run(context.Background(), c,
		Config{Model: "m", JudgeModel: "j", AgentMode: true, Honeytool: rec})

	if !res.Vulnerable {
		t.Error("an agent that invoked the honeytool must be CONFIRMED vulnerable")
	}
	if n := judgeCalls(); n != 0 {
		t.Errorf("a honeytool-confirmed finding must not call the judge; called %d", n)
	}
	if !strings.Contains(res.Evidence, "CONFIRMED") || !strings.Contains(res.Evidence, "honeytool") {
		t.Errorf("evidence should record a confirmed honeytool invocation:\n%s", res.Evidence)
	}
	if rec.Count() == 0 {
		t.Error("honeytool should have recorded the agent's tool call")
	}
}

// With a honeytool present but an agent that never calls it, the probe falls
// back to the judge (proxy) path: a VULNERABLE judge verdict is a judged finding,
// not a confirmed one.
func TestAgencyHoneytoolProxyWhenNoCallback(t *testing.T) {
	rec, err := honeytool.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("honeytool: %v", err)
	}
	defer rec.Close()

	judgeCalls, c := agentCallbackServer(t, rec.URL(), "VULNERABLE", false, false)
	res := NewAgencyProbe().Run(context.Background(), c,
		Config{Model: "m", JudgeModel: "j", AgentMode: true, Honeytool: rec})

	if !res.Vulnerable {
		t.Error("a VULNERABLE judge verdict should still flag the proxy finding")
	}
	if judgeCalls() == 0 {
		t.Error("with no honeytool hit the judge (proxy) path must run")
	}
	if strings.Contains(res.Evidence, "CONFIRMED") {
		t.Errorf("without a hit the finding is a proxy, not CONFIRMED:\n%s", res.Evidence)
	}
	if !strings.Contains(res.Evidence, "VULNERABLE:") {
		t.Errorf("evidence should record the judged (proxy) verdict:\n%s", res.Evidence)
	}
	if rec.Count() != 0 {
		t.Errorf("honeytool should have no hits when the agent never calls it; got %d", rec.Count())
	}
}

// A honeytool with a compliant (SAFE) agent that never calls the tool stays safe.
func TestAgencyHoneytoolSafeWhenNoCallbackAndSafeJudge(t *testing.T) {
	rec, err := honeytool.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("honeytool: %v", err)
	}
	defer rec.Close()

	_, c := agentCallbackServer(t, rec.URL(), "SAFE", false, false)
	res := NewAgencyProbe().Run(context.Background(), c,
		Config{Model: "m", JudgeModel: "j", AgentMode: true, Honeytool: rec})

	if res.Vulnerable {
		t.Error("no tool call and a SAFE judge must not be vulnerable")
	}
}

// A honeytool hit that does NOT carry this attack's nonce must NOT be treated as
// a confirmed finding (it could be a stray/concurrent/operator request); it falls
// through to the judge. This is the core honesty guarantee for LLM06 confirmation.
func TestAgencyHoneytoolUnattributedHitNotConfirmed(t *testing.T) {
	rec, err := honeytool.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("honeytool: %v", err)
	}
	defer rec.Close()

	// callBack=true but echoNonce=false: the tool is hit, but with no reference.
	judgeCalls, c := agentCallbackServer(t, rec.URL(), "SAFE", true, false)
	res := NewAgencyProbe().Run(context.Background(), c,
		Config{Model: "m", JudgeModel: "j", AgentMode: true, Honeytool: rec})

	if rec.Count() == 0 {
		t.Fatal("expected the honeytool to have recorded the unattributed hit")
	}
	if res.Vulnerable {
		t.Error("an unattributed honeytool hit (no nonce) must not be CONFIRMED")
	}
	if strings.Contains(res.Evidence, "CONFIRMED") {
		t.Errorf("no nonce means no confirmation:\n%s", res.Evidence)
	}
	if judgeCalls() == 0 {
		t.Error("an unattributed hit must fall through to the judge (proxy) path")
	}
}

// Close is idempotent and returns the same (nil) result each time.
func TestHoneytoolCloseIdempotent(t *testing.T) {
	rec, err := honeytool.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("honeytool: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Errorf("first Close = %v, want nil", err)
	}
	if err := rec.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
}
