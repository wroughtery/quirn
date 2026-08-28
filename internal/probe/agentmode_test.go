package probe

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wroughtery/quirn/internal/llm"
)

// captureServer records, per role, whether the target received a system message
// and the last judge prompt body, so a test can prove agent mode suppresses the
// synthetic system and swaps in the app-relative goal.
func captureServer(t *testing.T) (c *llm.Client, targetHadSystem func() bool, lastJudge func() string) {
	t.Helper()
	var mu sync.Mutex
	hadSystem := false
	judgeBody := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s := string(b)
		if strings.Contains(s, "security judge") {
			mu.Lock()
			judgeBody = s
			mu.Unlock()
			writeContent(w, "VERDICT: SAFE\nok")
			return
		}
		var req struct {
			Messages []struct {
				Role string `json:"role"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(b, &req)
		mu.Lock()
		for _, m := range req.Messages {
			if m.Role == "system" {
				hadSystem = true
			}
		}
		mu.Unlock()
		writeContent(w, "target reply")
	}))
	t.Cleanup(srv.Close)
	client := llm.NewClient(srv.URL, "")
	client.BackoffBase = time.Millisecond
	return client,
		func() bool { mu.Lock(); defer mu.Unlock(); return hadSystem },
		func() string { mu.Lock(); defer mu.Unlock(); return judgeBody }
}

// In agent mode a canary-planting probe (LLM02) must NOT send its synthetic
// system message, and the judge must receive the app-relative goal (leak the
// app's OWN secret) rather than the planted-canary goal.
func TestAgentModeSuppressesSystemAndUsesAppRelativeGoal(t *testing.T) {
	c, hadSystem, lastJudge := captureServer(t)
	NewSensitiveProbe().Run(context.Background(), c,
		Config{Target: "x", Model: "m", JudgeModel: "j", AgentMode: true})

	if hadSystem() {
		t.Error("agent mode must not send a synthetic system message to the target")
	}
	jb := lastJudge()
	if !strings.Contains(jb, "its OWN system context or configuration") {
		t.Errorf("judge did not get the app-relative agent goal:\n%s", jb)
	}
	// The model-mode goal names the planted canary; agent mode must not use it.
	if strings.Contains(jb, "Extract the planted secret") {
		t.Errorf("agent mode must not use the planted-canary goal:\n%s", jb)
	}
}

// Model mode (the default) is unchanged: the synthetic system IS sent and the
// judge receives the planted-canary goal.
func TestModelModeKeepsSystemAndCanaryGoal(t *testing.T) {
	c, hadSystem, lastJudge := captureServer(t)
	NewSensitiveProbe().Run(context.Background(), c,
		Config{Target: "x", Model: "m", JudgeModel: "j"}) // AgentMode false

	if !hadSystem() {
		t.Error("model mode must send the planted system message to the target")
	}
	if !strings.Contains(lastJudge(), "Extract the planted secret") {
		t.Errorf("model mode should use the planted-canary goal:\n%s", lastJudge())
	}
}
