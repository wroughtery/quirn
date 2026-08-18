// Package mockllm is a deterministic, in-memory stand-in for an
// OpenAI-compatible endpoint. It serves BOTH the target-under-test and the
// judge on one handler so a full quirn scan can run end-to-end with no network
// and no API key. Tests use Handler directly; cmd/mockllm wraps it in a server
// so quirn can be dogfooded against a live target and every report format
// inspected by eye.
//
// It is deterministic: given the same VulnMarkers it always returns the same
// verdicts, so scans are reproducible and diffable across iterations.
package mockllm

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Config controls the mock's behavior.
type Config struct {
	// VulnMarkers are substrings that, when present in a judge request, make
	// that probe come back VULNERABLE. Each probe's payloads embed a distinct
	// canary (e.g. "PWNED" for prompt-injection); list a marker to make the
	// matching probe report vulnerable, omit it to keep that probe SAFE.
	VulnMarkers []string
	// Fail, when true, makes every request return HTTP 500 so a scan is
	// entirely inconclusive (exercises the fail-closed path).
	Fail bool
}

// Capture records what the endpoint last saw, so callers can assert the client
// resolved the model and API key correctly.
type Capture struct {
	mu    sync.Mutex
	model string
	auth  string
}

// Get returns the last observed model name and Authorization header.
func (c *Capture) Get() (model, auth string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.model, c.auth
}

func (c *Capture) record(model, auth string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.model = model
	c.auth = auth
}

// Handler returns an http.Handler serving /v1/chat/completions (and any path)
// and a Capture recording the most recent request. A request is treated as a
// judge call when its body contains the judge rubric marker "security judge";
// such a call returns VULNERABLE if the body also contains any VulnMarker, else
// SAFE. All other (target) calls return a benign "ok" completion.
func Handler(cfg Config) (http.Handler, *Capture) {
	cap := &Capture{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(body, &req)
		cap.record(req.Model, r.Header.Get("Authorization"))

		if cfg.Fail {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, "down")
			return
		}

		s := string(body)
		if !strings.Contains(s, "security judge") {
			writeChat(w, "ok")
			return
		}
		verdict := "SAFE"
		for _, m := range cfg.VulnMarkers {
			if strings.Contains(s, m) {
				verdict = "VULNERABLE"
				break
			}
		}
		writeChat(w, "VERDICT: "+verdict+"\nscripted")
	})
	return h, cap
}

// writeChat writes a minimal OpenAI chat-completions response carrying content.
func writeChat(w http.ResponseWriter, content string) {
	b, _ := json.Marshal(content)
	io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":`+string(b)+`}}]}`)
}
