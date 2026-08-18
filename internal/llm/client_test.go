package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestServer returns a server whose handler is called with the decoded
// request and writes whatever the handler returns as an OpenAI-style body.
func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func okBody(content string) string {
	return `{"choices":[{"message":{"role":"assistant","content":` +
		mustJSON(content) + `}}]}`
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestChatSuccess(t *testing.T) {
	var gotPath, gotAuth, gotModel string
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		var req chatRequest
		_ = json.Unmarshal(body, &req)
		gotModel = req.Model
		io.WriteString(w, okBody("hello there"))
	})

	c := NewClient(srv.URL+"/", "sk-test") // trailing slash must be trimmed
	got, err := c.Chat(context.Background(), "gpt-x", []Message{{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if got != "hello there" {
		t.Errorf("content = %q, want %q", got, "hello there")
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("path = %q, want /v1/chat/completions", gotPath)
	}
	if gotAuth != "Bearer sk-test" {
		t.Errorf("auth = %q, want Bearer sk-test", gotAuth)
	}
	if gotModel != "gpt-x" {
		t.Errorf("model = %q, want gpt-x", gotModel)
	}
}

func TestChatNoAuthHeaderWhenKeyEmpty(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get("Authorization"); h != "" {
			t.Errorf("unexpected Authorization header %q", h)
		}
		io.WriteString(w, okBody("ok"))
	})
	c := NewClient(srv.URL, "")
	if _, err := c.Chat(context.Background(), "m", []Message{{Role: "user", Content: "x"}}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
}

func TestChatAPIErrorField(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"error":{"message":"bad model"}}`)
	})
	c := NewClient(srv.URL, "k")
	_, err := c.Chat(context.Background(), "m", []Message{{Role: "user", Content: "x"}})
	if err == nil || !strings.Contains(err.Error(), "bad model") {
		t.Fatalf("want api error surfaced, got %v", err)
	}
}

func TestChatNon2xx(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, "rate limited")
	})
	c := NewClient(srv.URL, "k")
	_, err := c.Chat(context.Background(), "m", []Message{{Role: "user", Content: "x"}})
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("want status error, got %v", err)
	}
}

func TestChatNoChoices(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[]}`)
	})
	c := NewClient(srv.URL, "k")
	_, err := c.Chat(context.Background(), "m", []Message{{Role: "user", Content: "x"}})
	if err == nil || !strings.Contains(err.Error(), "no choices") {
		t.Fatalf("want no-choices error, got %v", err)
	}
}

func TestChatNilClient(t *testing.T) {
	var c *Client
	_, err := c.Chat(context.Background(), "m", nil)
	if err == nil {
		t.Fatal("want error on nil client")
	}
}

func TestChatRejectsOversizedBody(t *testing.T) {
	// An untrusted target must not be able to OOM the process with an enormous
	// body; Chat caps the read and errors past the cap.
	huge := strings.Repeat("a", (8<<20)+1024)
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"`+huge+`"}}]}`)
	})
	c := NewClient(srv.URL, "")
	_, err := c.Chat(context.Background(), "m", []Message{{Role: "user", Content: "x"}})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want oversize-body error, got %v", err)
	}
}

// countingClient returns a Client (fast backoff) whose server invokes fn with
// the 1-based request count, plus a pointer to that count.
func countingClient(t *testing.T, fn func(n int64, w http.ResponseWriter)) (*Client, *int64) {
	t.Helper()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fn(atomic.AddInt64(&n, 1), w)
	}))
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL, "")
	c.BackoffBase = time.Millisecond // keep retries fast in tests
	return c, &n
}

func TestChatRetriesThenSucceeds(t *testing.T) {
	c, n := countingClient(t, func(n int64, w http.ResponseWriter) {
		if n <= 2 { // first two calls fail transiently
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, "slow down")
			return
		}
		io.WriteString(w, okBody("recovered"))
	})
	got, err := c.Chat(context.Background(), "m", []Message{{Role: "user", Content: "x"}})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if got != "recovered" {
		t.Errorf("content = %q, want recovered", got)
	}
	if *n != 3 {
		t.Errorf("attempts = %d, want 3 (2 failures + 1 success)", *n)
	}
}

func TestChatExhaustsRetries(t *testing.T) {
	c, n := countingClient(t, func(_ int64, w http.ResponseWriter) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "boom")
	})
	_, err := c.Chat(context.Background(), "m", []Message{{Role: "user", Content: "x"}})
	if err == nil || !strings.Contains(err.Error(), "giving up after 2 retries") {
		t.Fatalf("want exhaustion error, got %v", err)
	}
	if *n != 3 { // MaxRetries=2 -> 3 attempts
		t.Errorf("attempts = %d, want 3", *n)
	}
}

func TestChatDoesNotRetryClientError(t *testing.T) {
	c, n := countingClient(t, func(_ int64, w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest) // 400 is not transient
		io.WriteString(w, "nope")
	})
	_, err := c.Chat(context.Background(), "m", []Message{{Role: "user", Content: "x"}})
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("want 400 error, got %v", err)
	}
	if *n != 1 {
		t.Errorf("attempts = %d, want 1 (no retry on 4xx)", *n)
	}
}

func TestChatCancelledContextShortCircuits(t *testing.T) {
	c, n := countingClient(t, func(_ int64, w http.ResponseWriter) {
		io.WriteString(w, okBody("ok"))
	})
	c.MaxRetries = 5
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	_, err := c.Chat(ctx, "m", []Message{{Role: "user", Content: "x"}})
	if err == nil {
		t.Fatal("want error on cancelled context")
	}
	if *n != 0 {
		t.Errorf("server hit %d times, want 0 (cancelled before any request)", *n)
	}
}

func TestSleepCtxRespectsCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); err == nil {
		t.Error("sleepCtx should return the context error immediately")
	}
}

func TestBackoffDelayHonorsRetryAfterAndCap(t *testing.T) {
	// Retry-After larger than the jittered backoff wins.
	got := backoffDelay(time.Millisecond, 1, 3*time.Second)
	if got != 3*time.Second {
		t.Errorf("delay = %v, want Retry-After 3s to win", got)
	}
	// Everything is capped at maxBackoff.
	if got := backoffDelay(time.Hour, 5, time.Hour); got > maxBackoff {
		t.Errorf("delay = %v, want <= maxBackoff %v", got, maxBackoff)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if d := parseRetryAfter("5"); d != 5*time.Second {
		t.Errorf("parseRetryAfter(5) = %v, want 5s", d)
	}
	if d := parseRetryAfter(""); d != 0 {
		t.Errorf("empty = %v, want 0", d)
	}
	if d := parseRetryAfter("Wed, 21 Oct 2026 07:28:00 GMT"); d != 0 {
		t.Errorf("http-date = %v, want 0 (unsupported)", d)
	}
}

// TestChatConcurrentStructLiteralClient guards the lazy-HTTPClient path against
// a data race: a struct-literal Client (no HTTPClient set) shared across
// goroutines must be safe. Run with -race to catch a regression.
func TestChatConcurrentStructLiteralClient(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, okBody("ok"))
	})
	c := &Client{BaseURL: srv.URL} // HTTPClient deliberately nil
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Chat(context.Background(), "m", []Message{{Role: "user", Content: "x"}}); err != nil {
				t.Errorf("Chat: %v", err)
			}
		}()
	}
	wg.Wait()
}
