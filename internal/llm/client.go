// Package llm provides a minimal client for OpenAI-compatible chat completion
// endpoints, used by quirn to talk to both target and judge models.
package llm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Message is a single chat message in an OpenAI-compatible conversation.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// maxResponseBytes caps how much of a target response quirn will read into
// memory. quirn is pointed at endpoints it does not trust, so an endless or
// enormous body must not be able to OOM the process.
const maxResponseBytes = 8 << 20 // 8 MiB

// DefaultRequestTimeout is the per-call HTTP timeout NewClient applies. It is
// generous because quirn is commonly pointed at a local model (Ollama,
// llama.cpp, LM Studio) whose first, cold, or "thinking" responses can take far
// longer than a hosted API's — a too-short timeout there turns a working scan
// into a wall of false inconclusives. Override with Client.SetRequestTimeout.
const DefaultRequestTimeout = 120 * time.Second

// defaultHTTPClient is used when a Client is constructed without one (e.g. a
// struct literal). It is shared and read-only, so concurrent probes can use it
// without a data race.
var defaultHTTPClient = &http.Client{Timeout: DefaultRequestTimeout}

// Retry defaults. A transient 429/5xx or network blip is common against real
// endpoints; retrying keeps it from turning into a false "inconclusive" (which,
// under quirn's fail-closed gate, would redden CI for no real reason).
const (
	defaultMaxRetries  = 2
	defaultBackoffBase = 500 * time.Millisecond
	maxBackoff         = 8 * time.Second
)

// Client talks to an OpenAI-compatible /v1/chat/completions endpoint.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
	// MaxRetries is the number of RETRIES (not attempts) on a transient error;
	// total attempts = MaxRetries+1. Zero disables retrying.
	MaxRetries int
	// BackoffBase is the base delay for exponential backoff between retries.
	BackoffBase time.Duration
	// Provider maps the chat call onto a specific API shape (request + reply
	// parsing). Nil means the default OpenAI-compatible shape, so existing
	// callers and struct literals are unchanged.
	Provider Provider
}

// provider returns the Client's Provider, defaulting to the OpenAI-compatible
// shape when unset so a zero-value or NewClient-built Client behaves as before.
func (c *Client) provider() Provider {
	if c.Provider != nil {
		return c.Provider
	}
	return OpenAIProvider{}
}

// NewClient builds a Client for the given base URL (e.g. "http://localhost:1234"
// or "https://api.openai.com") and API key. baseURL should NOT include the
// "/v1/chat/completions" suffix; that is appended by Chat.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: DefaultRequestTimeout,
		},
		MaxRetries:  defaultMaxRetries,
		BackoffBase: defaultBackoffBase,
	}
}

// SetRequestTimeout sets the per-call HTTP timeout. A value <= 0 disables the
// timeout entirely (relying only on the caller's context deadline), which is
// useful for a very slow local model. Call it during setup, before the client
// is shared across probe goroutines.
func (c *Client) SetRequestTimeout(d time.Duration) {
	if c == nil {
		return
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{}
	}
	if d < 0 {
		d = 0
	}
	c.HTTPClient.Timeout = d
}

// Chat sends messages to the given model and returns the assistant's reply
// content. The provided context controls request timeout/cancellation. A
// transient failure (network error, or HTTP 429/500/502/503/504) is retried up
// to c.MaxRetries times with exponential backoff + jitter, honoring any
// Retry-After header; a non-transient error (4xx other than 429, a malformed
// body) returns immediately.
func (c *Client) Chat(ctx context.Context, model string, messages []Message) (string, error) {
	if c == nil {
		return "", fmt.Errorf("llm: nil client")
	}
	// Resolve into a local rather than writing c.HTTPClient: the runner shares
	// one *Client across concurrent probe goroutines, so mutating the field
	// here would be a data race.
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = defaultHTTPClient
	}

	spec, err := c.provider().BuildSpec(c.BaseURL, c.APIKey, model, messages)
	if err != nil {
		return "", fmt.Errorf("llm: %w", err)
	}

	base := c.BackoffBase
	if base <= 0 {
		base = defaultBackoffBase
	}

	var lastErr error
	var retryAfter time.Duration
	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := backoffDelay(base, attempt, retryAfter)
			if err := sleepCtx(ctx, delay); err != nil {
				return "", fmt.Errorf("llm: %w", err)
			}
		}

		content, ra, retryable, err := c.attempt(ctx, httpClient, spec)
		if err == nil {
			return content, nil
		}
		lastErr = err
		retryAfter = ra
		// Context cancellation/deadline is terminal, and a non-transient error
		// won't fix itself, so stop.
		if !retryable || ctx.Err() != nil {
			return "", err
		}
	}
	if c.MaxRetries > 0 {
		return "", fmt.Errorf("llm: giving up after %d retries: %w", c.MaxRetries, lastErr)
	}
	return "", lastErr
}

// attempt performs one HTTP round trip. It returns the reply content on success,
// or an error plus whether that error is worth retrying and any server-provided
// Retry-After delay.
func (c *Client) attempt(ctx context.Context, httpClient *http.Client, spec chatSpec) (content string, retryAfter time.Duration, retryable bool, err error) {
	httpReq, err := http.NewRequestWithContext(ctx, spec.method, spec.url, bytes.NewReader(spec.body))
	if err != nil {
		return "", 0, false, fmt.Errorf("llm: build request: %w", err)
	}
	for k, v := range spec.headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		// A transport error (connection refused, reset, timeout) is transient.
		return "", 0, true, fmt.Errorf("llm: request failed: %w", err)
	}
	defer resp.Body.Close()

	// Bound the read: an untrusted target must not be able to stream an
	// unbounded body into memory. maxResponseBytes+1 lets us detect overflow.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return "", 0, true, fmt.Errorf("llm: read response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return "", 0, false, fmt.Errorf("llm: response exceeds %d bytes; refusing to buffer", maxResponseBytes)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", parseRetryAfter(resp.Header.Get("Retry-After")), isRetryableStatus(resp.StatusCode),
			fmt.Errorf("llm: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	reply, perr := c.provider().ParseReply(body)
	if perr != nil {
		return "", 0, false, fmt.Errorf("llm: %w", perr)
	}
	return reply, 0, false, nil
}

// isRetryableStatus reports whether an HTTP status is worth retrying: rate limits
// and transient server errors.
func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	default:
		return false
	}
}

// backoffDelay computes the delay before a retry: a server Retry-After (when
// larger) wins; otherwise exponential backoff with full jitter, capped.
func backoffDelay(base time.Duration, attempt int, retryAfter time.Duration) time.Duration {
	ceiling := base << (attempt - 1) // base * 2^(attempt-1)
	if ceiling > maxBackoff || ceiling <= 0 {
		ceiling = maxBackoff
	}
	jittered := time.Duration(rand.Int63n(int64(ceiling) + 1)) // full jitter in [0, ceiling]
	if retryAfter > jittered {
		if retryAfter > maxBackoff {
			return maxBackoff
		}
		return retryAfter
	}
	return jittered
}

// parseRetryAfter parses a Retry-After header expressed in whole seconds.
// HTTP-date form is not honored (rare for these APIs); it yields 0.
func parseRetryAfter(h string) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}

// sleepCtx sleeps for d unless ctx is cancelled first, in which case it returns
// ctx.Err() immediately.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
