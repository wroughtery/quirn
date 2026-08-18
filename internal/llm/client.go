// Package llm provides a minimal client for OpenAI-compatible chat completion
// endpoints, used by quirn to talk to both target and judge models.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
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

// defaultHTTPClient is used when a Client is constructed without one (e.g. a
// struct literal). It is shared and read-only, so concurrent probes can use it
// without a data race.
var defaultHTTPClient = &http.Client{Timeout: 60 * time.Second}

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
}

// NewClient builds a Client for the given base URL (e.g. "http://localhost:1234"
// or "https://api.openai.com") and API key. baseURL should NOT include the
// "/v1/chat/completions" suffix; that is appended by Chat.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		MaxRetries:  defaultMaxRetries,
		BackoffBase: defaultBackoffBase,
	}
}

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type chatResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
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

	reqBody, err := json.Marshal(chatRequest{Model: model, Messages: messages})
	if err != nil {
		return "", fmt.Errorf("llm: encode request: %w", err)
	}
	url := c.BaseURL + "/v1/chat/completions"

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

		content, ra, retryable, err := c.attempt(ctx, httpClient, url, reqBody)
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
func (c *Client) attempt(ctx context.Context, httpClient *http.Client, url string, reqBody []byte) (content string, retryAfter time.Duration, retryable bool, err error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return "", 0, false, fmt.Errorf("llm: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)
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

	var chatResp chatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return "", 0, false, fmt.Errorf("llm: decode response: %w", err)
	}
	if chatResp.Error != nil {
		return "", 0, false, fmt.Errorf("llm: api error: %s", chatResp.Error.Message)
	}
	if len(chatResp.Choices) == 0 {
		return "", 0, false, fmt.Errorf("llm: no choices returned")
	}
	return chatResp.Choices[0].Message.Content, 0, false, nil
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
