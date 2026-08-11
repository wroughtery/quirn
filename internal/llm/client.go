// Package llm provides a minimal client for OpenAI-compatible chat completion
// endpoints, used by quirn to talk to both target and judge models.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// Client talks to an OpenAI-compatible /v1/chat/completions endpoint.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
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
// content. The provided context controls request timeout/cancellation.
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
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("llm: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("llm: request failed: %w", err)
	}
	defer resp.Body.Close()

	// Bound the read: an untrusted target must not be able to stream an
	// unbounded body into memory. maxResponseBytes+1 lets us detect overflow.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("llm: read response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return "", fmt.Errorf("llm: response exceeds %d bytes; refusing to buffer", maxResponseBytes)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("llm: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return "", fmt.Errorf("llm: decode response: %w", err)
	}
	if chatResp.Error != nil {
		return "", fmt.Errorf("llm: api error: %s", chatResp.Error.Message)
	}
	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("llm: no choices returned")
	}

	return chatResp.Choices[0].Message.Content, nil
}
