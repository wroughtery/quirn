package llm

import (
	"encoding/json"
	"fmt"
	"strings"
)

// --- Anthropic ---------------------------------------------------------------

// anthropicProvider speaks the Anthropic /v1/messages shape: x-api-key auth, a
// {model, max_tokens, system?, messages} body, and the reply concatenated from
// content[].text blocks.
type anthropicProvider struct{}

// anthropicMaxTokens caps the reply length on the Anthropic profile (the API
// requires the field). Sized to comfortably hold a probe reply or a judge
// verdict without truncation.
const anthropicMaxTokens = 4096

func init() {
	registerProvider("anthropic", func(o ProviderOpts) (Provider, error) {
		return anthropicProvider{}, nil
	})
}

func (anthropicProvider) Name() string { return "anthropic" }

func (anthropicProvider) BuildSpec(baseURL, apiKey, model string, messages []Message) (chatSpec, error) {
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}
	_, system := splitUserSystem(messages)

	var msgs []anthropicMessage
	for _, m := range messages {
		if m.Role == "system" {
			continue
		}
		msgs = append(msgs, anthropicMessage{Role: m.Role, Content: m.Content})
	}

	body, err := json.Marshal(anthropicRequest{
		Model: model,
		// Anthropic requires max_tokens. Keep it generous: a target reply
		// truncated mid-completion could hide the incriminating output and read
		// as a false SAFE, which for a scanner is a false negative.
		MaxTokens: anthropicMaxTokens,
		System:    system,
		Messages:  msgs,
	})
	if err != nil {
		return chatSpec{}, fmt.Errorf("encode request: %w", err)
	}

	h := map[string]string{
		"anthropic-version": "2023-06-01",
		"content-type":      "application/json",
	}
	if apiKey != "" {
		h["x-api-key"] = apiKey
	}
	return chatSpec{
		method:  "POST",
		url:     strings.TrimRight(baseURL, "/") + "/v1/messages",
		headers: h,
		body:    body,
	}, nil
}

func (anthropicProvider) ParseReply(body []byte) (string, error) {
	var r anthropicResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if r.Error != nil {
		return "", fmt.Errorf("api error: %s", r.Error.Message)
	}
	var sb strings.Builder
	for _, block := range r.Content {
		if block.Type == "text" {
			sb.WriteString(block.Text)
		}
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("no content returned")
	}
	return sb.String(), nil
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}
