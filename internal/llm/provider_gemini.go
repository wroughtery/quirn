package llm

import (
	"encoding/json"
	"fmt"
	"strings"
)

// --- Gemini --------------------------------------------------------------

// geminiProvider speaks the Gemini /v1beta/models/{model}:generateContent
// shape: x-goog-api-key auth, a {contents, systemInstruction?} body, and the
// reply concatenated from candidates[0].content.parts[].text.
type geminiProvider struct{}

func init() {
	registerProvider("gemini", func(o ProviderOpts) (Provider, error) {
		return geminiProvider{}, nil
	})
}

func (geminiProvider) Name() string { return "gemini" }

func (geminiProvider) BuildSpec(baseURL, apiKey, model string, messages []Message) (chatSpec, error) {
	if baseURL == "" {
		baseURL = "https://generativelanguage.googleapis.com"
	}
	payload, system := splitUserSystem(messages)

	req := geminiRequest{
		Contents: []geminiContent{
			{Role: "user", Parts: []geminiPart{{Text: payload}}},
		},
	}
	if system != "" {
		req.SystemInstruction = &geminiContent{Parts: []geminiPart{{Text: system}}}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return chatSpec{}, fmt.Errorf("encode request: %w", err)
	}

	h := map[string]string{"content-type": "application/json"}
	if apiKey != "" {
		h["x-goog-api-key"] = apiKey
	}
	url := strings.TrimRight(baseURL, "/") + "/v1beta/models/" + model + ":generateContent"
	return chatSpec{
		method:  "POST",
		url:     url,
		headers: h,
		body:    body,
	}, nil
}

func (geminiProvider) ParseReply(body []byte) (string, error) {
	var r geminiResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if r.Error != nil {
		return "", fmt.Errorf("api error: %s", r.Error.Message)
	}
	if len(r.Candidates) == 0 || len(r.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("no candidates returned")
	}
	var sb strings.Builder
	for _, part := range r.Candidates[0].Content.Parts {
		sb.WriteString(part.Text)
	}
	return sb.String(), nil
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiRequest struct {
	Contents          []geminiContent `json:"contents"`
	SystemInstruction *geminiContent  `json:"systemInstruction,omitempty"`
}

type geminiResponse struct {
	Candidates []struct {
		Content geminiContent `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}
