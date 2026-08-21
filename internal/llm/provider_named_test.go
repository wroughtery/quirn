package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// capturedRequest holds what the fake server observed about one incoming
// request, so each test can assert on path, headers, and decoded body.
type capturedRequest struct {
	path    string
	rawURL  string
	headers http.Header
	body    map[string]interface{}
}

func TestAnthropicProvider(t *testing.T) {
	var captured capturedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.path = r.URL.Path
		captured.rawURL = r.URL.String()
		captured.headers = r.Header.Clone()
		if err := json.NewDecoder(r.Body).Decode(&captured.body); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"REPLY"}]}`))
	}))
	defer srv.Close()

	provider, err := NewProvider("anthropic", nil, ProviderOpts{})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	c := NewClient(srv.URL, "KEY")
	c.Provider = provider
	c.BackoffBase = time.Millisecond

	reply, err := c.Chat(context.Background(), "MODEL", []Message{
		{Role: "system", Content: "SYS"},
		{Role: "user", Content: "PAY"},
	})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if reply != "REPLY" {
		t.Errorf("reply = %q, want %q", reply, "REPLY")
	}

	if got := captured.path; got != "/v1/messages" {
		t.Errorf("path = %q, want %q", got, "/v1/messages")
	}
	if got := captured.headers.Get("x-api-key"); got != "KEY" {
		t.Errorf("x-api-key header = %q, want %q", got, "KEY")
	}
	if got := captured.body["system"]; got != "SYS" {
		t.Errorf("body.system = %v, want %q", got, "SYS")
	}
	msgs, ok := captured.body["messages"].([]interface{})
	if !ok || len(msgs) != 1 {
		t.Fatalf("body.messages = %v, want one entry", captured.body["messages"])
	}
	m0 := msgs[0].(map[string]interface{})
	if m0["role"] != "user" || m0["content"] != "PAY" {
		t.Errorf("body.messages[0] = %v, want role=user content=PAY", m0)
	}
}

func TestGeminiProvider(t *testing.T) {
	var captured capturedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.path = r.URL.Path
		captured.rawURL = r.URL.String()
		captured.headers = r.Header.Clone()
		if err := json.NewDecoder(r.Body).Decode(&captured.body); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"REPLY"}]}}]}`))
	}))
	defer srv.Close()

	provider, err := NewProvider("gemini", nil, ProviderOpts{})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	c := NewClient(srv.URL, "KEY")
	c.Provider = provider
	c.BackoffBase = time.Millisecond

	reply, err := c.Chat(context.Background(), "MODEL", []Message{
		{Role: "system", Content: "SYS"},
		{Role: "user", Content: "PAY"},
	})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if reply != "REPLY" {
		t.Errorf("reply = %q, want %q", reply, "REPLY")
	}

	if want := "/v1beta/models/MODEL:generateContent"; captured.path != want {
		t.Errorf("path = %q, want %q", captured.path, want)
	}
	if got := captured.headers.Get("x-goog-api-key"); got != "KEY" {
		t.Errorf("x-goog-api-key header = %q, want %q", got, "KEY")
	}

	contents, ok := captured.body["contents"].([]interface{})
	if !ok || len(contents) != 1 {
		t.Fatalf("body.contents = %v, want one entry", captured.body["contents"])
	}
	c0 := contents[0].(map[string]interface{})
	parts, ok := c0["parts"].([]interface{})
	if !ok || len(parts) != 1 {
		t.Fatalf("body.contents[0].parts = %v, want one entry", c0["parts"])
	}
	if got := parts[0].(map[string]interface{})["text"]; got != "PAY" {
		t.Errorf("body.contents[0].parts[0].text = %v, want %q", got, "PAY")
	}

	sysInstr, ok := captured.body["systemInstruction"].(map[string]interface{})
	if !ok {
		t.Fatalf("body.systemInstruction = %v, want an object", captured.body["systemInstruction"])
	}
	sysParts, ok := sysInstr["parts"].([]interface{})
	if !ok || len(sysParts) != 1 {
		t.Fatalf("body.systemInstruction.parts = %v, want one entry", sysInstr["parts"])
	}
	if got := sysParts[0].(map[string]interface{})["text"]; got != "SYS" {
		t.Errorf("body.systemInstruction.parts[0].text = %v, want %q", got, "SYS")
	}
}

func TestAzureProvider(t *testing.T) {
	var captured capturedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.path = r.URL.Path
		captured.rawURL = r.URL.String()
		captured.headers = r.Header.Clone()
		if err := json.NewDecoder(r.Body).Decode(&captured.body); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"REPLY"}}]}`))
	}))
	defer srv.Close()

	provider, err := NewProvider("azure", nil, ProviderOpts{})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	c := NewClient(srv.URL, "KEY")
	c.Provider = provider
	c.BackoffBase = time.Millisecond

	reply, err := c.Chat(context.Background(), "MODEL", []Message{
		{Role: "system", Content: "SYS"},
		{Role: "user", Content: "PAY"},
	})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if reply != "REPLY" {
		t.Errorf("reply = %q, want %q", reply, "REPLY")
	}

	wantPathPrefix := "/openai/deployments/MODEL/chat/completions"
	if !strings.Contains(captured.path, wantPathPrefix) {
		t.Errorf("path = %q, want to contain %q", captured.path, wantPathPrefix)
	}
	if !strings.Contains(captured.rawURL, "api-version=") {
		t.Errorf("url = %q, want to contain %q", captured.rawURL, "api-version=")
	}
	if got := captured.headers.Get("api-key"); got != "KEY" {
		t.Errorf("api-key header = %q, want %q", got, "KEY")
	}
	if got := captured.headers.Get("Authorization"); got != "" {
		t.Errorf("Authorization header = %q, want empty (azure uses api-key, not Bearer)", got)
	}

	msgs, ok := captured.body["messages"].([]interface{})
	if !ok || len(msgs) != 2 {
		t.Fatalf("body.messages = %v, want two entries", captured.body["messages"])
	}
	m0 := msgs[0].(map[string]interface{})
	if m0["role"] != "system" || m0["content"] != "SYS" {
		t.Errorf("body.messages[0] = %v, want role=system content=SYS", m0)
	}
	m1 := msgs[1].(map[string]interface{})
	if m1["role"] != "user" || m1["content"] != "PAY" {
		t.Errorf("body.messages[1] = %v, want role=user content=PAY", m1)
	}
}
