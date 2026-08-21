package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// templateCfg is a stand-in for a custom JSON API: model/system/payload land in
// bespoke places, auth is a bespoke header, and the reply is nested behind an
// array index.
func templateCfg() TemplateConfig {
	return TemplateConfig{
		Method:    "POST",
		URL:       "{{baseURL}}/custom/{{model}}",
		Headers:   map[string]string{"X-Auth": "Token {{apiKey}}", "X-Model": "{{model}}"},
		Body:      json.RawMessage(`{"model":"{{model}}","sys":"{{system}}","turns":[{"q":"{{payload}}"}]}`),
		ReplyPath: "data.items.0.answer",
	}
}

func TestTemplateProviderEndToEnd(t *testing.T) {
	var gotPath, gotAuth, gotModelHdr string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("X-Auth")
		gotModelHdr = r.Header.Get("X-Model")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		io.WriteString(w, `{"data":{"items":[{"answer":"CUSTOM_REPLY"}]}}`)
	}))
	defer srv.Close()

	p, err := NewProvider("template", ptr(templateCfg()), ProviderOpts{})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	c := NewClient(srv.URL, "KEY123")
	c.Provider = p
	c.BackoffBase = time.Millisecond

	reply, err := c.Chat(context.Background(), "mymodel",
		[]Message{{Role: "system", Content: "SYS"}, {Role: "user", Content: "PAY"}})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if reply != "CUSTOM_REPLY" {
		t.Errorf("reply = %q, want CUSTOM_REPLY (reply_path extraction)", reply)
	}
	if gotPath != "/custom/mymodel" {
		t.Errorf("path = %q, want /custom/mymodel ({{baseURL}}/{{model}})", gotPath)
	}
	if gotAuth != "Token KEY123" {
		t.Errorf("X-Auth = %q, want Token KEY123 ({{apiKey}})", gotAuth)
	}
	if gotModelHdr != "mymodel" {
		t.Errorf("X-Model = %q, want mymodel", gotModelHdr)
	}
	if gotBody["model"] != "mymodel" || gotBody["sys"] != "SYS" {
		t.Errorf("body model/sys wrong: %+v", gotBody)
	}
	turns, _ := gotBody["turns"].([]interface{})
	if len(turns) != 1 {
		t.Fatalf("turns wrong: %+v", gotBody["turns"])
	}
	if q := turns[0].(map[string]interface{})["q"]; q != "PAY" {
		t.Errorf("turns[0].q = %v, want PAY", q)
	}
}

// TestTemplateProviderEscapesPayload is the security property: an attack payload
// full of JSON metacharacters (and a literal {{model}} token) is delivered
// verbatim, the body stays valid JSON, the payload is NOT re-scanned for
// placeholders, and the API key never leaks into the body.
func TestTemplateProviderEscapesPayload(t *testing.T) {
	nasty := "\"}]},\"x\":\"pwn\"\n\t\\ end {{model}} {{apiKey}}"
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		io.WriteString(w, `{"data":{"items":[{"answer":"ok"}]}}`)
	}))
	defer srv.Close()

	p, _ := NewProvider("template", ptr(templateCfg()), ProviderOpts{})
	c := NewClient(srv.URL, "SECRETKEY")
	c.Provider = p
	c.BackoffBase = time.Millisecond

	if _, err := c.Chat(context.Background(), "mymodel",
		[]Message{{Role: "user", Content: nasty}}); err != nil {
		t.Fatalf("Chat: %v", err)
	}

	// Body must still parse (payload could not break out of its JSON string).
	var body map[string]interface{}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("body is not valid JSON after substitution: %v\n%s", err, raw)
	}
	turns := body["turns"].([]interface{})
	q := turns[0].(map[string]interface{})["q"].(string)
	// Delivered verbatim: the literal {{model}}/{{apiKey}} in the payload were NOT
	// re-substituted, and no injected key "x" appeared at the top level.
	if q != nasty {
		t.Errorf("payload mangled:\n got  %q\n want %q", q, nasty)
	}
	if _, injected := body["x"]; injected {
		t.Errorf("payload broke out of its JSON string and injected a key: %+v", body)
	}
	// The API key must never appear in the request body.
	if strings.Contains(string(raw), "SECRETKEY") {
		t.Errorf("API key leaked into the request body:\n%s", raw)
	}
}

func TestTemplateProviderValidation(t *testing.T) {
	base := templateCfg()
	cases := map[string]func(*TemplateConfig){
		"no url":        func(c *TemplateConfig) { c.URL = "" },
		"no body":       func(c *TemplateConfig) { c.Body = nil },
		"no reply_path": func(c *TemplateConfig) { c.ReplyPath = "" },
		"bad body json": func(c *TemplateConfig) { c.Body = json.RawMessage(`{not json`) },
	}
	for name, mutate := range cases {
		cfg := base
		mutate(&cfg)
		if _, err := NewTemplateProvider(cfg); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

func TestTemplateReplyPathErrors(t *testing.T) {
	p, _ := NewTemplateProvider(templateCfg())
	cases := map[string]string{
		"missing key":  `{"data":{"items":[{"nope":"x"}]}}`,
		"index oob":    `{"data":{"items":[]}}`,
		"not a string": `{"data":{"items":[{"answer":42}]}}`,
		"not object":   `{"data":"scalar"}`,
	}
	for name, body := range cases {
		if _, err := p.ParseReply([]byte(body)); err == nil {
			t.Errorf("%s: expected reply_path error, got nil", name)
		}
	}
}

// A template that sets its own Content-Type (any casing) must keep it: the
// default must not sneak in a second, racing header entry.
func TestTemplateProviderHonorsCustomContentType(t *testing.T) {
	cfg := templateCfg()
	cfg.Headers["content-type"] = "application/vnd.custom+json"
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		io.WriteString(w, `{"data":{"items":[{"answer":"ok"}]}}`)
	}))
	defer srv.Close()

	p, _ := NewTemplateProvider(cfg)
	c := NewClient(srv.URL, "K")
	c.Provider = p
	c.BackoffBase = time.Millisecond
	if _, err := c.Chat(context.Background(), "m", []Message{{Role: "user", Content: "x"}}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if gotCT != "application/vnd.custom+json" {
		t.Errorf("Content-Type = %q, want the template's custom value (default must not override)", gotCT)
	}
}

func ptr(c TemplateConfig) *TemplateConfig { return &c }
