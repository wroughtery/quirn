package llm

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// chatSpec is the fully-resolved HTTP request for one chat call: a Provider
// turns (model, messages) into this, and the Client's transport layer (retries,
// timeouts, response-size cap) executes it. It is rebuilt per attempt so a retry
// always gets a fresh body reader.
type chatSpec struct {
	method  string
	url     string
	headers map[string]string
	body    []byte
}

// Provider maps quirn's provider-neutral (model, messages) chat call onto a
// specific HTTP API shape and extracts the reply from the response. A Provider
// owns only the request/response SHAPE; transport concerns (retries, backoff,
// size caps, timeouts) stay in Client, so every provider inherits them.
//
// Implementations MUST be safe for concurrent use and hold no per-call state:
// probes share one Client (hence one Provider) across goroutines.
type Provider interface {
	// Name is the stable profile id (e.g. "openai", "anthropic").
	Name() string
	// BuildSpec constructs the HTTP request for one chat call from the Client's
	// baseURL and apiKey plus the model and messages for this call.
	BuildSpec(baseURL, apiKey, model string, messages []Message) (chatSpec, error)
	// ParseReply extracts the assistant's reply text from a 2xx response body.
	// It returns a bare (unprefixed) error; the Client adds the "llm:" prefix.
	ParseReply(body []byte) (string, error)
}

// ProviderOpts carries provider-specific knobs that come from flags/config
// rather than the per-call arguments, so NewProvider can build any provider from
// one uniform call.
type ProviderOpts struct {
	// AzureAPIVersion is the ?api-version= value the azure profile appends. Empty
	// means the azure provider's built-in default.
	AzureAPIVersion string
}

// providerRegistry holds the built-in named providers that self-register via
// init() (anthropic, gemini, azure, ...). openai and template are handled
// directly by NewProvider. A registry lets each provider live in its own file
// and register itself without editing a central switch.
var providerRegistry = map[string]func(ProviderOpts) (Provider, error){}

// registerProvider adds a named provider constructor to the registry. Called
// from provider files' init() functions.
func registerProvider(name string, f func(ProviderOpts) (Provider, error)) {
	providerRegistry[name] = f
}

// NewProvider builds a Provider by profile name. An empty name or "openai"
// yields the default OpenAI-compatible provider. "template" builds a generic
// config-driven provider and requires tmpl. Any other name is looked up in the
// registry of built-in adapters. An unknown name is an error.
func NewProvider(name string, tmpl *TemplateConfig, opts ProviderOpts) (Provider, error) {
	switch name {
	case "", "openai":
		return OpenAIProvider{}, nil
	case "template":
		if tmpl == nil {
			return nil, fmt.Errorf("profile %q requires a template config", name)
		}
		return NewTemplateProvider(*tmpl)
	}
	if f, ok := providerRegistry[name]; ok {
		return f(opts)
	}
	return nil, fmt.Errorf("unknown profile %q (want openai|anthropic|gemini|azure|template)", name)
}

// splitUserSystem collapses quirn's messages into a single user payload and an
// optional system string. quirn only ever sends [system?, user], but this joins
// any extra user turns with newlines for robustness. Shared by the non-OpenAI
// providers, which carry system separately from the user turn.
func splitUserSystem(messages []Message) (payload, system string) {
	var users []string
	for _, m := range messages {
		if m.Role == "system" {
			system = m.Content
			continue
		}
		users = append(users, m.Content)
	}
	return strings.Join(users, "\n"), system
}

// --- OpenAI (default) -------------------------------------------------------

// OpenAIProvider speaks the OpenAI /v1/chat/completions shape: Bearer auth, a
// {model, messages} body, and the reply at choices[0].message.content. It is the
// default and covers every OpenAI-compatible endpoint (OpenAI, Cerebras, Groq,
// Together, Fireworks, OpenRouter, Mistral, DeepInfra, vLLM, Ollama, LM Studio,
// llama.cpp, ...).
type OpenAIProvider struct{}

func (OpenAIProvider) Name() string { return "openai" }

func (OpenAIProvider) BuildSpec(baseURL, apiKey, model string, messages []Message) (chatSpec, error) {
	body, err := json.Marshal(openAIRequest{Model: model, Messages: messages})
	if err != nil {
		return chatSpec{}, fmt.Errorf("encode request: %w", err)
	}
	h := map[string]string{"Content-Type": "application/json"}
	if apiKey != "" {
		h["Authorization"] = "Bearer " + apiKey
	}
	return chatSpec{
		method:  "POST",
		url:     strings.TrimRight(baseURL, "/") + "/v1/chat/completions",
		headers: h,
		body:    body,
	}, nil
}

func (OpenAIProvider) ParseReply(body []byte) (string, error) {
	var r openAIResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if r.Error != nil {
		return "", fmt.Errorf("api error: %s", r.Error.Message)
	}
	if len(r.Choices) == 0 {
		return "", fmt.Errorf("no choices returned")
	}
	return r.Choices[0].Message.Content, nil
}

type openAIRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type openAIResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// --- Generic template (any custom JSON-over-HTTP API) -----------------------

// TemplateConfig describes an arbitrary JSON-over-HTTP chat API so quirn can
// target or judge a provider it has no built-in adapter for. Placeholders,
// written {{name}}, are substituted when a request is built:
//
//	in Body string values : {{payload}} {{system}} {{model}}
//	in Headers / URL       : {{apiKey}} {{model}} {{baseURL}}
//
// Body is a JSON template; its string leaves are substituted and the whole
// structure is re-marshaled, so an injected payload is ALWAYS correctly
// JSON-escaped no matter what quotes/newlines/backslashes it contains — the
// template can never be broken out of by attack text.
type TemplateConfig struct {
	Method    string            `json:"method"`     // default POST
	URL       string            `json:"url"`        // required; may use {{baseURL}} {{model}}
	Headers   map[string]string `json:"headers"`    // values may use {{apiKey}} {{model}} {{baseURL}}
	Body      json.RawMessage   `json:"body"`       // required; a JSON template
	ReplyPath string            `json:"reply_path"` // required; dot path, e.g. choices.0.message.content
}

type templateProvider struct {
	cfg      TemplateConfig
	bodyTmpl interface{} // pre-parsed Body, deep-copied per call during substitution
}

// NewTemplateProvider validates a TemplateConfig and returns a Provider for it.
func NewTemplateProvider(cfg TemplateConfig) (Provider, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("template profile: url is required")
	}
	if len(cfg.Body) == 0 {
		return nil, fmt.Errorf("template profile: body is required")
	}
	if strings.TrimSpace(cfg.ReplyPath) == "" {
		return nil, fmt.Errorf("template profile: reply_path is required")
	}
	var tmpl interface{}
	if err := json.Unmarshal(cfg.Body, &tmpl); err != nil {
		return nil, fmt.Errorf("template profile: body is not valid JSON: %w", err)
	}
	if cfg.Method == "" {
		cfg.Method = "POST"
	}
	cfg.Method = strings.ToUpper(cfg.Method)
	return &templateProvider{cfg: cfg, bodyTmpl: tmpl}, nil
}

func (t *templateProvider) Name() string { return "template" }

func (t *templateProvider) BuildSpec(baseURL, apiKey, model string, messages []Message) (chatSpec, error) {
	payload, system := splitUserSystem(messages)
	// A single-pass Replacer: substituted text is never re-scanned, so an attack
	// payload that itself contains a "{{...}}" token cannot inject another
	// placeholder (e.g. smuggle {{model}} in via {{payload}}).
	bodyRepl := strings.NewReplacer(
		"{{payload}}", payload,
		"{{system}}", system,
		"{{model}}", model,
	)
	body, err := json.Marshal(substituteJSON(t.bodyTmpl, bodyRepl))
	if err != nil {
		return chatSpec{}, fmt.Errorf("build template body: %w", err)
	}
	meta := strings.NewReplacer(
		"{{model}}", model,
		"{{baseURL}}", strings.TrimRight(baseURL, "/"),
		"{{apiKey}}", apiKey,
	)
	h := make(map[string]string, len(t.cfg.Headers)+1)
	hasContentType := false
	for k, v := range t.cfg.Headers {
		h[k] = meta.Replace(v)
		if strings.EqualFold(k, "Content-Type") {
			hasContentType = true
		}
	}
	// Only default the Content-Type when the template set none under ANY casing:
	// a case-mismatched duplicate would race non-deterministically once both keys
	// canonicalize in the request, silently dropping the user's value.
	if !hasContentType {
		h["Content-Type"] = "application/json"
	}
	return chatSpec{method: t.cfg.Method, url: meta.Replace(t.cfg.URL), headers: h, body: body}, nil
}

func (t *templateProvider) ParseReply(body []byte) (string, error) {
	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	got, err := jsonPath(v, t.cfg.ReplyPath)
	if err != nil {
		return "", err
	}
	s, ok := got.(string)
	if !ok {
		return "", fmt.Errorf("reply_path %q did not resolve to a string (got %T)", t.cfg.ReplyPath, got)
	}
	return s, nil
}

// substituteJSON deep-copies a parsed JSON template, replacing placeholder tokens
// in every string leaf via repl (a single-pass Replacer). Re-marshaling the
// returned value escapes all substituted text, so a payload containing
// quotes/newlines/backslashes cannot corrupt or break out of the JSON body.
func substituteJSON(v interface{}, repl *strings.Replacer) interface{} {
	switch node := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(node))
		for k, val := range node {
			out[k] = substituteJSON(val, repl)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(node))
		for i, val := range node {
			out[i] = substituteJSON(val, repl)
		}
		return out
	case string:
		return repl.Replace(node)
	default:
		return v
	}
}

// jsonPath walks a dot-separated path into a decoded JSON value. A numeric
// segment indexes an array; any other segment is a map key.
func jsonPath(v interface{}, path string) (interface{}, error) {
	cur := v
	for _, seg := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]interface{}:
			next, ok := node[seg]
			if !ok {
				return nil, fmt.Errorf("reply_path: key %q not found in response", seg)
			}
			cur = next
		case []interface{}:
			i, err := strconv.Atoi(seg)
			if err != nil {
				return nil, fmt.Errorf("reply_path: %q is not an array index", seg)
			}
			if i < 0 || i >= len(node) {
				return nil, fmt.Errorf("reply_path: index %d out of range (len %d)", i, len(node))
			}
			cur = node[i]
		default:
			return nil, fmt.Errorf("reply_path: cannot descend into %q (value is not an object or array)", seg)
		}
	}
	return cur, nil
}
