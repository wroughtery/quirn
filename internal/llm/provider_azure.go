package llm

import (
	"encoding/json"
	"fmt"
	"strings"
)

// --- Azure OpenAI ----------------------------------------------------------

// azureProvider speaks the Azure OpenAI chat-completions shape: the deployment
// (model) and api-version live in the URL rather than the body, auth is an
// api-key header (not Bearer), and the reply is parsed exactly like OpenAI's.
type azureProvider struct {
	apiVersion string
}

func init() {
	registerProvider("azure", func(o ProviderOpts) (Provider, error) {
		v := o.AzureAPIVersion
		if v == "" {
			v = "2024-10-21"
		}
		return azureProvider{apiVersion: v}, nil
	})
}

func (azureProvider) Name() string { return "azure" }

func (a azureProvider) BuildSpec(baseURL, apiKey, model string, messages []Message) (chatSpec, error) {
	body, err := json.Marshal(azureRequest{Messages: messages})
	if err != nil {
		return chatSpec{}, fmt.Errorf("encode request: %w", err)
	}
	h := map[string]string{"content-type": "application/json"}
	if apiKey != "" {
		h["api-key"] = apiKey
	}
	url := strings.TrimRight(baseURL, "/") + "/openai/deployments/" + model +
		"/chat/completions?api-version=" + a.apiVersion
	return chatSpec{
		method:  "POST",
		url:     url,
		headers: h,
		body:    body,
	}, nil
}

func (azureProvider) ParseReply(body []byte) (string, error) {
	return OpenAIProvider{}.ParseReply(body)
}

type azureRequest struct {
	Messages []Message `json:"messages"`
}
