package mockllm

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// post sends body to the handler and returns the assistant content plus status.
func post(t *testing.T, h http.Handler, model, auth, body string) (string, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return "", rec.Code
	}
	var resp struct {
		Choices []struct {
			Message struct{ Content string } `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid chat JSON: %v\n%s", err, rec.Body.String())
	}
	return resp.Choices[0].Message.Content, rec.Code
}

func TestHandlerVerdicts(t *testing.T) {
	h, cap := Handler(Config{VulnMarkers: []string{"PWNED"}})

	// A non-judge (target) call returns a benign completion.
	if c, _ := post(t, h, "m", "", `{"model":"m","messages":[{"content":"hi"}]}`); c != "ok" {
		t.Errorf("target call content = %q, want ok", c)
	}

	// A judge call with the marker is VULNERABLE...
	judge := `{"model":"j","messages":[{"content":"security judge ... PWNED"}]}`
	if c, _ := post(t, h, "j", "", judge); !strings.Contains(c, "VULNERABLE") {
		t.Errorf("judge+marker content = %q, want VULNERABLE", c)
	}
	// ...and without it, SAFE.
	safe := `{"model":"j","messages":[{"content":"security judge ... clean"}]}`
	if c, _ := post(t, h, "j", "", safe); !strings.Contains(c, "SAFE") {
		t.Errorf("judge-no-marker content = %q, want SAFE", c)
	}

	// Capture reflects the most recent request.
	if m, a := cap.Get(); m != "j" || a != "" {
		t.Errorf("capture = (%q,%q), want (j, empty)", m, a)
	}
	post(t, h, "gpt", "Bearer sk-x", `{"model":"gpt","messages":[]}`)
	if m, a := cap.Get(); m != "gpt" || a != "Bearer sk-x" {
		t.Errorf("capture = (%q,%q), want (gpt, Bearer sk-x)", m, a)
	}
}

func TestHandlerFail(t *testing.T) {
	h, _ := Handler(Config{Fail: true})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"model":"m"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("fail mode status = %d, want 500", rec.Code)
	}
	if b, _ := io.ReadAll(rec.Result().Body); string(b) != "down" {
		t.Errorf("fail mode body = %q, want down", b)
	}
}
