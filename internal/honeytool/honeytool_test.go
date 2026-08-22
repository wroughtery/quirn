package honeytool

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// post sends a body to the honeytool and returns after the response so the hit is
// recorded before the caller inspects it.
func post(t *testing.T, url, body string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post to honeytool: %v", err)
	}
	resp.Body.Close()
}

func TestRecorderRecordsHit(t *testing.T) {
	rec, err := Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer rec.Close()

	post(t, rec.URL()+"/delete_database", `{"ref":"HT-XYZ","name":"prod"}`)

	if got := rec.Count(); got != 1 {
		t.Fatalf("Count = %d, want 1", got)
	}
	hits := rec.HitsSince(time.Time{})
	if len(hits) != 1 {
		t.Fatalf("HitsSince = %d hits, want 1", len(hits))
	}
	h := hits[0]
	if h.Path != "/delete_database" {
		t.Errorf("Path = %q, want /delete_database", h.Path)
	}
	if !strings.Contains(h.Body, "HT-XYZ") {
		t.Errorf("Body = %q, want it to contain the reference", h.Body)
	}
	if h.Method != http.MethodPost {
		t.Errorf("Method = %q, want POST", h.Method)
	}
}

func TestHitsSinceFiltersByTime(t *testing.T) {
	rec, err := Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer rec.Close()

	post(t, rec.URL()+"/x", "one")
	// A cutoff strictly after the recorded hit must exclude it.
	cutoff := time.Now().Add(time.Hour)
	if got := rec.HitsSince(cutoff); len(got) != 0 {
		t.Errorf("HitsSince(future) = %d, want 0", len(got))
	}
	// A zero cutoff includes everything.
	if got := rec.HitsSince(time.Time{}); len(got) != 1 {
		t.Errorf("HitsSince(zero) = %d, want 1", len(got))
	}
}

func TestNonLoopbackRefused(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "8.8.8.8:9999", ":0"} {
		if rec, err := Start(addr); err == nil {
			rec.Close()
			t.Errorf("Start(%q) = nil error, want refusal (non-loopback bind)", addr)
		}
	}
}

func TestLoopbackVariantsAccepted(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:0", "localhost:0"} {
		rec, err := Start(addr)
		if err != nil {
			t.Errorf("Start(%q) = %v, want success", addr, err)
			continue
		}
		rec.Close()
	}
}
