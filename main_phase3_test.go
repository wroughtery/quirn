package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStderr redirects os.Stderr for the duration of fn and returns what was
// written, so a test can assert on quirn's diagnostic warnings.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	os.Stderr = old
	return <-done
}

func TestCanaryWritesDocument(t *testing.T) {
	out := filepath.Join(t.TempDir(), "canary.md")
	if code := run([]string{"canary", "--nonce", "demo1", "--out", out}); code != 0 {
		t.Fatalf("canary exit = %d, want 0", code)
	}
	doc := readFile(t, out)
	for _, want := range []string{"demo1", "INDIRECT-INJECTED-demo1", "QUIRN-CANARY-DOC"} {
		if !strings.Contains(doc, want) {
			t.Errorf("canary doc missing %q:\n%s", want, doc)
		}
	}
}

func TestCanaryRequiresNonce(t *testing.T) {
	if code := run([]string{"canary"}); code != 2 {
		t.Errorf("canary with no --nonce exit = %d, want 2", code)
	}
}

func TestCanaryRejectsInvalidNonce(t *testing.T) {
	if code := run([]string{"canary", "--nonce", "bad nonce"}); code != 2 {
		t.Errorf("canary with a spaced nonce exit = %d, want 2", code)
	}
}

// The indirect-injection probe appears in a scan only when --indirect-nonce is
// given (the operator has seeded the matching canary document).
func TestScanAddsIndirectProbeWithNonce(t *testing.T) {
	url, _ := scriptedServer(t, nil, false)
	out := filepath.Join(t.TempDir(), "r.json")
	code := run([]string{"scan", "--target", url, "--format", "json", "--out", out,
		"--indirect-nonce", "demo1"})
	if code != 0 {
		t.Fatalf("scan exit = %d, want 0 (all safe)", code)
	}
	findings := readEnvelopeFindings(t, out)
	if _, ok := findings["indirect-injection"]; !ok {
		t.Errorf("indirect-injection probe missing when --indirect-nonce set: %v", findings)
	}
}

func TestScanOmitsIndirectProbeWithoutNonce(t *testing.T) {
	url, _ := scriptedServer(t, nil, false)
	out := filepath.Join(t.TempDir(), "r.json")
	run([]string{"scan", "--target", url, "--format", "json", "--out", out})
	if _, ok := readEnvelopeFindings(t, out)["indirect-injection"]; ok {
		t.Error("indirect-injection probe must not run without --indirect-nonce")
	}
}

func TestScanRejectsInvalidIndirectNonce(t *testing.T) {
	url, _ := scriptedServer(t, nil, false)
	code := run([]string{"scan", "--target", url, "--format", "json",
		"--out", filepath.Join(t.TempDir(), "r.json"), "--indirect-nonce", "bad nonce"})
	if code != 2 {
		t.Errorf("scan with an invalid --indirect-nonce exit = %d, want 2", code)
	}
}

// --agent-honeytool without --agent-mode still runs, but warns that it has no
// effect (a bare model cannot call tools).
func TestHoneytoolWithoutAgentModeWarns(t *testing.T) {
	url, _ := scriptedServer(t, nil, false)
	out := filepath.Join(t.TempDir(), "r.json")
	var code int
	stderr := captureStderr(t, func() {
		code = run([]string{"scan", "--target", url, "--format", "json", "--out", out,
			"--agent-honeytool", "--agent-honeytool-addr", "127.0.0.1:0"})
	})
	if code != 0 {
		t.Fatalf("scan exit = %d, want 0", code)
	}
	if !strings.Contains(stderr, "no effect without --agent-mode") {
		t.Errorf("expected a honeytool/agent-mode warning on stderr, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "honeytool listening at") {
		t.Errorf("expected the honeytool URL to be printed, got:\n%s", stderr)
	}
}

// A non-loopback honeytool address is refused as a usage error.
func TestHoneytoolNonLoopbackRefused(t *testing.T) {
	url, _ := scriptedServer(t, nil, false)
	code := run([]string{"scan", "--target", url, "--format", "json",
		"--out", filepath.Join(t.TempDir(), "r.json"),
		"--agent-mode", "--agent-honeytool", "--agent-honeytool-addr", "0.0.0.0:0"})
	if code != 2 {
		t.Errorf("non-loopback honeytool addr exit = %d, want 2", code)
	}
}
