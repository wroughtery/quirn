package baseline

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wroughtery/quirn/internal/probe"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if !errors.Is(err, ErrNotExist) {
		t.Fatalf("want ErrNotExist, got %v", err)
	}
}

func TestLoadOK(t *testing.T) {
	path := writeTemp(t, "b.json", `{"version":1,"findings":["prompt-injection","excessive-agency"]}`)
	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !set.Has("prompt-injection") || !set.Has("excessive-agency") {
		t.Errorf("set missing expected ids: %v", set)
	}
	if set.Has("system-prompt-leakage") {
		t.Error("set should not contain unrelated id")
	}
}

func TestLoadBadVersion(t *testing.T) {
	path := writeTemp(t, "b.json", `{"version":99,"findings":[]}`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("want version error, got %v", err)
	}
}

func TestLoadBadJSON(t *testing.T) {
	path := writeTemp(t, "b.json", `{not json`)
	if _, err := Load(path); err == nil {
		t.Fatal("want parse error")
	}
}

func TestNilSetHasNothing(t *testing.T) {
	var s Set
	if s.Has("anything") {
		t.Error("nil set must contain nothing")
	}
}

func TestWriteEmptyIsArrayNotNull(t *testing.T) {
	// A clean run snapshots zero findings; the JSON must be [] not null so
	// external consumers (jq '.findings[]') and diffs stay well-behaved.
	var buf bytes.Buffer
	if err := Write(&buf, []probe.Result{{ProbeID: "x", Vulnerable: false}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "null") {
		t.Errorf("empty findings should serialise as [], got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "[]") {
		t.Errorf("expected empty array, got:\n%s", buf.String())
	}
}

func TestApply(t *testing.T) {
	results := []probe.Result{
		{ProbeID: "prompt-injection", Vulnerable: true},
		{ProbeID: "excessive-agency", Vulnerable: true},
		{ProbeID: "sensitive-disclosure", Vulnerable: false}, // not vulnerable — must stay untouched
	}
	set := Set{"prompt-injection": {}, "sensitive-disclosure": {}}
	n := Apply(results, set)
	if n != 1 {
		t.Fatalf("suppressed = %d, want 1", n)
	}
	if !results[0].Baselined {
		t.Error("prompt-injection should be baselined")
	}
	if results[1].Baselined {
		t.Error("excessive-agency not in baseline, should not be marked")
	}
	if results[2].Baselined {
		t.Error("non-vulnerable result must never be baselined")
	}
}

func TestWriteRoundTripAndDeterminism(t *testing.T) {
	results := []probe.Result{
		{ProbeID: "excessive-agency", Vulnerable: true},
		{ProbeID: "prompt-injection", Vulnerable: true},
		{ProbeID: "system-prompt-leakage", Vulnerable: false}, // excluded
	}
	var a, b bytes.Buffer
	if err := Write(&a, results); err != nil {
		t.Fatal(err)
	}
	if err := Write(&b, results); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Error("Write output must be deterministic")
	}
	// Sorted, so excessive-agency precedes prompt-injection.
	if idx := strings.Index(a.String(), "excessive-agency"); idx < 0 || idx > strings.Index(a.String(), "prompt-injection") {
		t.Errorf("findings not sorted:\n%s", a.String())
	}
	if strings.Contains(a.String(), "system-prompt-leakage") {
		t.Error("non-vulnerable finding must not be written")
	}

	// Round-trip: loading what we wrote yields exactly the vulnerable IDs.
	path := filepath.Join(t.TempDir(), "rt.json")
	if err := WriteFile(path, results); err != nil {
		t.Fatal(err)
	}
	set, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 2 || !set.Has("prompt-injection") || !set.Has("excessive-agency") {
		t.Errorf("round-trip set wrong: %v", set)
	}
}
