package live

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// capture is a test Observer that records every Event it receives. It is safe
// for concurrent use so it can double as a sink in the fan-out tests.
type capture struct {
	mu     sync.Mutex
	events []Event
}

func (c *capture) Handle(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *capture) snapshot() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Event, len(c.events))
	copy(out, c.events)
	return out
}

func TestEventJSONOmitsEmptyKeepsSeq(t *testing.T) {
	b, err := json.Marshal(Event{Kind: KindProbeStart, ProbeID: "prompt-injection", Seq: 3})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, want := range []string{`"kind":"probe_start"`, `"probeId":"prompt-injection"`, `"seq":3`} {
		if !strings.Contains(s, want) {
			t.Errorf("event JSON %s missing %s", s, want)
		}
	}
	// Unset optional fields must be omitted so the stream stays compact.
	for _, absent := range []string{"payload", "reply", "reason", "latencyMs"} {
		if strings.Contains(s, absent) {
			t.Errorf("event JSON %s should omit empty field %q", s, absent)
		}
	}
}

func TestEventSeqAlwaysPresent(t *testing.T) {
	// Seq has no omitempty: a genuine seq of 0 (pre-hub) must still serialize so
	// the browser can distinguish "no seq" from a missing field.
	b, _ := json.Marshal(Event{Kind: KindScanFinish})
	if !strings.Contains(string(b), `"seq":0`) {
		t.Errorf("seq should always serialize, got %s", b)
	}
}

func TestMultiNilAndSingle(t *testing.T) {
	if got := Multi(); got != nil {
		t.Errorf("Multi() = %v, want nil", got)
	}
	if got := Multi(nil, nil); got != nil {
		t.Errorf("Multi(nil,nil) = %v, want nil", got)
	}
	c := &capture{}
	if got := Multi(nil, c); got != Observer(c) {
		t.Errorf("Multi with one real observer should return it unwrapped")
	}
}

func TestMultiFansOut(t *testing.T) {
	a, b := &capture{}, &capture{}
	obs := Multi(a, nil, b)
	obs.Handle(Event{Kind: KindScanFinish})
	if len(a.snapshot()) != 1 || len(b.snapshot()) != 1 {
		t.Errorf("both observers should receive the event; a=%d b=%d", len(a.snapshot()), len(b.snapshot()))
	}
}

func TestEmitNilSafe(t *testing.T) {
	// Must not panic: probe code calls Emit unconditionally with a possibly-nil
	// observer.
	Emit(nil, Event{Kind: KindProbeStart})
	c := &capture{}
	Emit(c, Event{Kind: KindProbeStart})
	if len(c.snapshot()) != 1 {
		t.Errorf("Emit to non-nil observer should deliver once")
	}
}
