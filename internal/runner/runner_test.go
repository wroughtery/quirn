package runner_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"quirn/internal/llm"
	"quirn/internal/probe"
	"quirn/internal/runner"
)

// stubProbe implements probe.Probe without touching the network; onRun lets a
// test observe scheduling.
type stubProbe struct {
	id    string
	onRun func()
}

func (s stubProbe) ID() string       { return s.id }
func (s stubProbe) OWASP() string    { return "LLM01" }
func (s stubProbe) Name() string     { return s.id }
func (s stubProbe) Severity() string { return "high" }
func (s stubProbe) Run(ctx context.Context, _ *llm.Client, _ probe.Config) probe.Result {
	if s.onRun != nil {
		s.onRun()
	}
	return probe.Result{ProbeID: s.id}
}

func TestRunPreservesOrder(t *testing.T) {
	var probes []probe.Probe
	for i := 0; i < 5; i++ {
		i := i
		probes = append(probes, stubProbe{
			id: fmt.Sprintf("p%d", i),
			// Earlier probes sleep longer, so completion order != input order.
			onRun: func() { time.Sleep(time.Duration(5-i) * time.Millisecond) },
		})
	}
	results := runner.Run(context.Background(), nil, probe.Config{}, probes, 8)
	if len(results) != 5 {
		t.Fatalf("want 5 results, got %d", len(results))
	}
	for i, r := range results {
		if want := fmt.Sprintf("p%d", i); r.ProbeID != want {
			t.Errorf("results[%d].ProbeID = %q, want %q", i, r.ProbeID, want)
		}
	}
}

func TestRunBoundsConcurrency(t *testing.T) {
	var inFlight, maxInFlight int64
	var probes []probe.Probe
	for i := 0; i < 12; i++ {
		probes = append(probes, stubProbe{
			id: fmt.Sprintf("p%d", i),
			onRun: func() {
				cur := atomic.AddInt64(&inFlight, 1)
				for {
					m := atomic.LoadInt64(&maxInFlight)
					if cur <= m || atomic.CompareAndSwapInt64(&maxInFlight, m, cur) {
						break
					}
				}
				time.Sleep(5 * time.Millisecond)
				atomic.AddInt64(&inFlight, -1)
			},
		})
	}

	const limit = 3
	runner.Run(context.Background(), nil, probe.Config{}, probes, limit)

	got := atomic.LoadInt64(&maxInFlight)
	if got > limit {
		t.Errorf("max in-flight = %d, want <= %d", got, limit)
	}
	// Lower bound too: if the runner serialized everything, max would be 1 and
	// scans would be needlessly slow. With 12 probes and a 3-slot limit, real
	// concurrency must overlap.
	if got < 2 {
		t.Errorf("max in-flight = %d, want >= 2 (probes never overlapped)", got)
	}
}

func TestRunDefaultsConcurrency(t *testing.T) {
	var ran int64
	probes := []probe.Probe{
		stubProbe{id: "a", onRun: func() { atomic.AddInt64(&ran, 1) }},
		stubProbe{id: "b", onRun: func() { atomic.AddInt64(&ran, 1) }},
	}
	// concurrency <= 0 should fall back to the default, not deadlock.
	runner.Run(context.Background(), nil, probe.Config{}, probes, 0)
	if ran != 2 {
		t.Errorf("ran = %d, want 2", ran)
	}
}
