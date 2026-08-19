// Package live provides optional, real-time visibility into a running scan:
// a console stream and a local web dashboard that show each attack's payload,
// the target's raw reply, and the judge's verdict as they happen.
//
// It is purely observational. An Observer is nil by default and probe code
// guards every call with a nil check, so a scan with no observer behaves
// exactly as before and produces byte-identical reports. Timestamps and
// latencies surface only in the live view; they never enter a Result or a
// report, so report output stays deterministic.
package live

// Kind identifies which point in a scan's lifecycle an Event marks.
type Kind string

const (
	KindProbeStart     Kind = "probe_start"
	KindAttackStart    Kind = "attack_start"
	KindAttackResponse Kind = "attack_response"
	KindAttackVerdict  Kind = "attack_verdict"
	KindProbeFinish    Kind = "probe_finish"
	KindScanFinish     Kind = "scan_finish"
)

// Event is a single lifecycle notification. It is a flat tagged struct rather
// than a set of typed messages so a sink can switch on Kind and the dashboard
// can serialize it straight to JSON. Only the fields relevant to a given Kind
// are populated; the rest stay zero (and omitempty out of the JSON).
type Event struct {
	Kind Kind `json:"kind"`

	// Probe identity (set on every Kind that carries a probe).
	ProbeID string `json:"probeId,omitempty"`
	OWASP   string `json:"owasp,omitempty"`
	Name    string `json:"name,omitempty"`

	// Attack detail (attack_* kinds).
	Attack  string `json:"attack,omitempty"`
	Goal    string `json:"goal,omitempty"`
	System  string `json:"system,omitempty"`
	Payload string `json:"payload,omitempty"`
	Reply   string `json:"reply,omitempty"`

	// Verdict is "vulnerable" | "safe" | "inconclusive" (attack_verdict,
	// probe_finish).
	Verdict string `json:"verdict,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Error   string `json:"error,omitempty"`

	// LatencyMS is the target/judge call latency in milliseconds
	// (attack_response). Live-view only; never enters a report.
	LatencyMS int64 `json:"latencyMs,omitempty"`

	// Seq is a monotonic sequence number assigned by the dashboard Hub so a
	// browser can order and de-duplicate replayed backlog against the live
	// stream. Emitters leave it zero.
	Seq int `json:"seq"`
}

// Observer receives lifecycle Events during a scan. Handle MUST be safe for
// concurrent use: with concurrency > 1 several probe goroutines emit at once.
type Observer interface {
	Handle(Event)
}

// Emit calls obs.Handle(e) only when obs is non-nil, so probe code can emit
// unconditionally without repeating the nil guard.
func Emit(obs Observer, e Event) {
	if obs != nil {
		obs.Handle(e)
	}
}

// Multi fans one Event out to several observers (e.g. console + dashboard). A
// nil element is skipped. Returns nil when no non-nil observers are given, so
// callers can leave Config.Observer nil in the common "no live view" case.
func Multi(observers ...Observer) Observer {
	var kept multi
	for _, o := range observers {
		if o != nil {
			kept = append(kept, o)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	if len(kept) == 1 {
		return kept[0]
	}
	return kept
}

type multi []Observer

func (m multi) Handle(e Event) {
	for _, o := range m {
		o.Handle(e)
	}
}
