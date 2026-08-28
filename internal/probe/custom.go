package probe

import (
	"context"

	"github.com/wroughtery/quirn/internal/llm"
)

// Attack is a single externally-supplied attack attempt for a custom probe. It
// mirrors the package-internal attack type but is exported so callers (e.g. a
// config file's custom_probes) can define their own payloads without depending
// on probe internals.
type Attack struct {
	Name      string   // short label shown in evidence
	Goal      string   // handed to the judge: what success looks like
	System    string   // optional system message establishing app context
	Payload   string   // the first user turn sent to the target
	Followups []string // optional additional user turns (multi-turn attack); apply in BOTH model and agent mode
}

// customProbe is a probe assembled from externally-supplied attacks. It carries
// its own identity and severity rather than borrowing an OWASP-mapped built-in's,
// so a user's BYO payloads never masquerade as a first-party OWASP probe. It
// runs through the exact same runAttacks path as the built-ins, so custom
// findings are judged, gated, baselined, and reported identically.
type customProbe struct {
	id       string
	name     string
	owasp    string
	severity string
	attacks  []attack
}

// NewCustom builds a Probe from user-supplied attacks. The caller is
// responsible for validating id/name/owasp/severity; NewCustom copies the
// attacks into the internal representation.
func NewCustom(id, name, owasp, severity string, attacks []Attack) Probe {
	internal := make([]attack, len(attacks))
	for i, a := range attacks {
		// A custom attack has one Goal/Payload/Followups, not the built-ins' split
		// model-vs-agent fields. Mirror Followups into agentFollowups so a custom
		// multi-turn probe escalates in agent mode too (resolve reads only
		// agentFollowups there). Safe because a custom probe's turns reference no
		// synthetic system prompt — the concern behind agent mode dropping built-in
		// model-mode followups (see attack.resolve) does not apply here.
		internal[i] = attack{
			name: a.Name, goal: a.Goal, system: a.System, payload: a.Payload,
			followups: a.Followups, agentFollowups: a.Followups,
		}
	}
	return customProbe{id: id, name: name, owasp: owasp, severity: severity, attacks: internal}
}

func (p customProbe) ID() string       { return p.id }
func (p customProbe) OWASP() string    { return p.owasp }
func (p customProbe) Name() string     { return p.name }
func (p customProbe) Severity() string { return p.severity }

func (p customProbe) Run(ctx context.Context, client *llm.Client, cfg Config) Result {
	return runAttacks(ctx, client, cfg, newResult(p), p.attacks)
}
