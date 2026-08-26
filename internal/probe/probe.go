// Package probe defines the Probe interface and shared types used by all
// OWASP-LLM-Top-10 attack probes, plus the Config passed to each probe run.
package probe

import (
	"context"

	"quirn/internal/honeytool"
	"quirn/internal/live"
	"quirn/internal/llm"
)

// Config carries the run-time configuration a probe needs to execute against
// a target endpoint and, optionally, a separate judge model.
type Config struct {
	// Target is the base URL of the OpenAI-compatible endpoint under test.
	Target string
	// Model is the model name to send probe payloads to.
	Model string
	// JudgeModel is the model name used to judge whether an attack
	// succeeded. May be empty if judging is not yet implemented for a probe.
	JudgeModel string
	// AppPurpose, when non-empty, is the stated purpose of the deployed
	// application under test. It is handed to the judge so it can tell a genuine
	// policy break from normal on-task behavior. Empty in model-mode, which keeps
	// judging byte-identical.
	AppPurpose string
	// AgentMode, when true, tests the deployed application rather than a bare
	// model: quirn's synthetic system prompts are suppressed (the app supplies
	// its own) and canary-dependent probes switch to app-relative success signals.
	// False (the default) preserves model-mode behavior exactly.
	AgentMode bool
	// Honeytool, when non-nil, is a running loopback listener the excessive-agency
	// probe (LLM06) uses to CONFIRM that the agent actually invoked a dangerous
	// tool (a recorded hit), rather than only inferring intent from the reply text.
	// Nil (the default) keeps LLM06 on its judge-only proxy path, byte-identical.
	Honeytool *honeytool.Recorder
	// JudgeClient, when non-nil, is a separate llm.Client used only for judge
	// calls, so the judge can live on a different endpoint/key than the target
	// (e.g. a cheap local target judged by a capable hosted model). When nil the
	// judge reuses the target client, which is byte-identical to the original
	// single-endpoint behavior.
	JudgeClient *llm.Client
	// Observer, when non-nil, receives live lifecycle events as the probe
	// runs (payload sent, target reply, judge verdict). It is purely
	// observational: it never affects the Result or report output. Nil in the
	// common case, which preserves byte-identical reports.
	Observer live.Observer
	// Gate, when non-nil, is consulted before each attack so the dashboard can
	// pause the scan. Nil in the common case (no pausing). A gated scan that is
	// stopped unwinds via the context; pausing only delays, it never changes a
	// Result, so reports stay byte-identical.
	Gate live.Gate
}

// Result is the outcome of running a single probe against a target.
type Result struct {
	ProbeID    string
	OWASP      string
	Name       string
	Severity   string
	Vulnerable bool
	// Inconclusive is true when the probe could not reach a verdict (e.g. the
	// judge model errored or replied unparseably). It is never set together
	// with Vulnerable; an inconclusive probe is not treated as a finding.
	Inconclusive bool
	// Baselined is true when this finding matched an entry in a loaded
	// baseline file. A baselined finding is still Vulnerable, but it is
	// excluded from the severity gate and from SARIF output so PRs surface
	// only *new* vulnerabilities. See internal/baseline.
	Baselined bool
	// Grade is the probe's resistance rating, set only by probes that use the
	// graded judge (currently indirect-injection). It holds the WEAKEST tier
	// seen across the probe's attempts (judge.Grade* / judge.GradeConfirmed) —
	// the security-relevant one — and is empty for ungraded probes. It records
	// how the target resisted; it does not by itself change Vulnerable.
	Grade    string `json:",omitempty"`
	Evidence string
}

// StableID returns the deterministic identifier used to match a finding
// against a baseline. Each probe emits at most one Result, so the probe ID is
// a stable, unique key that survives rewording of names or evidence.
func (r Result) StableID() string { return r.ProbeID }

// Probe is a single OWASP-LLM-Top-10 attack technique that can be run
// against a target model.
type Probe interface {
	// ID is a short, stable, machine-readable identifier (e.g. "prompt-injection").
	ID() string
	// OWASP is the OWASP LLM Top 10 identifier this probe maps to (e.g. "LLM01").
	OWASP() string
	// Name is a short human-readable name for the probe.
	Name() string
	// Severity is the finding severity this probe reports when vulnerable
	// (low|medium|high|critical). Exposed on the interface so probes can be
	// listed and gated on without executing them.
	Severity() string
	// Run executes the probe against the target described by cfg and
	// returns a Result. Run should not panic; errors talking to the target
	// should be reflected in the Result's Evidence field.
	Run(ctx context.Context, client *llm.Client, cfg Config) Result
}
