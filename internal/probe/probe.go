// Package probe defines the Probe interface and shared types used by all
// OWASP-LLM-Top-10 attack probes, plus the Config passed to each probe run.
package probe

import (
	"context"

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
}

// Result is the outcome of running a single probe against a target.
type Result struct {
	ProbeID    string
	OWASP      string
	Name       string
	Severity   string
	Vulnerable bool
	Evidence   string
}

// Probe is a single OWASP-LLM-Top-10 attack technique that can be run
// against a target model.
type Probe interface {
	// ID is a short, stable, machine-readable identifier (e.g. "prompt-injection").
	ID() string
	// OWASP is the OWASP LLM Top 10 identifier this probe maps to (e.g. "LLM01").
	OWASP() string
	// Name is a short human-readable name for the probe.
	Name() string
	// Run executes the probe against the target described by cfg and
	// returns a Result. Run should not panic; errors talking to the target
	// should be reflected in the Result's Evidence field.
	Run(ctx context.Context, client *llm.Client, cfg Config) Result
}
