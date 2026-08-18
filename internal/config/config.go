// Package config loads an optional JSON configuration file that supplies
// defaults for quirn's scan flags plus per-probe severity overrides.
//
// It is JSON, not YAML, on purpose: JSON parses with the standard library, so
// quirn keeps its single-static-binary, zero-dependency wedge. Precedence is
// resolved by the caller (main): an explicitly-set command-line flag always
// wins over a config value, which in turn wins over the built-in default. This
// package only parses and statically validates the file; probe-ID existence
// (for only/skip/severities) is checked by the caller, which owns the registry.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"quirn/internal/report"
)

// ErrNotExist is returned by Load when the config path does not exist, so the
// caller can distinguish "no config file" from "config file is broken".
var ErrNotExist = errors.New("config file does not exist")

// File is the on-disk config schema. Pointer and slice fields distinguish an
// absent key from a present zero value, so the caller can apply a config value
// only where the user did not pass an explicit flag.
type File struct {
	Version            int      `json:"version"`
	Target             string   `json:"target"`
	Model              string   `json:"model"`
	JudgeModel         string   `json:"judge_model"`
	FailOn             string   `json:"fail_on"`
	FailOnInconclusive *bool    `json:"fail_on_inconclusive"`
	Format             string   `json:"format"`
	Concurrency        *int     `json:"concurrency"`
	Timeout            string   `json:"timeout"`
	MaxRetries         *int     `json:"max_retries"`
	Only               []string `json:"only"`
	Skip               []string `json:"skip"`
	Baseline           string   `json:"baseline"`
	// Severities overrides the reported severity of a probe, keyed by probe ID,
	// e.g. {"prompt-injection": "critical"}. Values must be a valid severity.
	Severities map[string]string `json:"severities"`
	// CustomProbes are user-defined "bring your own payload" probes. Each runs
	// in addition to the selected built-ins, through the same judge/gate/report
	// path, but carries its own id/severity so it never masquerades as a
	// first-party OWASP probe.
	CustomProbes []CustomProbe `json:"custom_probes"`
}

// CustomProbe is a user-defined probe supplied via config.
type CustomProbe struct {
	ID       string         `json:"id"`       // required, unique, must not collide with a built-in
	Name     string         `json:"name"`     // optional; defaults to ID
	OWASP    string         `json:"owasp"`    // optional label; defaults to "CUSTOM"
	Severity string         `json:"severity"` // required, low|medium|high|critical
	Attacks  []CustomAttack `json:"attacks"`  // required, at least one
}

// CustomAttack is a single attack attempt inside a CustomProbe.
type CustomAttack struct {
	Name    string `json:"name"`    // optional label shown in evidence
	Goal    string `json:"goal"`    // required: what the judge treats as success
	System  string `json:"system"`  // optional system message
	Payload string `json:"payload"` // required: the user turn sent to the target
}

// Load reads and statically validates the JSON config at path. Unknown keys are
// rejected so a typo fails fast rather than being silently ignored. It returns
// ErrNotExist if the file is absent.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	// A second value in the stream (e.g. two JSON objects) is a malformed config.
	if dec.More() {
		return nil, fmt.Errorf("parse config %q: unexpected trailing data after JSON object", path)
	}

	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	return &f, nil
}

// validate checks the statically-knowable invariants of a config file.
func (f *File) validate() error {
	if f.Version != 1 {
		return fmt.Errorf("unsupported version %d (want 1)", f.Version)
	}
	if f.FailOn != "" && !report.ValidSeverity(f.FailOn) {
		return fmt.Errorf("fail_on %q is not a valid severity (low|medium|high|critical)", f.FailOn)
	}
	if f.Format != "" && !report.ValidFormat(f.Format) {
		return fmt.Errorf("format %q is not a valid report format (sarif|json|text|markdown)", f.Format)
	}
	if f.Timeout != "" {
		if _, err := time.ParseDuration(f.Timeout); err != nil {
			return fmt.Errorf("timeout %q is not a valid duration (e.g. 10m): %w", f.Timeout, err)
		}
	}
	if f.Concurrency != nil && *f.Concurrency < 1 {
		return fmt.Errorf("concurrency %d must be >= 1", *f.Concurrency)
	}
	if f.MaxRetries != nil && *f.MaxRetries < 0 {
		return fmt.Errorf("max_retries %d must be >= 0", *f.MaxRetries)
	}
	for id, sev := range f.Severities {
		if !report.ValidSeverity(sev) {
			return fmt.Errorf("severities[%q] = %q is not a valid severity (low|medium|high|critical)", id, sev)
		}
	}

	seen := map[string]bool{}
	for i, cp := range f.CustomProbes {
		if strings.TrimSpace(cp.ID) == "" {
			return fmt.Errorf("custom_probes[%d]: id is required", i)
		}
		if seen[cp.ID] {
			return fmt.Errorf("custom_probes: duplicate id %q", cp.ID)
		}
		seen[cp.ID] = true
		if !report.ValidSeverity(cp.Severity) {
			return fmt.Errorf("custom_probes[%q]: severity %q is not valid (low|medium|high|critical)", cp.ID, cp.Severity)
		}
		if len(cp.Attacks) == 0 {
			return fmt.Errorf("custom_probes[%q]: at least one attack is required", cp.ID)
		}
		for j, a := range cp.Attacks {
			if strings.TrimSpace(a.Goal) == "" || strings.TrimSpace(a.Payload) == "" {
				return fmt.Errorf("custom_probes[%q].attacks[%d]: goal and payload are required", cp.ID, j)
			}
		}
	}
	return nil
}

// TimeoutDuration returns the parsed timeout. It is only valid to call after a
// successful Load (which has already verified the string parses); an empty
// string returns (0, false).
func (f *File) TimeoutDuration() (time.Duration, bool) {
	if f.Timeout == "" {
		return 0, false
	}
	d, _ := time.ParseDuration(f.Timeout)
	return d, true
}
