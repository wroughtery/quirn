package probe

import (
	"context"
	"fmt"
	"strings"
	"time"

	"quirn/internal/judge"
	"quirn/internal/live"
	"quirn/internal/llm"
)

// attack is one attack attempt: a human-readable name, the goal handed to the
// judge, an optional system message that establishes the app context being
// attacked (e.g. a planted secret or a fake tool interface), and the raw
// payload sent to the target as the user turn.
type attack struct {
	name    string
	goal    string
	system  string // optional; sent as a system message before payload when non-empty
	payload string
}

// newResult seeds a Result from a probe's identity and severity, so each
// probe's Run body does not repeat the four-field boilerplate.
func newResult(p Probe) Result {
	return Result{
		ProbeID:  p.ID(),
		OWASP:    p.OWASP(),
		Name:     p.Name(),
		Severity: p.Severity(),
	}
}

// runAttacks runs every attack in attacks against the target, judges each
// outcome, and folds the per-attempt verdicts into a single Result seeded from
// base. The Result is Vulnerable if ANY attempt is judged vulnerable; it is
// Inconclusive only when no attempt was vulnerable and at least one attempt
// could not be scored (transport error or unparseable judge reply). A
// confirmed vulnerability always takes precedence over inconclusive attempts.
func runAttacks(ctx context.Context, client *llm.Client, cfg Config, base Result, attacks []attack) Result {
	j := judge.New(client, cfg.JudgeModel)
	obs := cfg.Observer

	live.Emit(obs, live.Event{
		Kind: live.KindProbeStart, ProbeID: base.ProbeID, OWASP: base.OWASP, Name: base.Name,
	})

	var evidence []string
	sawInconclusive := false

	for _, atk := range attacks {
		// Honor a dashboard pause before starting the attack; a stop cancels the
		// context, so GateWait returns an error and we unwind without a false
		// "safe" for the attacks that never ran.
		if err := live.GateWait(cfg.Gate, ctx); err != nil {
			sawInconclusive = true
			evidence = append(evidence, fmt.Sprintf("[%s] not run: scan %v", atk.name, err))
			break
		}

		var messages []llm.Message
		if atk.system != "" {
			messages = append(messages, llm.Message{Role: "system", Content: atk.system})
		}
		messages = append(messages, llm.Message{Role: "user", Content: atk.payload})

		live.Emit(obs, live.Event{
			Kind: live.KindAttackStart, ProbeID: base.ProbeID, Attack: atk.name,
			Goal: atk.goal, System: atk.system, Payload: atk.payload,
		})

		start := time.Now()
		reply, err := client.Chat(ctx, cfg.Model, messages)
		latencyMS := time.Since(start).Milliseconds()
		if err != nil {
			live.Emit(obs, live.Event{
				Kind: live.KindAttackResponse, ProbeID: base.ProbeID, Attack: atk.name,
				Error: err.Error(), LatencyMS: latencyMS,
			})
			sawInconclusive = true
			evidence = append(evidence, fmt.Sprintf("[%s] target request failed: %v", atk.name, err))
			continue
		}
		live.Emit(obs, live.Event{
			Kind: live.KindAttackResponse, ProbeID: base.ProbeID, Attack: atk.name,
			Reply: reply, LatencyMS: latencyMS,
		})

		v := j.Score(ctx, atk.goal, atk.payload, reply)
		switch {
		case v.Vulnerable:
			live.Emit(obs, live.Event{Kind: live.KindAttackVerdict, ProbeID: base.ProbeID, Attack: atk.name, Verdict: "vulnerable", Reason: v.Reason})
			base.Vulnerable = true
			evidence = append(evidence, fmt.Sprintf("[%s] VULNERABLE: %s", atk.name, v.Reason))
		case v.Inconclusive:
			live.Emit(obs, live.Event{Kind: live.KindAttackVerdict, ProbeID: base.ProbeID, Attack: atk.name, Verdict: "inconclusive", Reason: v.Reason})
			sawInconclusive = true
			evidence = append(evidence, fmt.Sprintf("[%s] inconclusive: %s", atk.name, v.Reason))
		default:
			live.Emit(obs, live.Event{Kind: live.KindAttackVerdict, ProbeID: base.ProbeID, Attack: atk.name, Verdict: "safe", Reason: v.Reason})
			evidence = append(evidence, fmt.Sprintf("[%s] safe: %s", atk.name, v.Reason))
		}
	}

	// Only report inconclusive when we have no positive finding; a confirmed
	// vulnerability takes precedence over any incomplete attempts.
	if !base.Vulnerable && sawInconclusive {
		base.Inconclusive = true
	}
	base.Evidence = strings.Join(evidence, "\n")

	live.Emit(obs, live.Event{
		Kind: live.KindProbeFinish, ProbeID: base.ProbeID, OWASP: base.OWASP,
		Name: base.Name, Verdict: verdictLabel(base),
	})

	return base
}

// verdictLabel collapses a finished Result into the live-view verdict string.
func verdictLabel(r Result) string {
	switch {
	case r.Vulnerable:
		return "vulnerable"
	case r.Inconclusive:
		return "inconclusive"
	default:
		return "safe"
	}
}
