package probe

import (
	"context"
	"fmt"
	"strings"

	"quirn/internal/judge"
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

// runAttacks runs every attack in attacks against the target, judges each
// outcome, and folds the per-attempt verdicts into a single Result seeded from
// base. The Result is Vulnerable if ANY attempt is judged vulnerable; it is
// Inconclusive only when no attempt was vulnerable and at least one attempt
// could not be scored (transport error or unparseable judge reply). A
// confirmed vulnerability always takes precedence over inconclusive attempts.
func runAttacks(ctx context.Context, client *llm.Client, cfg Config, base Result, attacks []attack) Result {
	j := judge.New(client, cfg.JudgeModel)

	var evidence []string
	sawInconclusive := false

	for _, atk := range attacks {
		var messages []llm.Message
		if atk.system != "" {
			messages = append(messages, llm.Message{Role: "system", Content: atk.system})
		}
		messages = append(messages, llm.Message{Role: "user", Content: atk.payload})

		reply, err := client.Chat(ctx, cfg.Model, messages)
		if err != nil {
			sawInconclusive = true
			evidence = append(evidence, fmt.Sprintf("[%s] target request failed: %v", atk.name, err))
			continue
		}

		v := j.Score(ctx, atk.goal, atk.payload, reply)
		switch {
		case v.Vulnerable:
			base.Vulnerable = true
			evidence = append(evidence, fmt.Sprintf("[%s] VULNERABLE: %s", atk.name, v.Reason))
		case v.Inconclusive:
			sawInconclusive = true
			evidence = append(evidence, fmt.Sprintf("[%s] inconclusive: %s", atk.name, v.Reason))
		default:
			evidence = append(evidence, fmt.Sprintf("[%s] safe: %s", atk.name, v.Reason))
		}
	}

	// Only report inconclusive when we have no positive finding; a confirmed
	// vulnerability takes precedence over any incomplete attempts.
	if !base.Vulnerable && sawInconclusive {
		base.Inconclusive = true
	}
	base.Evidence = strings.Join(evidence, "\n")

	return base
}
