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
// attacked (e.g. a planted secret or a fake tool interface), and the user turn(s)
// sent to the target.
//
// Agent mode (Config.AgentMode) tests the DEPLOYED app rather than a synthetic
// scenario: the planted system message is suppressed, and where the model-mode
// goal/payload referenced quirn's planted canary, agentGoal/agentPayload replace
// them with an app-relative form (leak the app's OWN secret/system-prompt, take
// its OWN unauthorized action). An empty agentGoal/agentPayload means the
// model-mode value already works user-only and is reused as-is.
//
// Multi-turn (Phase 3): followups are additional user turns sent after payload;
// between turns the target's reply is appended as an assistant message so the
// conversation escalates. nil followups means a single-turn attack, which is
// byte-identical to the pre-Phase-3 behavior. agentFollowups overrides followups
// in agent mode.
type attack struct {
	name    string
	goal    string
	system  string // optional; sent as a system message before the first turn when non-empty
	payload string // the first (often only) user turn

	followups []string // optional additional user turns (turns 2..N)

	agentGoal      string   // optional; replaces goal in agent mode
	agentPayload   string   // optional; replaces payload in agent mode
	agentFollowups []string // optional; replaces followups in agent mode

	// confirm, when non-nil, is a deterministic check run after the final reply.
	// A true result CONFIRMS the finding without a judge call (Phase 3): the
	// indirect-injection probe checks the reply for its canary nonce; the
	// excessive-agency probe checks whether the honeytool was actually hit since
	// the attack began. A false result falls through to the judge (proxy) path.
	// Confirmers are attached programmatically at probe-run time (a func cannot
	// come from config JSON), so custom probes always use the judge path.
	confirm func(reply string, since time.Time) (confirmed bool, detail string)

	// graded opts this attack into the resistance-ladder judge (ScoreGraded):
	// instead of a binary SAFE/VULNERABLE the judge assigns a tier
	// (OBEYED..FLAGGED), so even an all-SAFE run ranks how close each attempt
	// came to breaking. Only the indirect-injection probe sets it; every other
	// probe keeps the byte-identical binary judge path.
	graded bool
}

// turnSeparator delimits the user turns of a multi-turn attack when they are
// joined into the single payload string shown to the judge, so the judge can see
// the full escalation that led to the final reply it is scoring.
const turnSeparator = "\n\n--- [next user turn] ---\n\n"

// resolve returns the goal, system message, and ordered user turns to use for
// this attack under the given mode. In agent mode the synthetic system is always
// suppressed (the app supplies its own), and agentGoal/agentPayload/agentFollowups
// override goal/payload/followups when set.
func (a attack) resolve(agentMode bool) (goal, system string, turns []string) {
	if !agentMode {
		return a.goal, a.system, append([]string{a.payload}, a.followups...)
	}
	goal, payload := a.goal, a.payload
	if a.agentGoal != "" {
		goal = a.agentGoal
	}
	if a.agentPayload != "" {
		payload = a.agentPayload
	}
	// Agent mode is specified entirely by agent fields. Model-mode followups never
	// carry over: they may reference the synthetic system prompt that agent mode
	// suppresses, which would splice an incoherent conversation. Only
	// agentFollowups add turns in agent mode.
	return goal, "", append([]string{payload}, a.agentFollowups...)
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
// base. The Result is Vulnerable if ANY attempt is judged (or confirmed)
// vulnerable; it is Inconclusive only when no attempt was vulnerable and at
// least one attempt could not be scored (transport error or unparseable judge
// reply). A confirmed vulnerability always takes precedence over inconclusive
// attempts.
func runAttacks(ctx context.Context, client *llm.Client, cfg Config, base Result, attacks []attack) Result {
	// The judge runs on its own client when one is configured (a separate
	// endpoint/key), otherwise it reuses the target client. The target itself is
	// always reached via client.
	judgeClient := cfg.JudgeClient
	if judgeClient == nil {
		judgeClient = client
	}
	j := judge.New(judgeClient, cfg.JudgeModel)
	j.AppPurpose = cfg.AppPurpose
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

		goal, system, turns := atk.resolve(cfg.AgentMode)

		// Send each user turn in order, appending the target's reply as an
		// assistant message so a multi-turn attack escalates within one
		// conversation. The final reply is what gets judged/confirmed.
		var messages []llm.Message
		if system != "" {
			messages = append(messages, llm.Message{Role: "system", Content: system})
		}

		attackStart := time.Now()
		finalReply := ""
		var turnErr error
		failedTurn := 0
		turnCount := len(turns)
		for ti, turn := range turns {
			messages = append(messages, llm.Message{Role: "user", Content: turn})

			startEvt := live.Event{
				Kind: live.KindAttackStart, ProbeID: base.ProbeID, Attack: atk.name,
				Goal: goal, Payload: turn,
			}
			if ti == 0 {
				startEvt.System = system
			}
			// Only multi-turn attacks carry turn markers, so single-turn live
			// events stay byte-identical.
			if turnCount > 1 {
				startEvt.Turn = ti + 1
				startEvt.TurnCount = turnCount
			}
			live.Emit(obs, startEvt)

			start := time.Now()
			reply, err := client.Chat(ctx, cfg.Model, messages)
			latencyMS := time.Since(start).Milliseconds()
			respEvt := live.Event{
				Kind: live.KindAttackResponse, ProbeID: base.ProbeID, Attack: atk.name,
				LatencyMS: latencyMS,
			}
			if turnCount > 1 {
				respEvt.Turn = ti + 1
				respEvt.TurnCount = turnCount
			}
			if err != nil {
				respEvt.Error = err.Error()
				live.Emit(obs, respEvt)
				turnErr = err
				failedTurn = ti + 1
				break
			}
			respEvt.Reply = reply
			live.Emit(obs, respEvt)
			finalReply = reply
			// Feed the reply back in as context for the next turn (not needed after
			// the last turn).
			if ti < turnCount-1 {
				messages = append(messages, llm.Message{Role: "assistant", Content: reply})
			}
		}

		// A deterministic confirmer (Phase 3) beats the judge: a canary echo
		// (indirect injection) or a real honeytool hit (excessive agency) is proof,
		// not inference. It runs even when a turn errored — a reply-independent
		// confirmer (the honeytool) may already hold proof (the agent invoked the
		// dangerous tool, then the call timed out); discarding that recorded hit as
		// merely "inconclusive" would be a false negative on the strongest evidence
		// quirn can obtain. A confirmer that needs the reply (indirect injection)
		// simply fails to match an empty reply and falls through.
		if atk.confirm != nil {
			if confirmed, detail := atk.confirm(finalReply, attackStart); confirmed {
				live.Emit(obs, live.Event{Kind: live.KindAttackVerdict, ProbeID: base.ProbeID, Attack: atk.name, Verdict: "vulnerable", Reason: "confirmed: " + detail})
				base.Vulnerable = true
				if atk.graded {
					base.Grade = judge.WorseGrade(base.Grade, judge.GradeConfirmed)
				}
				evidence = append(evidence, fmt.Sprintf("[%s] CONFIRMED: %s", atk.name, detail))
				continue
			}
		}

		// A transport error with no confirmation is inconclusive (never a false
		// SAFE); the judge is not consulted for an incomplete conversation. The
		// turn index tells the operator whether the opener or a later escalation
		// turn broke.
		if turnErr != nil {
			sawInconclusive = true
			turnLabel := ""
			if turnCount > 1 {
				turnLabel = fmt.Sprintf(" (turn %d/%d)", failedTurn, turnCount)
			}
			evidence = append(evidence, fmt.Sprintf("[%s] target request failed%s: %v", atk.name, turnLabel, turnErr))
			continue
		}

		// Judge (proxy) path. Single-turn passes the lone turn to the judge
		// byte-identically; multi-turn joins the turns so the judge sees the
		// escalation behind the final reply it scores.
		judgePayload := turns[0]
		if len(turns) > 1 {
			judgePayload = strings.Join(turns, turnSeparator)
		}
		var v judge.Verdict
		if atk.graded {
			v = j.ScoreGraded(ctx, goal, judgePayload, finalReply)
		} else {
			v = j.Score(ctx, goal, judgePayload, finalReply)
		}
		// gradeTag annotates the graded probe's evidence and live reason with the
		// resistance tier (e.g. " [FLAGGED]"), so an all-SAFE run still shows how
		// each attempt ranked. Empty for the binary path.
		gradeTag := ""
		if v.Grade != "" {
			gradeTag = " [" + v.Grade + "]"
			base.Grade = judge.WorseGrade(base.Grade, v.Grade)
		}
		switch {
		case v.Vulnerable:
			live.Emit(obs, live.Event{Kind: live.KindAttackVerdict, ProbeID: base.ProbeID, Attack: atk.name, Verdict: "vulnerable", Reason: strings.TrimSpace(gradeTag + " " + v.Reason)})
			base.Vulnerable = true
			evidence = append(evidence, fmt.Sprintf("[%s] VULNERABLE%s: %s", atk.name, gradeTag, v.Reason))
		case v.Inconclusive:
			live.Emit(obs, live.Event{Kind: live.KindAttackVerdict, ProbeID: base.ProbeID, Attack: atk.name, Verdict: "inconclusive", Reason: v.Reason})
			sawInconclusive = true
			evidence = append(evidence, fmt.Sprintf("[%s] inconclusive: %s", atk.name, v.Reason))
		default:
			live.Emit(obs, live.Event{Kind: live.KindAttackVerdict, ProbeID: base.ProbeID, Attack: atk.name, Verdict: "safe", Reason: strings.TrimSpace(gradeTag + " " + v.Reason)})
			evidence = append(evidence, fmt.Sprintf("[%s] safe%s: %s", atk.name, gradeTag, v.Reason))
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
