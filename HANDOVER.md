# Handover - Quirn agent-mode roadmap: Phase 3 next (2026-08-21)

## Goal
**Quirn** - "gitleaks/trivy for LLM apps": one Go static binary, stdlib-only, that
red-teams an LLM endpoint vs the OWASP LLM Top 10; SARIF/md/text/json, CI gating,
baseline ratchet, BYO-key. Repo `wroughtery/quirn`, branch `main`. Roadmap: make
quirn test the DEPLOYED agent (its own system prompt, tools, RAG), not just the
bare model, judged by a strong independent model. Full plan in `AGENT-MODE-PLAN.md`.

## Status / where we are now
COMMITTED: `de77632` Phase 2 profiles, `928e250` Phase 1 judge endpoint,
`80f7e31` injection payload-splitting (validated). 

UNCOMMITTED (this session - user commits their own work): **Phase 2 agent mode**,
all green + live-validated:
- **`--app-purpose "..."`** flag + config `app_purpose` -> `probe.Config.AppPurpose`
  -> judge. `internal/judge/judge.go` prepends `appPurposeContext` to the rubric
  via the exported `Judge.AppPurpose` field (set in `attackrun.go`). Byte-identical
  when empty (test `TestScoreAppPurpose`).
- **`--agent-mode`** (bool flag + config `agent_mode`) -> `probe.Config.AgentMode`.
  `attack.resolve(agentMode)` in `attackrun.go` suppresses the synthetic `system`
  and swaps in per-attack `agentGoal`/`agentPayload` (added to injection, sensitive,
  leakage, agency; output/misinfo already work user-only). App-relative goals score
  the app's OWN secret / system-prompt / unauthorized action.
- Tests: `internal/probe/agentmode_test.go`, `main_test.go`
  TestRunAgentModeSuppressesSystem, plus judge/config tests. Model mode stays
  byte-identical (all prior probe tests pass).
- Live-validated vs Cerebras (template "app" with its own system prompt + secret,
  judge on a SEPARATE plain endpoint): well-aligned ShopBot (gpt-oss-120b) -> SAFE;
  naive HelpBot (gemma-4-31b) -> VULNERABLE. Detection discriminates both ways.

Earlier Phase 2 part 1 (profiles): `--profile`/`--judge-profile`
(openai|anthropic|gemini|azure|template) via a `Provider` interface
(`internal/llm/provider.go` + `provider_*.go`); generic `template` profile hits any
custom JSON API (payloads always re-escaped). Committed as de77632.

## Next action (start here) - Phase 3, OR polish
Phase 3 (see `AGENT-MODE-PLAN.md` Phase 3): indirect injection via RAG/tools
(bring-your-own-context canary doc -> user seeds it -> query triggers retrieval ->
check compliance); excessive-agency CONFIRMATION (honeytool/sandbox, not just
intent); multi-turn attacks. All need app cooperation - scope carefully, label
proxy vs confirmed. Alternatives: session/cookie passthrough for the template
profile; ready-to-paste template configs (Cohere, bare /api/chat) in the README.

## Known issue (PRE-EXISTING, NOT agent-mode): flaky live test
`internal/live` `TestConcurrentPauseResumeWaitNoDeadlock` (control_test.go:117) is
racy: its final `c.Resume()` cannot guarantee the controller ends un-paused when a
`Pause()` goroutine runs after it, and with `context.Background()` a left-paused
`Wait` blocks forever -> false "deadlocked" under load. The `Controller` itself is
fine for real use (the scan ctx is cancellable). Committed code, untouched here.
Fix = make the test deterministic. It fails independently of the agent-mode work
(`go test $(go list ./... | grep -v internal/live)` is fully green).

## Key files & locations
- `internal/probe/attackrun.go` - `attack` struct (+ `agentGoal`/`agentPayload`),
  `resolve(agentMode)`, `runAttacks` (judge selection, message build). 
- `internal/probe/probe.go` - `Config` (AppPurpose, AgentMode, JudgeClient, ...).
- `internal/probe/{injection,sensitive,leakage,agency,output,misinformation}.go` -
  the 6 probes; first 4 have agent variants.
- `internal/judge/judge.go` - rubric, `appPurposeContext`, `Judge.AppPurpose`.
- `internal/llm/provider.go` + `provider_{anthropic,gemini,azure}.go` - profiles.
- `main.go` - flags, config apply, provider + judge wiring, `templateProfile()`,
  `sameHost()`. `internal/config/config.go` - JSON schema.
- `internal/mockllm/` + `cmd/mockllm` - deterministic mock endpoint / server.

## Decisions & constraints (why)
- stdlib-only, single binary, JSON config. Keep model-mode default; agent-mode
  additive. Judge quality is everything (Cerebras `gpt-oss-120b` = fast free judge;
  keys in `simon.kodu/apps/web/.env.local` as OPENAI_API_KEY / CEREBRAS_API_KEY;
  source via `set -a; . file; set +a` in bash - the classifier allowed it).
- Never leak/log keys; key only from flag/env, never config. Template `{{apiKey}}`
  only into url/headers, never body. In agent mode, use a SEPARATE judge endpoint
  so the judge is a plain call, not wrapped in the app's template.
- Black-box honesty; fail-closed (all-inconclusive -> exit 1).
- User commits their own work - do NOT commit for them.

## Gotchas / environment
- Windows: cannot `go build -o quirn.exe` while a scan holds it; `go build ./...`
  fine. `go run` spawns a temp child - killing the parent leaves it listening
  (find PID via `netstat -ano | grep :PORT`, Stop-Process).
- LM Studio `http://127.0.0.1:1234`: `qwen/qwen3-8b` (slow, times out at short
  --request-timeout; use `google/gemma-3-1b` fast). Concurrency 1 for a single
  local model (memory `local-model-concurrency-trap`).
- Stale `.git/index.lock` appeared this session (interrupted git / VS Code churn):
  `rm -f .git/index.lock` when no git runs.
- Cerebras key here exposes only `gpt-oss-120b` and `gemma-4-31b` (llama-3.3-70b
  404s). LLM nondeterminism - re-validate live.

## Don't
- Don't commit without asking. No third-party deps. No small model judging itself.
  No keys in config files. Don't break the byte-identical model-mode default path.
  Don't ship refreshed goals/signals as validated without a live strong-judge run.
