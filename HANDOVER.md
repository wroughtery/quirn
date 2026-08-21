# Handover — Quirn agent-mode roadmap: Phase 2 remainder next (2026-08-21)

## Goal
**Quirn** — "gitleaks/trivy for LLM apps": one Go static binary, stdlib-only, that
red-teams an LLM endpoint vs the OWASP LLM Top 10; SARIF/md/text/json, CI gating,
baseline ratchet, BYO-key. Repo `wroughtery/quirn`, branch `main`. Roadmap driver:
make quirn test the **deployed agent** (its own system prompt, tools, RAG), not
just the bare model, judged by a strong independent model. Full plan in
`AGENT-MODE-PLAN.md` (3 phases, user agreed to all).

## Status / where we are now (all COMMITTED, tree clean)
- `928e250` **Phase 1 — separate judge endpoint + key.** `--judge-target` /
  `--judge-api-key` / `QUIRN_JUDGE_API_KEY` / config `judge_target`. Judge threaded
  via `probe.Config.JudgeClient` (nil ⇒ reuse target ⇒ byte-identical). Judge key:
  flag > env > target key, and the target key is reused ONLY same-host (no
  cross-host leak). judge_api_key deliberately NOT a config field.
- `80f7e31` **injection.go payload-splitting goal** — the fumble-tolerant LLM01
  success signal. It FAILED the old qwen3-8b judge but is now **validated**: the
  live judge test (`internal/probe/judgelive_test.go`, env-gated, skips without
  env) passes 5/5 on BOTH OpenAI gpt-5-mini AND Cerebras gpt-oss-120b (garbled
  "PWNECD" / spaced "PW NE D" → VULNERABLE; non-assembly / refusal → SAFE). Root
  cause of the old failure was judge weakness, not the goal.
- `de77632` **Phase 2 PART 1 — pluggable API profiles.** `--profile` /
  `--judge-profile` (openai default | anthropic | gemini | azure | template) +
  config `profile`/`judge_profile`/`template`/`judge_template`/`azure_api_version`.
  `internal/llm/provider.go` defines the `Provider` interface; client refactored to
  delegate request/response SHAPE while keeping transport (retries/timeout/cap).
  Named adapters self-register via init(). Generic `template` profile =
  config-driven any-JSON-API (placeholders {{payload}}/{{system}}/{{model}} in
  body; {{apiKey}}/{{model}}/{{baseURL}} in url/headers; `reply_path` dot-path).
  Payloads always re-escaped on marshal (can't break out / inject placeholders).
  Adversarially reviewed (verdict SHIP); all findings fixed + tested. Live-validated
  end-to-end: template profile → real Cerebras, 3 attacks judged, 0 inconclusive.

## Next action (start here) — Phase 2 PART 2: agent mode (the "real fix")
The profile abstraction was only the FIRST bullet of Phase 2. Progress + remaining
(see `AGENT-MODE-PLAN.md` §Phase 2):

**DONE (this session, UNCOMMITTED — user commits their own work):**
- Step 1 ✅ **`--app-purpose "…"`** flag + config `app_purpose` →
  `probe.Config.AppPurpose` → judge. `internal/judge/judge.go` prepends an
  agent-mode context block (`appPurposeContext`) to the rubric via the exported
  `Judge.AppPurpose` field (set in `attackrun.go`). Byte-identical when empty
  (test `TestScoreAppPurpose`). Full suite green.

**REMAINING (implement next, in order):**
2. **Agent mode: suppress quirn's synthetic system prompt.** A `--agent-mode` flag
   (or implied) that makes probes send USER-ONLY turns (no injected `system`), so
   quirn tests the deployed app's OWN system prompt/guardrails, not a synthetic
   scenario. Today `attackrun.go:63-75` sends `[system?, user]`; agent mode drops
   the system message. Some attacks (payload-splitting, smuggled-tool-output,
   spoofed-policy-update) already work user-only; the canary-dependent ones
   (LLM02 planted secret, LLM07 system-prompt canary) need app-relative variants.
3. **App-relative success signals** for LLM02/LLM07 in agent mode: leak of the
   *app's own* system prompt / any secret-shaped output, instead of a planted
   canary. Split each probe's attacks into "works user-only" vs "needs planted
   context"; agent mode runs the user-only set + app-relative variants.

Design the probe-semantics decisions first (short), then implement + test (mock
"web agent" server with its OWN system prompt) + live-validate.

## Key files & locations
- `AGENT-MODE-PLAN.md` — the roadmap; Phase 1 marked SHIPPED; Phase 2/3 detail.
- `internal/probe/probe.go` — `Config` (Target, Model, JudgeModel, JudgeClient,
  Observer, Gate). Phase 2 pt2 adds `AppPurpose string` and an agent-mode flag.
- `internal/probe/attackrun.go:63-75` — message build (`[system?, user]`); agent
  mode suppresses the system message here. Judge selection at top of `runAttacks`.
- `internal/probe/injection.go` — LLM01 attacks; pattern for probe attack structs.
- `internal/judge/judge.go` — rubric + `New(client, model)` + `Score(ctx, goal,
  payload, response)`. App-purpose plumbs into the rubric here.
- `internal/llm/provider.go` — `Provider` interface, OpenAIProvider, TemplateConfig
  /templateProvider, NewProvider factory, registry. `provider_{anthropic,gemini,
  azure}.go` — named adapters. `client.go` — transport (retries/cap/timeout).
- `main.go` — flag parsing, config apply (`applyStr`), provider build + wiring,
  `templateProfile()` helper, `sameHost()`.
- `internal/config/config.go` — JSON config schema + validate.
- `internal/mockllm/` — deterministic mock endpoint (judge detected by "security
  judge" in body). `cmd/mockllm` runs it as a server for live dogfooding.

## Decisions & constraints (and why)
- **stdlib-only**, single static binary, JSON config (no YAML) — the wedge.
- **Keep model-mode default**; agent-mode is additive, opt-in.
- **Judge quality is everything** — never let a small model judge itself; Phase 1
  makes a strong external judge one flag away. Cerebras `gpt-oss-120b` is a great
  fast free judge; OpenAI `gpt-5-mini` also good. Keys live in
  `simon.kodu/apps/web/.env.local` as `OPENAI_API_KEY` / `CEREBRAS_API_KEY`.
- **Never leak/log keys.** Key only from flag/env, never config file. Template
  {{apiKey}} substituted only into url/headers, never body.
- **Black-box honesty** — LLM03/04/08/10 excluded; LLM05 hygiene proxy;
  fail-closed (all-inconclusive → exit 1).
- **User commits their own work** — do NOT commit for them; ask/leave uncommitted.

## Gotchas / open problems
- **Windows file lock:** can't `go build -o quirn.exe` while a scan holds it;
  `go build ./...` / `go test ./...` fine. `go run` spawns a temp binary — killing
  the `go run` parent leaves the child listening (find PID via `netstat -ano | grep
  :PORT`, then Stop-Process).
- **Security classifier** sometimes blocks Bash reading keys from files — but it
  ALLOWED `set -a; . .env.local; set +a; VAR=$X go run ...` this session. If it
  blocks, have the user run via `!` (their shell bypasses it).
- **LM Studio** on `http://127.0.0.1:1234`: `qwen/qwen3-8b` (slow "thinking",
  times out at short --request-timeout — use `google/gemma-3-1b` as a fast target).
  Concurrency 1 for a single local model (memory `local-model-concurrency-trap`).
- **Stale `.git/index.lock`** appeared this session (0-byte, from an interrupted
  git process — likely VS Code churn). Fix: `rm -f .git/index.lock` when no git
  process runs. Nothing auto-recreates it.
- **LLM nondeterminism:** re-validate live; don't trust one run.

## Don't
- Don't commit without the user asking. Don't add third-party deps. Don't let a
  small model judge itself. Don't put keys in config files. Don't ship refreshed
  payloads/signals as validated without a live strong-judge run. Don't break the
  byte-identical openai/model-mode default path.
