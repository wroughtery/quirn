# quirn — Agent-mode roadmap (Phases 1–3)

**Why:** Today quirn tests the *bare model*. It sends `[system: <quirn's synthetic
scenario>, user: <payload>]` to the `--model` on the target endpoint
(`attackrun.go:63-75`), and the judge reuses the *same* client — same URL + key,
different model name only (`main.go:285`, `attackrun.go:43`). That answers "is this
model injection-prone?" It does **not** test the *deployed agent* — the app on the
website with its own system prompt, tools, RAG, and guardrails — which is what OWASP
LLM Top 10 is actually about, and what a buyer cares about.

**Goal of this roadmap:** keep model-mode (a useful portable benchmark) and add
**agent-mode** as a first-class target, judged by a strong independent model.

This plan is intentionally *general*. Each phase gets a detailed design doc when we
start it (see "Detail on start").

---

## Phase 1 — Separate judge endpoint + key  *(SHIPPED 2026-08-21)*

**Status: done.** `--judge-target` / `--judge-api-key` + `QUIRN_JUDGE_API_KEY` +
config `judge_target` land the judge on its own endpoint/key; the judge client is
threaded via `probe.Config.JudgeClient` (nil ⇒ reuse target, byte-identical).
Two deviations from the draft below, both deliberate: (1) **no `judge_api_key`
config field** — like the target `api_key` the judge key lives only in flag/env,
so a committed config never carries a secret; (2) the target-key fallback is
reused **only when the judge is on the same host** as the target, else quirn
sends no key and warns — a real target credential never crosses to another host.
Unit-tested (routing + key isolation, same-/cross-host) and live-validated (real
gemma-3-1b target judged via a separate local endpoint).

**Goal.** Let the judge live on a different endpoint/key than the target, so you can
test a cheap/local target but judge with a capable API (GPT-4o / Claude). Bonus: a
judge on a separate endpoint stops competing with a single local target, softening
the concurrency-1 trap.

**In scope.** `--judge-target`, `--judge-api-key` flags; `QUIRN_JUDGE_API_KEY` env;
`judge_target` / `judge_api_key` config fields; `probe.Config.JudgeTarget/JudgeAPIKey`;
build a 2nd `llm.Client` for the judge when set, else reuse the target client;
help/README.

**Out of scope.** No change to probes, attacks, or targeting.

**Key decisions (locked).**
- Backward compatible: judge flags absent ⇒ byte-identical behavior (diff-verify reports).
- If `--judge-target` set but no judge key ⇒ resolve key precedence (flag > env >
  reuse target key). *Detail on start.*

**Rough tasks.** Config fields → main.go wiring (build judgeClient) → thread judge
client into `runAttacks`/`judge.New` (instead of the shared target client) → config
JSON fields → tests (two httptest servers: judge routed to the 2nd; fallback when
unset) → docs.

**Done when.** A scan hits a local target while judging via a second endpoint
(verified with two mock servers); reports unchanged when flags absent;
`go build/vet/test ./...` green; live re-validated against a real 2nd endpoint.

**Risk.** Low. Main care: never log keys.

---

## Phase 2 — Agent target adapter  *(SHIPPED 2026-08-21)*

**Status: done.** (1) **Profiles** — `--profile`/`--judge-profile`
(openai|anthropic|gemini|azure|template) via a `Provider` interface; the generic
`template` profile hits any custom JSON API (config-driven, payloads always
re-escaped). (2) **Agent mode** — `--agent-mode` suppresses quirn's synthetic
system prompt (tests the app's own prompt/guardrails/tools) and switches the
canary-dependent probes (LLM02/LLM07/LLM06) to app-relative goals (leak the app's
OWN secret/system-prompt, take its OWN unauthorized action). (3) **`--app-purpose`**
feeds the judge the app's intended purpose so it scores a real break vs on-task
behavior. Model mode stays byte-identical. Unit-tested + live-validated both ways
(a well-aligned app → SAFE, a naive app → VULNERABLE, judged on a separate plain
endpoint). Not yet: optional session/cookie passthrough (deferred; add if needed).

**Goal.** Point quirn at a deployed agent's HTTP API (not just OpenAI-compatible
model endpoints), sending only the *user turn* — the app supplies its own system
prompt, tools, and RAG. Judge the app's actual response against its intended purpose.

**In scope.**
- **Target profile abstraction** — an interface: payload → HTTP request, response →
  reply text.
  - `openai` profile = current behavior (default).
  - `http-template` profile = config-driven: method, URL, headers (auth), JSON body
    template with `{{payload}}` (and optional `{{conversation}}`), response extractor
    (dot-path / small JSONPath-lite, stdlib only).
- **Agent mode** — suppress quirn's synthetic system prompt; send user-only.
- **App-context input** — `--app-purpose "…"` (or config) handed to the judge so it
  can tell a real policy break from normal on-task behavior.
- **Probe success-signal variants** — attacks that relied on planted canaries (LLM02
  secret, LLM07 system-prompt canary) get app-relative signals (leak of the *app's
  own* system prompt / any secret-shaped output). payload-splitting / smuggled-tool-
  output / spoofed-policy-update already work as pure user turns.
- Optional session handling (conversation id / cookie passthrough).

**Out of scope.** RAG/tool poisoning and real tool-call confirmation (Phase 3);
auto-discovery of the app's API shape.

**Key decisions (high-level; detail on start).**
- Stay **stdlib-only** and **black-box**: http-template is JSON config, no new deps.
- Split each probe's attacks into "works user-only" vs "needs planted context";
  agent-mode runs the user-only set + app-relative variants.
- In agent mode the judge gets `app-purpose` and **no** planted-canary knowledge.

**Rough tasks.** Target interface + 2 profiles → message-building change (no system
in agent mode) → Config additions (mode, profile config, app-purpose) → probe
success-signal variants → tests (mock "web agent" server with its own system prompt)
→ docs + a worked example (e.g. test a Next.js `/api/chat`).

**Done when.** quirn points at a mock web agent (own system prompt) and detects a
real override; model-mode stays unchanged; live-validated against a real agent
endpoint.

**Risk.** Medium–large. Probe semantics grow; judge quality matters even more; auth/
session variety.

---

## Phase 3 — Agent-only attack surface  *(frontier; roadmap)*

**Goal.** The vulnerabilities that only exist in the deployed agent.

**In scope (to be detailed much later).**
- **Indirect injection via RAG/tools** — "bring-your-own-context" flow: quirn emits a
  canary document the user seeds into the agent's knowledge base/tool, then queries
  the agent to trigger retrieval and checks for compliance. This is the real-world
  LLM01/LLM05.
- **Excessive agency (LLM06)** — detect tool-call *intent* in responses (partly
  possible today), and — with app cooperation / a sandbox "honeytool" — confirm the
  agent actually invoked a dangerous action.
- **Multi-turn attacks** — conversation-state injections that span turns.

**Out of scope.** Fully automated RAG poisoning (inherently app-specific).

**Key decisions.** Mostly deferred. Keep black-box honesty: label clearly what is a
*proxy* signal vs a *confirmed* action.

**Risk.** High; needs app cooperation; requires scope discipline (don't overpromise).

---

## Cross-cutting (all phases)
- **stdlib-only**, no third-party deps — the single-binary wedge.
- Keep **model-mode** as default; agent-mode is additive.
- **Judge quality is everything** — never let a small model judge itself; Phase 1
  makes a strong external judge easy.
- Reports must state **which mode/layer** a scan covered (model vs agent).
- Every refreshed payload / new signal is **live-validated** before it's trusted.

## Detail on start
When we begin a phase, expand its section into a full design doc (interfaces, flag
grammar, config schema, test matrix, acceptance script) before writing code.
