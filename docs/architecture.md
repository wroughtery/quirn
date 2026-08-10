# Cerberus — Architecture & Roadmap

Working notes. Decisions here are the current plan, not final. Name is a placeholder pending selection (Jailscope leading).

## Positioning & wedge

**"gitleaks / trivy for LLM apps."** A pre-ship, CI-native security gate for the app developer shipping an LLM feature who is not a security engineer and today runs nothing.

The market splits two ways and leaves a hole in the middle:

- **Heavyweight red-team frameworks** (garak, promptfoo, PyRIT, Giskard, DeepTeam) — powerful, but Python/Node packages that need an interpreter, an environment, and config authoring. Built for security researchers.
- **Runtime guardrails** (LLM Guard, Rebuff, LlamaFirewall) — post-ship *defense*, not pre-ship *testing*. They don't tell you where your app breaks before you ship.

Nobody ships a dependency-free binary that a developer curls into CI and gets zero-config OWASP coverage with SARIF/PR-native output. That's the wedge.

### Differentiators (why a newcomer gets adopted)

1. **Single static binary** — no Python/Node interpreter, no dependency tree. Beats the pip/npm friction of every incumbent.
2. **Zero-config first run** — OWASP LLM Top 10 preset by default; YAML optional.
3. **BYO-key / local-model-first** — target + judge on any OpenAI-compatible or local model; no vendor cloud, no telemetry.
4. **Native GitHub code-scanning** — emits SARIF into the Security tab + inline PR annotations + a Markdown scorecard, gated by `--fail-on <severity>`. No incumbent ships this as the default.
5. **Agent/tool-abuse as a first-class probe class** — indirect injection via tool outputs, excessive agency, tool-orchestration abuse. Fastest-growing risk; only DeepTeam covers it well, not as a binary.
6. **Deterministic, diffable findings + `.baseline`** — PRs show only *new* vulns; teams ratchet severity over time. Turns red-teaming into a regression gate devs trust.
7. **OWASP LLM01–LLM10 taxonomy on every finding** — instant compliance/reporting language.

## Language split (and why Go for v0)

- **Go — the v0 red-team core.** The sharpest differentiator is *"one static binary, no pip/npm."* A Python core would compete on the same friction axis it's trying to beat, so the core must compile to a single binary → Go (Rust is the alternative; Go ships faster). Bonus: Go is the deliberate gap-language to learn, so the market reason and the learning reason align. A red-team CLI is well within Go's wheelhouse — HTTP probes, JSON, a judge LLM call (also HTTP), SARIF output, goroutines for concurrent probe execution. No ML libraries required; the "AI" is prompt templates + API calls.
- **TypeScript / Next.js — the dashboard.** Fastest path to a polished shell. Enters at v1.
- **Go again — the later DAST head.** Native language of the tools it would orchestrate (nuclei, httpx, subfinder).

## v0 architecture — LLM red-team CLI (small on purpose)

A single Go binary (and importable package) that:

1. **Targets** an OpenAI-compatible endpoint/API or a local model (Ollama/llama.cpp), with the user's key. Optionally auto-detects the app's system prompt / tool schemas.
2. **Runs probes** mapped to OWASP LLM Top 10 + agent tool-abuse, fanned out concurrently across goroutines. Probe packs are versioned data (`<tool> update`), refreshed like a vuln DB.
3. **Judges** each probe outcome with a BYO-key judge model (attack succeeded / blocked), producing deterministic, stably-IDed findings.
4. **Reports** to: terminal summary, machine-readable **SARIF** (Security tab + PR annotations), and a shareable HTML/Markdown scorecard with OWASP tags. Honors a `.baseline` and a `--fail-on <severity>` gate.

A **GitHub Action** wraps the binary: zero-input default, comments a scorecard, fails the build on the severity budget. **No server, no database, no sandbox for v0** — it runs locally against the user's endpoint. Hosted dashboard + stored history come at v1.

## Data flow — later heads (for reference)

### Long scans without blocking the API (DAST head)

Queue + worker. `POST /scans` writes a row, enqueues a job (River, Postgres-backed), returns `scan_id` immediately; Go workers run each scan in a sandboxed container; client watches over SSE/WebSocket.

### Sandboxing CLI security tools (DAST head)

Ephemeral throwaway container per scan: non-root, read-only rootfs, dropped capabilities, seccomp, resource limits, hard timeout, and **egress allowlisted to the verified target only** — the load-bearing control. gVisor/Firecracker for stronger isolation.

### GitHub webhook loop (SAST head)

Subscribe to `push`, `pull_request`, `issue_comment`, `installation`. Every webhook: verify HMAC signature, dedupe by delivery-id, persist, enqueue. `@sec-bot` loop: on `issue_comment`, load per-PR agent state (`pr_agent_session`), regenerate the patch, push a commit, reply.

## Phased roadmap

- **v0 — the wedge:** Go red-team CLI + GitHub Action. Zero-config, BYO-key/local, OWASP-LLM-Top-10 + tool-abuse probes, SARIF + `.baseline` + severity gate. Runs locally, no infra. The whole first release.
- **v1 — hosted dashboard:** Next.js over saved runs — history, trend-over-time, team sharing. Postgres enters here.
- **v2 — second head:** AI-assisted SAST with fix-PRs (GitHub App) **or** black-box DAST (Go engine + sandbox). Pick by traction.
- **v3 — unify:** the full platform.

## Core data model (Postgres — v1+)

v0 needs no DB (local SARIF/JSON output). From v1:

- **user** — id, email, auth_provider_id, created_at
- **organization** — id, name, owner_user_id
- **redteam_run** — id, org_id, target_endpoint, model, status, started_at, finished_at *(v1 hero entity)*
- **redteam_finding** — id, run_id, owasp_id (LLM01–LLM10), severity, succeeded(bool), transcript(jsonb), status, stable_finding_id
- **report** — id, run_id, kind(`executive`/`technical`/`sarif`), storage_url, generated_at

Later heads add: **target**, **verification**, **scan**, **finding**, **repository**, **pull_request**, **pr_agent_session**. `transcript`/`evidence` as jsonb → flexible shapes without a migration per attack/vuln class.

## Safety guardrails

1. Test only endpoints/targets you own or are authorized to test. For the DAST head, the verification gate is un-bypassable — build it first.
2. Dev/demo only against owned or intentionally-vulnerable targets (Juice Shop, DVWA, Gruyere).
3. Lead the write-up with the controls. The safety engineering is as much the portfolio as the tool.
