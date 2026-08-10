# Cerberus  *(placeholder name — pick from the shortlist; Jailscope leading)*

**"gitleaks / trivy for LLM apps."** An open-source security linter for AI features: one line in CI runs an OWASP-LLM-Top-10 red-team against your chatbot or LLM endpoint and posts findings to the GitHub Security tab + the PR — zero config, zero Python, BYO-key. Grows from there into source-code and live-app security.

## The gap it fills

Every existing tool is either a **Python/Node package** (garak, promptfoo, PyRIT, Giskard, DeepTeam — need an interpreter, an env, and config authoring) or a **runtime guardrail** (LLM Guard, Rebuff, LlamaFirewall — post-ship defense, not pre-ship testing). Nobody ships a **dependency-free single binary** that a non-security developer drops into CI and gets OWASP coverage with no setup. That developer currently runs nothing. That's the wedge.

## v0 — what ships first

- **Single static binary (Go).** `curl | sh` or a pinned GitHub Action. No pip, no npm, runs on any runner in seconds.
- **Zero-config first run.** OWASP LLM Top 10 is the default policy; YAML is optional, not required on day one.
- **BYO-key / local-model-first.** Target and judge run against any OpenAI-compatible or local (Ollama/llama.cpp) model. No vendor cloud, no telemetry — usable on regulated/private codebases.
- **Native SARIF + PR gating.** Findings appear in the GitHub Security tab and as inline PR annotations; `--fail-on high` gates the build on a severity budget.
- **Baseline / ratchet.** A `.baseline` file so PRs surface only *new* vulnerabilities — adopt at `--fail-on critical`, tighten over time. Stops teams disabling the gate.
- **Probe classes:** prompt injection, jailbreak, system-prompt leakage, sensitive-data disclosure, insecure output handling, and **agent tool-abuse / excessive agency** (the fastest-growing risk, weakly covered by incumbents).

## Positioning & roadmap

- **Wedge (v0):** the CLI + GitHub Action above. Runs locally, no server, no DB.
- **v1:** hosted dashboard (Next.js) — saved runs, trend-over-time, team sharing.
- **v2:** second head — AI-assisted SAST with fix-PRs, or black-box DAST. Pick by traction.
- **v3:** unify into the full platform.

## Distribution & model

- **Open-core, Apache-2.0.** Adoption first; monetize a hosted layer later.
- **CI-native.** A Marketplace Action (`uses: <name>/action@v1`) that works with zero inputs and comments a scorecard — the path that drove trivy/gitleaks/semgrep.
- **Wroughtery product.** Own name, own site, own branding — listed as a Wroughtery product alongside KeepWinning, so it spreads on its own name while every adopter still lands on Wroughtery.

## Stack

| Layer | Tech |
|---|---|
| Red-team core (v0) | **Go** — single static binary; `cobra` CLI, stdlib `net/http`, goroutines for concurrent probes; SARIF output. No runtime dependency |
| Dashboard (v1+) | Next.js + TypeScript + Tailwind + shadcn/ui |
| Security engine (later DAST head) | Go (`chi`, `river`) + Docker sandbox |
| Data (v1+) | Postgres; artifacts on S3-compatible storage (R2) |

See [`docs/architecture.md`](docs/architecture.md).

## Safety — non-negotiable

Test only LLM endpoints and targets you **own or are authorized to test**. For the later DAST head, the domain-ownership verification gate is a hard blocker: no active scan against an unverified target. Lead the write-up with these controls — the safety engineering is as much the product as the scanner.

## Status

Pre-v0. Direction locked: **LLM red-team wedge, Go single-binary core, open-core, BYO-key, Wroughtery sub-brand.** Name selection + `wroughtery` org next, then scaffold.
