# Cerberus

> **Placeholder name.** Three-headed guardian — three heads for the three capabilities below. Rename before anything public; the name is thematically fitting but clashes with existing security tools.

An AI-powered DevSecOps platform. One place to identify, prove, and automatically fix vulnerabilities across a live app, its source code, and its AI features.

## The three heads

1. **Offensive** — autonomous black-box pentesting against a **verified** target. Recon, attack-surface mapping, safe validation of findings.
2. **Remediation** — white-box SAST on connected repos, with an AI agent that opens security fix PRs and takes review comments (`@sec-bot ...`).
3. **AI red team** — adversarial testing of deployed LLM apps for prompt injection, jailbreaks, and system-prompt leakage (OWASP LLM Top 10).

## Stack

| Layer | Tech | Why |
|---|---|---|
| Dashboard | Next.js + TypeScript + Tailwind + shadcn/ui | Fastest path to a production-grade shell |
| Security engine + API + workers | **Go** (`chi`, `river`) | Native language of the tools it orchestrates; concurrency fits scanning |
| AI agentic layer + LLM red team | **Python** (FastAPI, LangGraph) | Best-supported agent ecosystem |
| Sandboxing | Docker / containerd, ephemeral egress-locked containers | Safe execution of CLI security tools |
| Data | Postgres | — |
| Queue | River (Postgres-backed) | Long scans off the request path, zero extra infra |
| Artifacts | S3-compatible (R2) | Report/log storage |

See [`docs/architecture.md`](docs/architecture.md) for data flow, the phased roadmap, and the schema.

## Safety — non-negotiable

Active scanning and LLM attacks run **only** against targets you own or have written authorization for. The domain-ownership verification gate is a hard blocker, not a UX step: no active scan fires against an unverified target. For development, use intentionally-vulnerable practice apps (OWASP Juice Shop, DVWA, Google Gruyere) or targets you deploy yourself.

## Status

Pre-Phase-1. Scaffold not yet built. Roadmap in `docs/architecture.md`.
