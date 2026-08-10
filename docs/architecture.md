# Cerberus — Architecture & Roadmap

Working notes. Decisions here are the current plan, not final. Name is a placeholder pending a naming scan.

## Positioning & wedge

Adoption is won by being unmistakably best at **one** painful thing, then expanding. The wedge is **LLM red-teaming**: newest market, weakest incumbents (garak, promptfoo, PyRIT are young), plays to the strongest demonstrated skill (multi-provider LLM work), most viral demo, smallest build. The broader three-capability platform is the destination, reached only after the wedge has users.

## Language split (and why)

- **Python — the v0 red-team core.** Best LLM/agent tooling and provider SDKs. Ships first.
- **Go — the later scanning heads (DAST).** Native language of the tools it would orchestrate (nuclei, httpx, subfinder); goroutines fit concurrent scanning; single static binary. Enters when the DAST head is built, not before.
- **TypeScript / Next.js — the dashboard.** Fastest path to a polished shell. Enters at v1.

## v0 architecture — LLM red-team (small on purpose)

A CLI (and importable library) that:

1. Takes a target LLM (OpenAI-compatible endpoint/API, or a local Ollama model) plus the user's key.
2. Runs a suite of adversarial probes mapped to the **OWASP LLM Top 10** — prompt injection, jailbreak, system-prompt leakage, sensitive-data disclosure, insecure output handling, excessive agency / tool abuse.
3. Scores results with an attacker/judge model (also BYO-key).
4. Emits a report: terminal summary + machine-readable JSON + shareable HTML/Markdown.

A **GitHub Action** wraps the CLI so it runs in CI, fails the build or comments on the PR when new vulnerabilities appear. **No server, no database, no sandbox needed for v0** — it runs locally against the user's endpoint. Hosted dashboard and stored history come at v1.

## Data flow — later scanning heads

### Long scans without blocking the API

Queue + worker. `POST /scans` writes a `scan` row, enqueues a job (River, Postgres-backed), returns `scan_id` immediately. A pool of Go workers runs each scan in a sandboxed container. Client watches progress over SSE/WebSocket.

### Sandboxing CLI security tools

One ephemeral throwaway container per scan: non-root, read-only rootfs, dropped capabilities, seccomp, CPU/mem/PID limits, hard timeout, and **network egress allowlisted to the verified target only** — the load-bearing control that stops the box being turned into an attack relay. Stronger isolation via gVisor / Firecracker if needed.

### GitHub webhook loop (SAST head)

App subscribes to `push`, `pull_request`, `issue_comment`, `installation`. Every webhook: verify the HMAC signature (never trust a raw payload), dedupe by delivery-id (GitHub redelivers), persist, enqueue. `@sec-bot` loop: on `issue_comment`, load per-PR agent state (`pr_agent_session`, keyed by `installation_id + pr_number`), hand the LLM the diff + comment, generate a new patch, push a commit, reply.

## Distribution & business model

- **Open-core, Apache-2.0.** Zero license friction early; add a source-available/AGPL layer on hosted-only features once there are users worth protecting.
- **BYO-key + local-model-first.** No subsidizing strangers' AI; unlocks on-prem/security-conscious users.
- **CI-native.** Single binary + GitHub Action = how security tools actually spread.
- **Wroughtery sub-brand.** Own hero name and site; listed as a Wroughtery product (like KeepWinning). The tool name is the star; "by Wroughtery" is the attribution and the funnel.

## Phased roadmap

- **v0 — the wedge:** LLM red-team CLI + GitHub Action. BYO-key/local, OWASP-LLM-Top-10 probe suite, report output (terminal/JSON/HTML). Runs locally, no infra. This is the whole first release.
- **v1 — hosted dashboard:** Next.js UI over saved runs — history, trend-over-time, team sharing, optional managed runs. Postgres enters here.
- **v2 — second head:** AI-assisted SAST with automated fix-PRs (GitHub App) **or** black-box DAST (Go engine + sandbox). Pick by traction.
- **v3 — unify:** the full platform vision, once each head has earned its place.

## Core data model (Postgres — v1+)

v0 needs no DB (local JSON output). From v1:

- **user** — id, email, auth_provider_id, created_at
- **organization** — id, name, owner_user_id
- **redteam_run** — id, org_id, target_endpoint, model, status, started_at, finished_at *(the v1 hero entity)*
- **redteam_finding** — id, run_id, attack_class (OWASP LLM id), severity, succeeded(bool), transcript(jsonb), status
- **report** — id, run_id, kind(`executive`/`technical`), storage_url, generated_at

Later heads add: **target**, **verification**, **scan**, **finding**, **repository**, **pull_request**, **pr_agent_session**. `transcript`/`evidence` as jsonb → flexible shapes without a migration per attack/vuln class.

## Safety guardrails

1. Test only endpoints/targets you own or are authorized to test. For the DAST head, the verification gate is un-bypassable — build it first.
2. Dev/demo only against owned or intentionally-vulnerable targets (Juice Shop, DVWA, Gruyere).
3. Lead the write-up with the controls. The safety engineering is as much the portfolio as the tool.
