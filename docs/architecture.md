# Cerberus — Architecture & Roadmap

Working notes for the platform. Decisions here are the current plan, not final.

## Language split (and why)

Three services, three languages, each chosen deliberately:

- **Go** — security engine, HTTP API, scan workers. It's the native language of the tools this platform orchestrates (nuclei, subfinder, httpx, naabu, Trivy, gitleaks). Scanning is concurrency fan-out; goroutines fit it exactly. Single static binary → trivial to containerize.
- **Python** — AI agentic layer and the LLM red-team module. Best-supported agent tooling (LangGraph) and provider SDKs.
- **TypeScript / Next.js** — dashboard. Fastest path to a polished, production-looking shell.

## Data flow

### Long scans without blocking the API

Queue + worker.

1. `POST /scans` writes a `scan` row, enqueues a job (River, Postgres-backed), returns `scan_id` immediately.
2. A pool of Go workers pulls jobs and runs each scan inside a sandboxed container.
3. Client watches progress live over SSE/WebSocket. Findings stream in as they're confirmed.

### Sandboxing CLI security tools

One ephemeral throwaway container per scan:

- non-root user, read-only rootfs, dropped Linux capabilities, seccomp profile
- CPU / memory / PID limits, hard timeout
- **network egress allowlisted to the verified target only** — the load-bearing control; it's what stops the box being turned into an attack relay
- results captured via mounted output dir or stdout; container destroyed after

Stronger isolation if needed: gVisor or Firecracker microVMs instead of shared-kernel Docker.

### GitHub webhook loop (Feature 2)

GitHub App subscribes to `push`, `pull_request`, `issue_comment`, `installation`.

Every webhook:
1. **Verify the HMAC signature** (never trust a raw payload — forged events must not drive the bot).
2. Dedupe by delivery-id (GitHub redelivers; handling must be idempotent).
3. Persist the event, enqueue a job.

`@sec-bot` comment loop: on `issue_comment`, load per-PR agent state (`pr_agent_session`, keyed by `installation_id + pr_number`) — the running instruction thread plus current patch — hand the LLM the diff + comment, generate a new patch, push a commit to the branch, reply.

## Phased roadmap

The full triad is a funded team's roadmap, not a solo build. Ship one narrow slice end-to-end, then extend.

- **Phase 1 — MVP (Go-first):** target CRUD + domain-ownership verification gate (DNS TXT / meta tag) → Go scanner fanning out concurrent recon (subfinder / httpx / naabu / nuclei) in a sandboxed container → normalized findings in Postgres → thin Next.js dashboard to launch a scan and watch findings stream. No AI yet.
- **Phase 2 — AI layer (Python):** LangGraph service triages/dedupes findings, cuts false positives, writes exec + technical reports. **Or** ship Feature 3 (LLM red-team) as a self-contained module — pull forward if the trendiest demo is wanted first.
- **Phase 3 — V1 (Feature 2):** GitHub App, webhook pipeline, SAST (wrap semgrep), LLM patch-gen, automated security PRs, the `@sec-bot` feedback loop. Heaviest integration — do it last.

## Core data model (Postgres)

- **user** — id, email, auth_provider_id, created_at
- **organization** — id, name, owner_user_id
- **target** — id, org_id, hostname, status(`unverified`/`verified`/`revoked`), created_at
- **verification** — id, target_id, method(`dns_txt`/`meta_tag`/`file`), token, verified_at
- **scan** — id, target_id, type(`recon`/`active`/`sast`/`llm_redteam`), status(`queued`/`running`/`done`/`failed`), started_at, finished_at, initiated_by
- **finding** — id, scan_id, category, severity(`info`→`critical`), title, evidence(jsonb), status(`open`/`confirmed`/`false_positive`/`fixed`), location
- **report** — id, scan_id, kind(`executive`/`technical`), storage_url, generated_at
- **repository** — id, org_id, github_installation_id, full_name, default_branch
- **pull_request** — id, repository_id, finding_id, github_pr_number, branch, state
- **pr_agent_session** — id, pull_request_id, instruction_thread(jsonb), current_patch, updated_at
- **redteam_run** — id, scan_id, target_endpoint, attack_class, succeeded(bool), transcript(jsonb)

`evidence` / `transcript` as jsonb → flexible finding shapes across scan types without a migration per vuln class.

## Safety guardrails

1. Verification gate is un-bypassable. No active scan against an unverified target, ever. Build it first.
2. Dev/demo only against owned or intentionally-vulnerable targets (Juice Shop, DVWA, Gruyere) or self-deployed apps.
3. Lead the write-up with the controls — "built the authorization gate and egress-locked sandbox before the scanner." The safety engineering is as much the portfolio as the scanner.
