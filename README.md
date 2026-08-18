# Quirn

**"gitleaks / trivy for LLM apps."** An open-source security linter for AI features: one line in CI runs an OWASP-LLM-Top-10 red-team against your chatbot or LLM endpoint and posts findings to the GitHub Security tab + the PR — zero config, zero Python, BYO-key. Grows from there into source-code and live-app security.

## The gap it fills

Every existing tool is either a **Python/Node package** (garak, promptfoo, PyRIT, Giskard, DeepTeam — need an interpreter, an env, and config authoring) or a **runtime guardrail** (LLM Guard, Rebuff, LlamaFirewall — post-ship defense, not pre-ship testing). Nobody ships a **dependency-free single binary** that a non-security developer drops into CI and gets OWASP coverage with no setup. That developer currently runs nothing. That's the wedge.

## v0 — what ships first

- **Single static binary (Go).** `curl | sh` or a pinned GitHub Action. No pip, no npm, runs on any runner in seconds.
- **Zero-config first run.** OWASP LLM Top 10 is the default policy; YAML is optional, not required on day one.
- **BYO-key / local-model-first.** Target and judge run against any OpenAI-compatible or local (Ollama/llama.cpp) model. No vendor cloud, no telemetry — usable on regulated/private codebases.
- **Native SARIF + PR gating.** Findings appear in the GitHub Security tab and as inline PR annotations; `--fail-on high` gates the build on a severity budget.
- **Baseline / ratchet.** A baseline file so PRs surface only *new* vulnerabilities — snapshot with `--write-baseline`, then adopt at `--fail-on critical` and tighten over time. Stops teams disabling the gate.
- **Probe classes (shipped):** prompt injection / jailbreak (LLM01), sensitive information disclosure (LLM02), improper output handling (LLM05), **excessive agency / tool-abuse** (LLM06, the fastest-growing risk, weakly covered by incumbents), system-prompt leakage (LLM07), and misinformation (LLM09). Each finding is judged by a BYO-key model and tagged with its OWASP LLM Top 10 class. Scope a run with `--only`/`--skip` (by probe id or OWASP class); list what's available with `quirn scan --list-probes`.

## Usage

Build and run locally:

```sh
go build -o quirn .
export QUIRN_API_KEY=sk-...
./quirn scan --target https://api.openai.com --model gpt-4o-mini --fail-on high --format sarif --out quirn.sarif
```

`quirn scan --target <url>` is the only required flag; see `quirn help` for the full flag list (`--model`, `--judge-model`, `--fail-on`, `--fail-on-inconclusive`, `--format`, `--concurrency`, `--timeout`, `--max-retries`, `--only`, `--skip`, `--list-probes`, `--baseline`, `--write-baseline`, `--out`). Transient model errors (HTTP 429/5xx or network blips) are retried with backoff (`--max-retries`, default 2, honoring `Retry-After`) so a rate limit doesn't become a false inconclusive. `--format` accepts `text` (default), `json`, `sarif`, or `markdown` (a PR-comment scorecard). The `json` report is a deterministic envelope — `{tool, version, target, summary{probes,vulnerable,baselined,inconclusive,ok}, findings[]}`, no timestamp — so identical scans diff cleanly and downstream tooling gets pre-computed counts. `quirn version` prints the build version.

**Exit codes:** `0` clean, `1` a finding at or above `--fail-on` (or the scan reached no verdict), `2` a usage error. Crucially the gate is **fail-closed**: if every probe is inconclusive — a wrong key, an unreachable target, a blown `--timeout` — quirn exits non-zero instead of reporting a false green, so a misconfigured CI run can't masquerade as a pass. Add `--fail-on-inconclusive` to also fail when *any* probe couldn't be scored.

### Baseline (ratchet)

Adopt on a noisy codebase without disabling the gate: snapshot today's findings once, then only *new* vulnerabilities break the build.

```sh
# 1. Accept the current findings (writes the file, exits 0)
./quirn scan --target <url> --baseline .quirn-baseline.json --write-baseline

# 2. From now on, gate only on regressions — baselined findings are suppressed
./quirn scan --target <url> --baseline .quirn-baseline.json --fail-on high
```

Baselined findings are excluded from both the severity gate and the SARIF output, so the Security tab and the PR show only what's new. Commit `.quirn-baseline.json` and tighten `--fail-on` over time.

### GitHub Action

No tagged release exists yet, so the action ([`action.yml`](action.yml)) builds the binary from source on every run. Add it to a workflow:

```yaml
- uses: wroughtery/quirn@main
  with:
    target: ${{ secrets.QUIRN_TARGET_URL }}
    api-key: ${{ secrets.QUIRN_API_KEY }}
    fail-on: high
    format: sarif
    output: quirn.sarif
```

See [`.github/workflows/quirn-example.yml`](.github/workflows/quirn-example.yml) for a full example that uploads the SARIF report to the GitHub Security tab.

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

Building v0. Locked: **name Quirn, LLM red-team wedge, Go single-binary core, open-core, BYO-key, Wroughtery sub-brand.** Repo lives at `wroughtery/quirn`.

Working today: `scan` against any OpenAI-compatible endpoint; six OWASP probe classes (LLM01/02/05/06/07/09) with an LLM judge; probe selection (`--only`/`--skip`/`--list-probes`); `text`/`json`/`sarif`/`markdown` reports; baseline ratchet (`--baseline` / `--write-baseline`); `--fail-on` severity gate (fail-closed on an unreachable target); concurrent probe execution; and a GitHub Action. Test suite covers the CLI, judge, probes, selection, reports, baseline, and client. Not yet: remaining OWASP classes, YAML policy config, `curl | sh` release artifacts, and the v1 hosted dashboard.
