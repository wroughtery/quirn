# Cerberus  *(placeholder name — final name pending a naming scan)*

Open-source security testing for AI-powered apps. **Ships first as an LLM red-team tool**: point it at your chatbot or LLM endpoint and get an OWASP-LLM-Top-10 report of how it can be prompt-injected, jailbroken, or made to leak its system prompt. Grows from there into source-code and live-app security.

## Positioning

- **Wedge (v0):** LLM red-teaming. Newest market, weakest incumbents, fastest to ship, most viral demo.
- **Later heads:** AI-assisted SAST with automated fix-PRs, then black-box DAST — same brand, once the wedge has users.

The three-capability "platform" is the destination, not the starting point. Win one niche first.

## Distribution & model

- **Open-core, Apache-2.0.** Adoption first; monetize a hosted layer later.
- **BYO-key + local models (Ollama).** Runs on the user's own keys/models — you never subsidize strangers' AI bills, and security teams can keep everything on-prem.
- **Single-binary CLI + GitHub Action.** Drops into any CI. Low time-to-first-value.
- **Wroughtery product.** Own name, own site, own branding — listed as a Wroughtery product alongside KeepWinning, so it spreads on its own name while every adopter still lands on Wroughtery.

## Stack

| Layer | Tech |
|---|---|
| Red-team core (v0) | **Python** — FastAPI (optional), provider SDKs / LangGraph, BYO-key. No server or DB required to run locally |
| Dashboard (v1+) | Next.js + TypeScript + Tailwind + shadcn/ui |
| Security engine (later heads) | **Go** (`chi`, `river`) for concurrent scanning; Docker sandbox |
| Data (v1+) | Postgres; artifacts on S3-compatible storage (R2) |

See [`docs/architecture.md`](docs/architecture.md) for data flow, the phased roadmap, and the schema.

## Safety — non-negotiable

Test only LLM endpoints and targets you **own or are authorized to test**. For the later DAST head, the domain-ownership verification gate is a hard blocker: no active scan fires against an unverified target. For development, use your own apps or intentionally-vulnerable practice targets (OWASP Juice Shop, DVWA, Gruyere). Lead the write-up with these controls — the safety engineering is as much the product as the scanner.

## Status

Pre-v0. Direction locked: **LLM red-team wedge, open-core, BYO-key, Wroughtery sub-brand.** Naming scan in progress. Scaffold next.
