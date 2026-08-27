# Contributing to Quirn

Thanks for helping. Quirn's whole promise is a **dependency-free single Go
binary a developer drops into CI** — a few invariants protect that, so read the
constraints before a big change.

## Non-negotiable constraints

- **Standard library only.** No third-party Go modules. `go.mod` stays free of
  `require` entries beyond the toolchain. If you think you need a dependency,
  open an issue first — the answer is almost always "write the small piece we
  need in stdlib."
- **One static binary.** No CGO, no runtime assets that aren't `embed`ed.
- **The report contract is stable.** The JSON envelope shape, exit codes
  (`0` clean / `1` findings-or-unreachable / `2` usage), flag names, SARIF
  shape, and Action inputs are a promise to users. Don't break them without a
  major-version bump.
- **Never weaken the safety posture.** Quirn only tests authorized targets; the
  judge stays on a separate capable model; a finding must be the target's own
  behavior, never gamed by the probe.

## Getting set up

```sh
go build -o quirn .            # build
go test ./...                 # full suite (mock LLM, no network)
gofmt -l .                    # must print nothing
go vet ./...                  # must be clean
```

`internal/mockllm` is the same handler CI gates on, so the local loop matches CI.

## Making a change

1. Fork and branch.
2. Add or update tests — behavior changes need coverage.
3. Keep `gofmt`, `go vet`, and `go test ./...` green.
4. **Conventional Commits** for messages (`feat:`, `fix:`, `docs:`, `chore:`,
   `refactor:`, `test:`). Subject ≤ 50 chars, imperative. Body only when the
   "why" isn't obvious from the diff.
5. Open a PR against `main`. CI runs `test`/`gofmt`/`vet` on every PR and must
   pass before merge.

Maintainers push small changes straight to `main`; external contributions come
in as PRs from forks. Either way, `main` must stay green and releasable.

## Adding a probe

Probes live in `internal/probe`. A probe is judged by a capable independent
model and tagged with its OWASP LLM Top 10 class. Prefer **fewer, high-signal**
findings over broad coverage — a false positive costs a user's trust, which is
the product. See an existing probe (`internal/probe/*.go`) for the shape.

## Reporting bugs / security issues

Bugs: open an issue. Security vulnerabilities: **do not** open a public issue —
see [SECURITY.md](SECURITY.md).
