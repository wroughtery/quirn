#!/usr/bin/env bash
# dev.sh — one-command visibility loop for improving quirn.
#
# Builds, vets, tests with coverage, then dogfoods quirn against the local
# mockllm target and prints EVERY report format. Run it after any change to see
# real end-to-end behavior, not just unit results.
#
#   scripts/dev.sh
#
# Exit status is non-zero if build/vet/test fail, so it doubles as a CI gate.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

hr() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

hr "build";  go build ./... || exit 1
hr "vet";    go vet ./...   || exit 1
hr "test (coverage)"
go test -cover ./... || exit 1

# Build both binaries into a scratch dir.
bin="$(mktemp -d)"
trap 'rm -rf "$bin"; [ -n "${mock_pid:-}" ] && kill "$mock_pid" 2>/dev/null' EXIT
go build -o "$bin/quirn" .            || exit 1
go build -o "$bin/mockllm" ./cmd/mockllm || exit 1

# Start the deterministic mock target (LLM01 + LLM02 vulnerable, rest safe).
addr="127.0.0.1:8749"
"$bin/mockllm" "$addr" & mock_pid=$!
for _ in $(seq 1 50); do
  curl -s -o /dev/null "http://$addr/v1/chat/completions" && break
  sleep 0.1
done

target="http://$addr"
run() { "$bin/quirn" scan --target "$target" --api-key sk-dev "$@"; echo "  -> exit $?"; }

hr "scan: text (default)";   run
hr "scan: json envelope";    run --format json
hr "scan: markdown";         run --format markdown
hr "scan: sarif (head)";     run --format sarif | head -40
hr "list-probes";            "$bin/quirn" scan --list-probes

hr "done"
