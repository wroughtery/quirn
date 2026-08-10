// Command quirn probes an OpenAI-compatible LLM endpoint for OWASP-LLM-Top-10
// weaknesses and reports findings as SARIF, JSON, or a terminal summary.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"quirn/internal/llm"
	"quirn/internal/probe"
	"quirn/internal/report"
	"quirn/internal/runner"
)

const helpText = `quirn - LLM red-team CLI (OWASP LLM Top 10)

Usage:
  quirn scan --target <url> [flags]

Flags:
  --target string        Base URL of the OpenAI-compatible endpoint under test (required)
  --model string          Model name to send probe payloads to (default "gpt-4o-mini")
  --judge-model string    Model name used to judge probe outcomes (default: same as --model)
  --api-key string        API key for the target endpoint (overrides QUIRN_API_KEY env var)
  --fail-on string        Minimum severity that fails the build: low|medium|high|critical (default "high")
  --format string         Report format: sarif|json|text (default "text")
  --concurrency int       Max probes to run concurrently (default 4)
  --baseline string       Path to a baseline file of previously-seen findings (not yet applied)
  --out string            Path to write the report to (default: stdout)

Examples:
  quirn scan --target http://localhost:1234 --model llama3
  quirn scan --target https://api.openai.com --model gpt-4o-mini --format sarif --out results.sarif
`

func main() {
	os.Exit(run(os.Args[1:]))
}

// run contains the CLI logic and returns a process exit code, so main stays
// a thin os.Exit wrapper and the rest of the program stays testable.
func run(args []string) int {
	if len(args) == 0 {
		fmt.Print(helpText)
		return 0
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "-h", "--help", "help":
		fmt.Print(helpText)
		return 0
	default:
		fmt.Print(helpText)
		return 2
	}
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	target := fs.String("target", "", "Base URL of the OpenAI-compatible endpoint under test")
	model := fs.String("model", "gpt-4o-mini", "Model name to send probe payloads to")
	judgeModel := fs.String("judge-model", "", "Model name used to judge probe outcomes (default: same as --model)")
	apiKeyFlag := fs.String("api-key", "", "API key for the target endpoint (overrides QUIRN_API_KEY env var)")
	failOn := fs.String("fail-on", "high", "Minimum severity that fails the build: low|medium|high|critical")
	format := fs.String("format", "text", "Report format: sarif|json|text")
	concurrency := fs.Int("concurrency", runner.DefaultConcurrency, "Max probes to run concurrently")
	baseline := fs.String("baseline", "", "Path to a baseline file of previously-seen findings (not yet applied)")
	out := fs.String("out", "", "Path to write the report to (default: stdout)")

	if err := fs.Parse(args); err != nil {
		// flag already printed its own error/usage.
		return 2
	}

	if *target == "" {
		fmt.Print(helpText)
		return 0
	}

	if *judgeModel == "" {
		*judgeModel = *model
	}

	apiKey := *apiKeyFlag
	if apiKey == "" {
		apiKey = os.Getenv("QUIRN_API_KEY")
	}

	// TODO: load *baseline (if set) and filter it out of the results below
	// so PRs only surface *new* findings, per the ratchet design in
	// docs/architecture.md. Not implemented in v0.
	if *baseline != "" {
		fmt.Fprintf(os.Stderr, "quirn: --baseline %q given but baseline filtering is not yet implemented (TODO)\n", *baseline)
	}

	outWriter, closeOut, err := openOutput(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quirn: %v\n", err)
		return 1
	}
	defer closeOut()

	client := llm.NewClient(*target, apiKey)

	cfg := probe.Config{
		Target:     *target,
		Model:      *model,
		JudgeModel: *judgeModel,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	results := runner.Run(ctx, client, cfg, probe.All(), *concurrency)

	if err := writeReport(outWriter, *format, results, *target); err != nil {
		fmt.Fprintf(os.Stderr, "quirn: %v\n", err)
		return 1
	}

	if report.GateFailed(results, *failOn) {
		return 1
	}
	return 0
}

// openOutput returns a writer for path (or os.Stdout if path is empty) and a
// close function that is always safe to call.
func openOutput(path string) (*os.File, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open output %q: %w", path, err)
	}
	return f, func() { f.Close() }, nil
}

func writeReport(w *os.File, format string, results []probe.Result, target string) error {
	switch format {
	case "sarif":
		return report.WriteSARIF(w, results, target)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	case "text", "":
		report.WriteText(w, results)
		return nil
	default:
		return fmt.Errorf("unknown --format %q (want sarif|json|text)", format)
	}
}
