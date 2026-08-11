// Command quirn probes an OpenAI-compatible LLM endpoint for OWASP-LLM-Top-10
// weaknesses and reports findings as SARIF, JSON, or a terminal summary.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"quirn/internal/baseline"
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
  --fail-on-inconclusive  Also fail the build if any probe could not reach a verdict
  --format string         Report format: sarif|json|text|markdown (default "text")
  --concurrency int       Max probes to run concurrently (default 4)
  --timeout duration      Overall scan deadline, e.g. 10m or 0 to disable (default 10m)
  --baseline string       Path to a baseline file; matching findings are suppressed from the gate and SARIF
  --write-baseline        Snapshot the current findings to the --baseline path and exit 0 (accept them)
  --out string            Path to write the report to (default: stdout)

Exit codes: 0 = clean, 1 = findings gated / scan reached no verdict, 2 = usage error.

Examples:
  quirn scan --target http://localhost:1234 --model llama3
  quirn scan --target https://api.openai.com --model gpt-4o-mini --format sarif --out results.sarif
  quirn scan --target http://localhost:1234 --baseline .quirn-baseline.json --write-baseline
  quirn scan --target http://localhost:1234 --baseline .quirn-baseline.json --fail-on high
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
	failOnInconclusive := fs.Bool("fail-on-inconclusive", false, "Also fail if any probe could not reach a verdict")
	format := fs.String("format", "text", "Report format: sarif|json|text|markdown")
	concurrency := fs.Int("concurrency", runner.DefaultConcurrency, "Max probes to run concurrently")
	timeout := fs.Duration("timeout", 10*time.Minute, "Overall scan deadline (0 disables)")
	baselinePath := fs.String("baseline", "", "Path to a baseline file; matching findings are suppressed")
	writeBaseline := fs.Bool("write-baseline", false, "Snapshot current findings to --baseline and exit 0")
	out := fs.String("out", "", "Path to write the report to (default: stdout)")

	if err := fs.Parse(args); err != nil {
		// flag already printed its own error/usage.
		return 2
	}

	if *judgeModel == "" {
		*judgeModel = *model
	}

	apiKey := *apiKeyFlag
	if apiKey == "" {
		apiKey = os.Getenv("QUIRN_API_KEY")
	}

	// Validate everything cheap BEFORE running the scan or truncating --out, so
	// a misconfigured run fails fast without spending API calls or destroying a
	// previous report.
	if *target == "" {
		fmt.Fprintln(os.Stderr, "quirn: --target <url> is required")
		return 2
	}
	if !validFormat(*format) {
		fmt.Fprintf(os.Stderr, "quirn: unknown --format %q (want sarif|json|text|markdown)\n", *format)
		return 2
	}
	if !report.ValidSeverity(*failOn) {
		fmt.Fprintf(os.Stderr, "quirn: unknown --fail-on %q (want low|medium|high|critical)\n", *failOn)
		return 2
	}
	if *writeBaseline && *baselinePath == "" {
		fmt.Fprintln(os.Stderr, "quirn: --write-baseline requires --baseline <path>")
		return 2
	}

	// Load an existing baseline up front (unless we're about to overwrite it) so
	// a corrupt or wrong-version file is caught before the scan runs.
	var baselineSet baseline.Set
	if *baselinePath != "" && !*writeBaseline {
		set, err := baseline.Load(*baselinePath)
		switch {
		case errors.Is(err, baseline.ErrNotExist):
			fmt.Fprintf(os.Stderr, "quirn: baseline %q not found; no findings suppressed\n", *baselinePath)
		case err != nil:
			fmt.Fprintf(os.Stderr, "quirn: %v\n", err)
			return 2
		default:
			baselineSet = set
		}
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

	ctx := context.Background()
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}

	results := runner.Run(ctx, client, cfg, probe.All(), *concurrency)

	// Apply the baseline: matching findings are marked Baselined and drop out of
	// the gate and SARIF output.
	if baselineSet != nil {
		if n := baseline.Apply(results, baselineSet); n > 0 {
			fmt.Fprintf(os.Stderr, "quirn: baseline suppressed %d finding(s)\n", n)
		}
	}

	if err := writeReport(outWriter, *format, results, *target); err != nil {
		fmt.Fprintf(os.Stderr, "quirn: %v\n", err)
		return 1
	}

	// A run in which no probe reached a verdict tested nothing (bad key,
	// unreachable target, timeout). It must NOT look like a clean pass, and it
	// must not snapshot an empty baseline, so fail before either.
	if report.AllInconclusive(results) {
		fmt.Fprintln(os.Stderr, "quirn: every probe was inconclusive — the target could not be reached or scored (check --target, --api-key, --timeout); failing the run")
		return 1
	}

	// --write-baseline snapshots the current findings and accepts them: write
	// the file and exit 0 without gating this run.
	if *writeBaseline {
		if err := baseline.WriteFile(*baselinePath, results); err != nil {
			fmt.Fprintf(os.Stderr, "quirn: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "quirn: wrote baseline %q\n", *baselinePath)
		return 0
	}

	if report.GateFailed(results, *failOn) {
		return 1
	}
	if *failOnInconclusive && report.AnyInconclusive(results) {
		fmt.Fprintln(os.Stderr, "quirn: --fail-on-inconclusive set and at least one probe was inconclusive; failing the run")
		return 1
	}
	return 0
}

// validFormat reports whether f is a report format writeReport can render.
func validFormat(f string) bool {
	switch f {
	case "sarif", "json", "markdown", "md", "text", "":
		return true
	default:
		return false
	}
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
	case "markdown", "md":
		report.WriteMarkdown(w, results, target)
		return nil
	case "text", "":
		report.WriteText(w, results)
		return nil
	default:
		return fmt.Errorf("unknown --format %q (want sarif|json|text|markdown)", format)
	}
}
