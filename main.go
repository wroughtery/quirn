// Command quirn probes an OpenAI-compatible LLM endpoint for OWASP-LLM-Top-10
// weaknesses and reports findings as SARIF, JSON, or a terminal summary.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"quirn/internal/baseline"
	"quirn/internal/config"
	"quirn/internal/live"
	"quirn/internal/llm"
	"quirn/internal/probe"
	"quirn/internal/report"
	"quirn/internal/runner"
)

const helpText = `quirn - LLM red-team CLI (OWASP LLM Top 10)

Usage:
  quirn scan --target <url> [flags]
  quirn version
  quirn help

Flags:
  --target string        Base URL of the OpenAI-compatible endpoint under test (required)
  --model string          Model name to send probe payloads to (default "gpt-4o-mini")
  --judge-model string    Model name used to judge probe outcomes (default: same as --model)
  --judge-target string   Base URL of a separate endpoint for the judge model (default: reuse --target)
  --api-key string        API key for the target endpoint (overrides QUIRN_API_KEY env var)
  --judge-api-key string  API key for --judge-target (overrides QUIRN_JUDGE_API_KEY; falls back to the target key)
  --fail-on string        Minimum severity that fails the build: low|medium|high|critical (default "high")
  --fail-on-inconclusive  Also fail the build if any probe could not reach a verdict
  --format string         Report format: sarif|json|text|markdown (default "text"; "md" is an alias for "markdown")
  --concurrency int       Max probes to run concurrently (default 4)
  --timeout duration      Overall scan deadline, e.g. 10m or 0 to disable (default 10m)
  --max-retries int       Retries per model call on a transient error: 429/5xx/network (default 2)
  --request-timeout dur   Per model-call HTTP timeout, e.g. 2m or 0 to disable (default 2m; raise for slow local models)
  --only string           Run only these probes (comma-separated probe IDs or OWASP ids, e.g. LLM01,excessive-agency)
  --skip string           Skip these probes (comma-separated probe IDs or OWASP ids)
  --list-probes           Print the available probes and exit
  --baseline string       Path to a baseline file; matching findings are suppressed from the gate and SARIF
  --write-baseline        Snapshot the current findings to the --baseline path and exit 0 (accept them)
  --out string            Path to write the report to (default: stdout)
  --config string         JSON config file supplying flag defaults + per-probe severity overrides (flags still win)
  --live                  Stream each attack's payload, reply, and verdict to stderr as the scan runs
  --dashboard             Serve a live web dashboard of the scan; stays up after the scan until Ctrl+C
  --dashboard-addr string Address for --dashboard to bind (default "127.0.0.1:8899"; keep on loopback)

Exit codes: 0 = clean, 1 = findings gated / scan reached no verdict, 2 = usage error.

Examples:
  quirn scan --target http://localhost:1234 --model llama3
  quirn scan --target https://api.openai.com --model gpt-4o-mini --format sarif --out results.sarif
  quirn scan --target http://localhost:1234 --baseline .quirn-baseline.json --write-baseline
  quirn scan --target http://localhost:1234 --baseline .quirn-baseline.json --fail-on high
  quirn scan --target http://localhost:1234 --model qwen3-8b --judge-target https://api.openai.com --judge-model gpt-4o --judge-api-key $OPENAI_KEY
`

// version is the tool version, overridable at build time with
// -ldflags "-X main.version=v1.2.3".
var version = "0.0.1"

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
	case "version", "--version", "-v":
		fmt.Printf("quirn %s\n", version)
		return 0
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
	judgeTarget := fs.String("judge-target", "", "Base URL of a separate endpoint for the judge model (default: reuse --target)")
	judgeAPIKeyFlag := fs.String("judge-api-key", "", "API key for --judge-target (overrides QUIRN_JUDGE_API_KEY; falls back to the target key)")
	failOn := fs.String("fail-on", "high", "Minimum severity that fails the build: low|medium|high|critical")
	failOnInconclusive := fs.Bool("fail-on-inconclusive", false, "Also fail if any probe could not reach a verdict")
	format := fs.String("format", "text", "Report format: sarif|json|text|markdown")
	concurrency := fs.Int("concurrency", runner.DefaultConcurrency, "Max probes to run concurrently")
	timeout := fs.Duration("timeout", 10*time.Minute, "Overall scan deadline (0 disables)")
	maxRetries := fs.Int("max-retries", 2, "Retries per model call on a transient error (429/5xx/network)")
	requestTimeout := fs.Duration("request-timeout", llm.DefaultRequestTimeout, "Per model-call HTTP timeout (0 disables); raise for slow local models")
	only := fs.String("only", "", "Run only these probes (comma-separated probe IDs or OWASP ids)")
	skip := fs.String("skip", "", "Skip these probes (comma-separated probe IDs or OWASP ids)")
	listProbes := fs.Bool("list-probes", false, "Print the available probes and exit")
	baselinePath := fs.String("baseline", "", "Path to a baseline file; matching findings are suppressed")
	writeBaseline := fs.Bool("write-baseline", false, "Snapshot current findings to --baseline and exit 0")
	out := fs.String("out", "", "Path to write the report to (default: stdout)")
	configPath := fs.String("config", "", "Path to a JSON config file supplying flag defaults and per-probe severity overrides")
	liveConsole := fs.Bool("live", false, "Stream each attack's payload, reply, and verdict to stderr as the scan runs")
	dashboard := fs.Bool("dashboard", false, "Serve a live web dashboard of the scan (payload/reply/verdict per attack)")
	dashboardAddr := fs.String("dashboard-addr", "127.0.0.1:8899", "Address for --dashboard to bind (keep on loopback: it exposes captured payloads and replies)")

	if err := fs.Parse(args); err != nil {
		// flag already printed its own error/usage.
		return 2
	}

	// --list-probes is informational and needs no target/key/config.
	if *listProbes {
		printProbes(os.Stdout)
		return 0
	}

	// Load an optional JSON config and fold it in UNDER the flags: a value the
	// user passed on the command line always wins, a config value fills an
	// unset flag, and the built-in default fills the rest. Applied before any
	// validation so the *effective* values are what we validate and scan with.
	var conf *config.File
	if *configPath != "" {
		c, err := config.Load(*configPath)
		switch {
		case errors.Is(err, config.ErrNotExist):
			fmt.Fprintf(os.Stderr, "quirn: --config %q not found\n", *configPath)
			return 2
		case err != nil:
			fmt.Fprintf(os.Stderr, "quirn: %v\n", err)
			return 2
		default:
			conf = c
		}

		set := map[string]bool{}
		fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
		applyStr := func(name string, dst *string, val string) {
			if !set[name] && val != "" {
				*dst = val
			}
		}
		applyStr("target", target, conf.Target)
		applyStr("model", model, conf.Model)
		applyStr("judge-model", judgeModel, conf.JudgeModel)
		applyStr("judge-target", judgeTarget, conf.JudgeTarget)
		applyStr("fail-on", failOn, conf.FailOn)
		applyStr("format", format, conf.Format)
		applyStr("baseline", baselinePath, conf.Baseline)
		if !set["only"] && len(conf.Only) > 0 {
			*only = strings.Join(conf.Only, ",")
		}
		if !set["skip"] && len(conf.Skip) > 0 {
			*skip = strings.Join(conf.Skip, ",")
		}
		if !set["fail-on-inconclusive"] && conf.FailOnInconclusive != nil {
			*failOnInconclusive = *conf.FailOnInconclusive
		}
		if !set["concurrency"] && conf.Concurrency != nil {
			*concurrency = *conf.Concurrency
		}
		if !set["max-retries"] && conf.MaxRetries != nil {
			*maxRetries = *conf.MaxRetries
		}
		if !set["timeout"] {
			if d, ok := conf.TimeoutDuration(); ok {
				*timeout = d
			}
		}
		if !set["request-timeout"] {
			if d, ok := conf.RequestTimeoutDuration(); ok {
				*requestTimeout = d
			}
		}
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
	if !report.ValidFormat(*format) {
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

	probes, err := probe.Select(splitList(*only), splitList(*skip))
	if err != nil {
		fmt.Fprintf(os.Stderr, "quirn: %v\n", err)
		return 2
	}
	// Append any config-defined custom probes. They run in addition to the
	// selected built-ins, in a deterministic order (sorted by id) so reports and
	// baselines stay diff-stable. Done before the empty-selection check so a run
	// consisting only of custom probes (all built-ins skipped) is valid.
	var customIDs []string
	if conf != nil && len(conf.CustomProbes) > 0 {
		builtin := map[string]bool{}
		for _, p := range probe.All() {
			builtin[p.ID()] = true
		}
		custom := append([]config.CustomProbe(nil), conf.CustomProbes...)
		sort.Slice(custom, func(i, j int) bool { return custom[i].ID < custom[j].ID })
		for _, cp := range custom {
			if builtin[cp.ID] {
				fmt.Fprintf(os.Stderr, "quirn: custom probe id %q collides with a built-in probe id\n", cp.ID)
				return 2
			}
			probes = append(probes, buildCustomProbe(cp))
			customIDs = append(customIDs, cp.ID)
		}
	}

	if len(probes) == 0 {
		fmt.Fprintln(os.Stderr, "quirn: no probes selected (check --only/--skip or custom_probes)")
		return 2
	}

	// A severity override keyed on a probe ID that does not exist (neither a
	// built-in nor a defined custom probe) is almost certainly a typo; fail
	// loudly rather than silently ignoring it.
	if conf != nil {
		if unknown := unknownProbeIDs(conf.Severities, customIDs); len(unknown) > 0 {
			fmt.Fprintf(os.Stderr, "quirn: config severities reference unknown probe id(s): %s\n", strings.Join(unknown, ", "))
			return 2
		}
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
	if *maxRetries >= 0 {
		client.MaxRetries = *maxRetries
	}
	client.SetRequestTimeout(*requestTimeout)

	cfg := probe.Config{
		Target:     *target,
		Model:      *model,
		JudgeModel: *judgeModel,
	}

	// A judge key only matters with a separate judge endpoint; flag it if given
	// without one, since it would otherwise be silently ignored.
	if *judgeAPIKeyFlag != "" && *judgeTarget == "" {
		fmt.Fprintln(os.Stderr, "quirn: --judge-api-key set without --judge-target; the judge reuses the target endpoint, so this key is ignored")
	}

	// A separate judge endpoint lets a cheap/local target be judged by a capable
	// model. Judge-key precedence: flag > env > (fallback) the target key, but the
	// target key is reused ONLY when the judge is on the SAME host (the same-
	// provider common case). A real target key is never sent to a different host;
	// there we send none and warn. The judge client inherits the target's
	// retry/timeout settings. Absent --judge-target, JudgeClient stays nil and the
	// judge reuses the target client, keeping single-endpoint runs byte-identical.
	if *judgeTarget != "" {
		judgeKey := *judgeAPIKeyFlag
		if judgeKey == "" {
			judgeKey = os.Getenv("QUIRN_JUDGE_API_KEY")
		}
		if judgeKey == "" {
			if sameHost(*judgeTarget, *target) {
				judgeKey = apiKey
			} else if apiKey != "" {
				fmt.Fprintln(os.Stderr, "quirn: --judge-target is on a different host than --target and no judge key was given; the judge will send no API key (set --judge-api-key or QUIRN_JUDGE_API_KEY)")
			}
		}
		judgeClient := llm.NewClient(*judgeTarget, judgeKey)
		if *maxRetries >= 0 {
			judgeClient.MaxRetries = *maxRetries
		}
		judgeClient.SetRequestTimeout(*requestTimeout)
		cfg.JudgeClient = judgeClient
		fmt.Fprintf(os.Stderr, "quirn: judging via %s (model %s)\n", *judgeTarget, *judgeModel)
	}

	// A cancellable context underlies the scan so the dashboard's Stop button
	// (and the optional --timeout) can end it; cancelling this parent propagates
	// to the timeout child the scan actually runs under.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if *timeout > 0 {
		var tcancel context.CancelFunc
		ctx, tcancel = context.WithTimeout(ctx, *timeout)
		defer tcancel()
	}

	// Optional live views. Both are observational and off by default, so a
	// normal run is unchanged and reports stay byte-identical. The console
	// streams to stderr (never stdout, where a report may go); the dashboard
	// serves on loopback so captured payloads/replies never leave the host.
	var consoleSink live.Observer
	if *liveConsole {
		consoleSink = live.NewConsole(os.Stderr)
	}
	var hub *live.Hub
	if *dashboard {
		hub = live.NewHub()
		// Stop cancels the scan; Pause/Resume gate it between attacks.
		controller := live.NewController(cancel)
		hub.SetController(controller)
		cfg.Gate = controller
		url, err := hub.ListenAndServe(*dashboardAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "quirn: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "quirn: live dashboard at %s\n", url)
	}
	if hub != nil {
		cfg.Observer = live.Multi(consoleSink, hub)
	} else {
		cfg.Observer = consoleSink
	}

	results := runner.Run(ctx, client, cfg, probes, *concurrency)

	// Apply config severity overrides before the gate, baseline, and reports so
	// every downstream consumer sees the overridden severity.
	if conf != nil && len(conf.Severities) > 0 {
		for i := range results {
			if sev, ok := conf.Severities[results[i].ProbeID]; ok {
				results[i].Severity = sev
			}
		}
	}

	// Apply the baseline: matching findings are marked Baselined and drop out of
	// the gate and SARIF output.
	if baselineSet != nil {
		if n := baseline.Apply(results, baselineSet); n > 0 {
			fmt.Fprintf(os.Stderr, "quirn: baseline suppressed %d finding(s)\n", n)
		}
	}

	live.Emit(cfg.Observer, live.Event{Kind: live.KindScanFinish})

	// finish keeps a live dashboard served after the scan ends: it blocks until
	// the user interrupts, then returns the exit code. Without a dashboard it
	// returns immediately, so CI behavior is unchanged.
	finish := func(code int) int {
		if hub != nil {
			fmt.Fprintf(os.Stderr, "quirn: scan finished (exit %d) — dashboard still live at http://%s, press Ctrl+C to exit\n", code, *dashboardAddr)
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt)
			<-sig
		}
		return code
	}

	if err := writeReport(outWriter, *format, results, *target); err != nil {
		fmt.Fprintf(os.Stderr, "quirn: %v\n", err)
		return 1
	}

	// A run in which no probe reached a verdict tested nothing (bad key,
	// unreachable target, timeout). It must NOT look like a clean pass, and it
	// must not snapshot an empty baseline, so fail before either.
	if report.AllInconclusive(results) {
		fmt.Fprintln(os.Stderr, "quirn: every probe was inconclusive — the target was unreachable or every call timed out (check --target/--api-key, raise --request-timeout, or lower --concurrency for a slow local model); failing the run")
		return finish(1)
	}

	// --write-baseline snapshots the current findings and accepts them: write
	// the file and exit 0 without gating this run.
	if *writeBaseline {
		if err := baseline.WriteFile(*baselinePath, results); err != nil {
			fmt.Fprintf(os.Stderr, "quirn: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "quirn: wrote baseline %q\n", *baselinePath)
		return finish(0)
	}

	if report.GateFailed(results, *failOn) {
		return finish(1)
	}
	if *failOnInconclusive && report.AnyInconclusive(results) {
		fmt.Fprintln(os.Stderr, "quirn: --fail-on-inconclusive set and at least one probe was inconclusive; failing the run")
		return finish(1)
	}
	return finish(0)
}

// splitList splits a comma-separated flag value into trimmed, non-empty tokens.
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// sameHost reports whether two base URLs point at the same host:port. The judge
// reuses the target's API key only when this is true, so a real target key is
// never sent to a different host. A URL that fails to parse or has no host is
// treated as "not the same host" — the safe default (send no key).
func sameHost(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil || ua.Host == "" {
		return false
	}
	return ua.Host == ub.Host
}

// unknownProbeIDs returns the keys of sevs that match neither a built-in probe
// ID nor one of the extra (custom) IDs, sorted for a stable error message.
func unknownProbeIDs(sevs map[string]string, extra []string) []string {
	if len(sevs) == 0 {
		return nil
	}
	known := map[string]bool{}
	for _, p := range probe.All() {
		known[p.ID()] = true
	}
	for _, id := range extra {
		known[id] = true
	}
	var unknown []string
	for id := range sevs {
		if !known[id] {
			unknown = append(unknown, id)
		}
	}
	sort.Strings(unknown)
	return unknown
}

// buildCustomProbe converts a config-defined custom probe into a runnable Probe,
// filling in defaults for the optional name/owasp/attack-name fields.
func buildCustomProbe(cp config.CustomProbe) probe.Probe {
	name := cp.Name
	if name == "" {
		name = cp.ID
	}
	owasp := cp.OWASP
	if owasp == "" {
		owasp = "CUSTOM"
	}
	atks := make([]probe.Attack, len(cp.Attacks))
	for i, a := range cp.Attacks {
		nm := a.Name
		if nm == "" {
			nm = fmt.Sprintf("attack-%d", i+1)
		}
		atks[i] = probe.Attack{Name: nm, Goal: a.Goal, System: a.System, Payload: a.Payload}
	}
	return probe.NewCustom(cp.ID, name, owasp, cp.Severity, atks)
}

// printProbes writes the available probes (id, OWASP, severity, name) to w.
func printProbes(w io.Writer) {
	fmt.Fprintf(w, "%-24s %-8s %-10s %s\n", "PROBE", "OWASP", "SEVERITY", "NAME")
	for _, p := range probe.All() {
		fmt.Fprintf(w, "%-24s %-8s %-10s %s\n", p.ID(), p.OWASP(), p.Severity(), p.Name())
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
		return report.WriteJSON(w, results, target, version)
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
