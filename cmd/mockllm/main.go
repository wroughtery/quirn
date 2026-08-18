// Command mockllm serves a deterministic OpenAI-compatible endpoint so quirn
// can be run end-to-end with no real API key and every report format inspected
// by eye. It is the dogfood target for the dev loop (see scripts/dev.*).
//
//	go run ./cmd/mockllm 127.0.0.1:8749
//	quirn scan --target http://127.0.0.1:8749 --format json
//
// By default the injection (LLM01) and sensitive-disclosure (LLM02) probes come
// back VULNERABLE and the rest SAFE, giving a mixed run that exercises the
// gate, the baseline, and every report. Override the vulnerable set with
// --markers (comma-separated canaries) or force an all-inconclusive run with
// --fail.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"quirn/internal/mockllm"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("mockllm", flag.ContinueOnError)
	markers := fs.String("markers", "PWNED,sk_live_ACME",
		"comma-separated canaries whose probes report VULNERABLE (empty = all SAFE)")
	fail := fs.Bool("fail", false, "return 500 to every request (all-inconclusive run)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	addr := "127.0.0.1:8749"
	if a := fs.Arg(0); a != "" {
		addr = a
	}

	h, _ := mockllm.Handler(mockllm.Config{
		VulnMarkers: splitList(*markers),
		Fail:        *fail,
	})

	fmt.Fprintf(os.Stderr, "mockllm: listening on http://%s  (vulnerable markers: %q, fail=%v)\n",
		addr, *markers, *fail)
	if err := http.ListenAndServe(addr, h); err != nil {
		fmt.Fprintf(os.Stderr, "mockllm: %v\n", err)
		return 1
	}
	return 0
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
