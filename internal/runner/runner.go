// Package runner executes a set of probes concurrently against a target,
// bounding parallelism with a worker-count semaphore.
package runner

import (
	"context"
	"sync"

	"quirn/internal/llm"
	"quirn/internal/probe"
)

// DefaultConcurrency is used when Run is called with concurrency <= 0.
const DefaultConcurrency = 4

// Run executes every probe in probes concurrently against cfg, bounding the
// number of in-flight probes to concurrency (DefaultConcurrency if <= 0).
// Results are returned in the same order as probes, regardless of
// completion order.
func Run(ctx context.Context, client *llm.Client, cfg probe.Config, probes []probe.Probe, concurrency int) []probe.Result {
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}

	results := make([]probe.Result, len(probes))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, p := range probes {
		wg.Add(1)
		go func(i int, p probe.Probe) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			results[i] = p.Run(ctx, client, cfg)
		}(i, p)
	}

	wg.Wait()
	return results
}
