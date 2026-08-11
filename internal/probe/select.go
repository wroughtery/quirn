package probe

import (
	"fmt"
	"sort"
	"strings"
)

// Select returns the subset of All() chosen by the only/skip filters. Each
// token matches a probe by its ID (e.g. "prompt-injection") or its OWASP id
// (e.g. "LLM01"), case-insensitively. When only is non-empty, just the matching
// probes are kept; skip then removes any matching probes. Unknown tokens are an
// error, so a typo cannot silently scan nothing (or everything). Input order
// from All() is preserved.
func Select(only, skip []string) ([]Probe, error) {
	all := All()
	if err := validateTokens(all, only, "--only"); err != nil {
		return nil, err
	}
	if err := validateTokens(all, skip, "--skip"); err != nil {
		return nil, err
	}

	onlySet := lowerSet(only)
	skipSet := lowerSet(skip)

	var out []Probe
	for _, p := range all {
		if len(onlySet) > 0 && !probeMatches(p, onlySet) {
			continue
		}
		if probeMatches(p, skipSet) {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// probeMatches reports whether p is named by any token in set (by ID or OWASP).
func probeMatches(p Probe, set map[string]struct{}) bool {
	if _, ok := set[strings.ToLower(p.ID())]; ok {
		return true
	}
	_, ok := set[strings.ToLower(p.OWASP())]
	return ok
}

// lowerSet builds a case-folded lookup set, dropping empty tokens.
func lowerSet(tokens []string) map[string]struct{} {
	set := make(map[string]struct{}, len(tokens))
	for _, t := range tokens {
		if t = strings.TrimSpace(t); t != "" {
			set[strings.ToLower(t)] = struct{}{}
		}
	}
	return set
}

// validateTokens returns an error naming any token in tokens that does not
// match a known probe ID or OWASP id, along with the available identifiers.
func validateTokens(all []Probe, tokens []string, flag string) error {
	known := make(map[string]struct{}, len(all)*2)
	for _, p := range all {
		known[strings.ToLower(p.ID())] = struct{}{}
		known[strings.ToLower(p.OWASP())] = struct{}{}
	}
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := known[strings.ToLower(t)]; !ok {
			return fmt.Errorf("%s: unknown probe %q; available: %s", flag, t, strings.Join(identifiers(all), ", "))
		}
	}
	return nil
}

// identifiers returns a sorted list of every selectable token (probe IDs and
// OWASP ids), used in error messages.
func identifiers(all []Probe) []string {
	var ids []string
	for _, p := range all {
		ids = append(ids, p.ID(), p.OWASP())
	}
	sort.Strings(ids)
	return ids
}
