// Package baseline records previously-accepted findings so that repeated scans
// surface only *new* vulnerabilities. A baseline is a small JSON file listing
// the stable IDs of findings a team has chosen to accept; on the next run,
// matching findings are flagged Baselined and excluded from the severity gate
// and SARIF output. This turns quirn from a pass/fail check into a ratchet:
// adopt at a loose --fail-on, snapshot the current findings, then tighten over
// time while only regressions break the build.
package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/wroughtery/quirn/internal/probe"
)

// formatVersion is written into every baseline file so the format can evolve
// without silently misreading an older file.
const formatVersion = 1

// File is the on-disk baseline structure.
type File struct {
	Version  int      `json:"version"`
	Findings []string `json:"findings"`
}

// Set is a fast lookup of accepted finding IDs.
type Set map[string]struct{}

// Has reports whether id is present in the set. The nil set contains nothing.
func (s Set) Has(id string) bool {
	_, ok := s[id]
	return ok
}

// ErrNotExist is returned by Load when path does not exist, so callers can
// distinguish "no baseline yet" (fine when creating one) from a read error.
var ErrNotExist = os.ErrNotExist

// Load reads a baseline file and returns the set of accepted finding IDs. If
// the file does not exist it returns a wrapped ErrNotExist; callers that are
// about to create the baseline can ignore that case.
func Load(path string) (Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("baseline %q: %w", path, ErrNotExist)
		}
		return nil, fmt.Errorf("baseline: read %q: %w", path, err)
	}

	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("baseline: parse %q: %w", path, err)
	}
	if f.Version != formatVersion {
		return nil, fmt.Errorf("baseline %q: unsupported version %d (want %d)", path, f.Version, formatVersion)
	}

	set := make(Set, len(f.Findings))
	for _, id := range f.Findings {
		set[id] = struct{}{}
	}
	return set, nil
}

// Apply marks every vulnerable result whose stable ID is in set as Baselined,
// mutating results in place, and returns how many were suppressed. Results
// that are not vulnerable are left untouched.
func Apply(results []probe.Result, set Set) int {
	suppressed := 0
	for i := range results {
		if results[i].Vulnerable && set.Has(results[i].StableID()) {
			results[i].Baselined = true
			suppressed++
		}
	}
	return suppressed
}

// Write serialises the stable IDs of every currently-vulnerable finding (both
// newly-found and already-baselined) to w as a baseline file. The ID list is
// sorted so the output is deterministic and diffs cleanly in version control.
func Write(w io.Writer, results []probe.Result) error {
	ids := []string{} // non-nil so an empty snapshot serialises as [], not null
	for _, r := range results {
		if r.Vulnerable {
			ids = append(ids, r.StableID())
		}
	}
	sort.Strings(ids)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(File{Version: formatVersion, Findings: ids})
}

// WriteFile writes the baseline for results to path, creating or truncating it.
func WriteFile(path string, results []probe.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("baseline: create %q: %w", path, err)
	}
	defer f.Close()
	if err := Write(f, results); err != nil {
		return fmt.Errorf("baseline: write %q: %w", path, err)
	}
	return nil
}
