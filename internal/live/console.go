package live

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// consoleWidth caps how much of a payload/reply the console stream prints on one
// line. The full text is always available in the report and the web dashboard;
// the console is a glanceable running log, so long bodies are truncated.
const consoleWidth = 160

// Console is an Observer that writes a human-readable running log of a scan to
// an io.Writer (typically os.Stderr, so it never mixes with a report on stdout).
// It is safe for concurrent use.
type Console struct {
	mu sync.Mutex
	w  io.Writer
}

// NewConsole returns a Console streaming to w.
func NewConsole(w io.Writer) *Console { return &Console{w: w} }

func (c *Console) Handle(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch e.Kind {
	case KindProbeStart:
		fmt.Fprintf(c.w, "\n▶ %s %s — %s\n", e.OWASP, e.ProbeID, e.Name)
	case KindAttackStart:
		fmt.Fprintf(c.w, "  → [%s] send: %s\n", e.Attack, oneLine(e.Payload))
	case KindAttackResponse:
		if e.Error != "" {
			fmt.Fprintf(c.w, "  ✗ [%s] call failed after %s: %s\n", e.Attack, dur(e.LatencyMS), oneLine(e.Error))
			return
		}
		fmt.Fprintf(c.w, "  ← [%s] reply (%s): %s\n", e.Attack, dur(e.LatencyMS), oneLine(e.Reply))
	case KindAttackVerdict:
		fmt.Fprintf(c.w, "  %s [%s] %s — %s\n", verdictGlyph(e.Verdict), e.Attack, strings.ToUpper(e.Verdict), oneLine(e.Reason))
	case KindProbeFinish:
		fmt.Fprintf(c.w, "%s %s %s: %s\n", verdictGlyph(e.Verdict), e.OWASP, e.ProbeID, e.Verdict)
	case KindScanFinish:
		fmt.Fprintf(c.w, "\n■ scan complete\n")
	case KindScanPaused:
		fmt.Fprintf(c.w, "\n‖ scan paused\n")
	case KindScanResumed:
		fmt.Fprintf(c.w, "\n▸ scan resumed\n")
	case KindScanStopped:
		fmt.Fprintf(c.w, "\n■ scan stopped by user\n")
	}
}

// verdictGlyph maps a verdict string to a leading marker.
func verdictGlyph(v string) string {
	switch v {
	case "vulnerable":
		return "⚠"
	case "safe":
		return "✓"
	default:
		return "?"
	}
}

// dur renders a millisecond latency compactly (e.g. "2.3s", "840ms").
func dur(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	if d >= time.Second {
		return d.Round(100 * time.Millisecond).String()
	}
	return d.Round(time.Millisecond).String()
}

// oneLine collapses newlines/tabs to spaces and truncates to consoleWidth so a
// multi-line payload or reply prints as a single scannable line.
func oneLine(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
	// Collapse runs of spaces the mapping may have produced.
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > consoleWidth {
		return s[:consoleWidth-1] + "…"
	}
	return s
}
