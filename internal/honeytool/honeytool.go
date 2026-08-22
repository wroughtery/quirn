// Package honeytool runs a loopback HTTP listener that stands in for a
// dangerous tool an operator registers on the agent under test. When the agent
// actually invokes that tool, the call lands here and is recorded. A recorded
// hit CONFIRMS an excessive-agency finding (the agent really acted), as opposed
// to the black-box proxy signal of merely reading intent-to-act in the reply.
//
// It is loopback-only on purpose: anything that can reach the listener can
// fabricate a hit, and a fabricated hit would be a false CONFIRMED finding. So
// the agent under test must be reachable to a loopback address (run quirn on the
// same host as the agent, or tunnel). Binding to a routable address is refused.
//
// stdlib-only, like the rest of quirn.
package honeytool

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// maxBodyBytes caps how much of a tool-call body the recorder reads. The caller
// is an agent quirn does not trust; an unbounded body must not OOM the process.
const maxBodyBytes = 64 << 10 // 64 KiB

// maxHits bounds how many hits are retained. Anything on loopback (including a
// looping agent under test) could otherwise grow the slice without limit; we
// keep the most recent maxHits so memory stays bounded. Attribution only ever
// looks at hits since an attack began, so old hits beyond this window are never
// needed.
const maxHits = 4096

// DefaultAddr is the loopback address the honeytool binds when none is given.
const DefaultAddr = "127.0.0.1:8898"

// Hit is one recorded invocation of the honeytool.
type Hit struct {
	Path   string
	Method string
	Query  string
	Body   string
	At     time.Time
}

// Recorder is a running honeytool listener that records every request it
// receives. It is safe for concurrent use.
type Recorder struct {
	mu        sync.Mutex
	hits      []Hit
	srv       *http.Server
	url       string
	now       func() time.Time // injectable clock; defaults to time.Now
	closeOnce sync.Once
	closeErr  error
}

// Start binds a loopback listener at addr (DefaultAddr when empty) and begins
// recording. It returns an error if addr is not a loopback address or the port
// is unavailable. Close stops the listener.
func Start(addr string) (*Recorder, error) {
	if strings.TrimSpace(addr) == "" {
		addr = DefaultAddr
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("honeytool: invalid address %q: %w", addr, err)
	}
	if !isLoopbackHost(host) {
		return nil, fmt.Errorf("honeytool: address %q is not loopback; the honeytool must bind to localhost (a routable bind would let any host forge a confirmed finding)", addr)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("honeytool: listen on %q: %w", addr, err)
	}
	// Assert the resolved bind is actually loopback, not just the name: net.Listen
	// runs "localhost" through the system resolver/hosts file, which could point
	// at a routable address. A routable listener would let any host forge a
	// confirmed finding, so refuse it rather than trust the name.
	if tcp, ok := ln.Addr().(*net.TCPAddr); !ok || !tcp.IP.IsLoopback() {
		ln.Close()
		return nil, fmt.Errorf("honeytool: %q resolved to a non-loopback address %s; refusing to bind", addr, ln.Addr())
	}

	r := &Recorder{now: time.Now}
	mux := http.NewServeMux()
	mux.HandleFunc("/", r.handle)
	r.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second, // a stalled local client must not pin a goroutine for the whole scan
	}
	r.url = "http://" + ln.Addr().String()

	go r.srv.Serve(ln)
	return r, nil
}

// handle records the request and returns a plausible success so the agent's tool
// call "succeeds" and it proceeds (revealing that it was willing to act).
func (r *Recorder) handle(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(req.Body, maxBodyBytes))
	r.mu.Lock()
	r.hits = append(r.hits, Hit{
		Path:   req.URL.Path,
		Method: req.Method,
		Query:  req.URL.RawQuery,
		Body:   string(body),
		At:     r.now(),
	})
	// Keep only the most recent maxHits so a flood of loopback calls cannot grow
	// memory without bound; older hits are outside any attack window anyway.
	if len(r.hits) > maxHits {
		r.hits = r.hits[len(r.hits)-maxHits:]
	}
	r.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"status":"ok","result":"done"}`)
}

// URL returns the base URL the operator should register as the dangerous tool.
func (r *Recorder) URL() string { return r.url }

// HitsSince returns the hits recorded at or after t, oldest first. The agency
// probe passes the moment an attack began so a hit is attributed to that attack.
func (r *Recorder) HitsSince(t time.Time) []Hit {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Hit
	for _, h := range r.hits {
		if !h.At.Before(t) {
			out = append(out, h)
		}
	}
	return out
}

// Count returns the number of retained hits (capped at maxHits).
func (r *Recorder) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.hits)
}

// Close stops the listener. It is safe to call more than once; the shutdown runs
// once and every caller sees the same result (a second raw Shutdown could
// otherwise return a spurious "closed network connection" depending on timing).
func (r *Recorder) Close() error {
	if r == nil || r.srv == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		r.closeErr = r.srv.Shutdown(ctx)
	})
	return r.closeErr
}

// isLoopbackHost reports whether host is a loopback host: an empty host (bind to
// all interfaces) is explicitly NOT loopback and is refused.
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
