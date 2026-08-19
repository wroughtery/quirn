package live

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
)

// dashboardHTML is the single-file web UI, embedded so quirn stays one static
// binary. It connects to /events (SSE) and renders the live scan.
//
//go:embed dashboard.html
var dashboardHTML []byte

// clientBuffer is how many events a connected browser may fall behind before
// the Hub drops events for it rather than blocking the scan. A scan emits on
// the order of tens of events, so a localhost client never approaches this;
// the bound exists only so a stalled or vanished client can never wedge a
// probe goroutine.
const clientBuffer = 512

// Hub is the dashboard's event bus and an Observer. It records every Event
// (for replay to browsers that connect mid-scan) and fans new ones out to all
// connected SSE clients. It is safe for concurrent Handle calls.
type Hub struct {
	mu      sync.Mutex
	seq     int
	buffer  []Event
	clients map[chan Event]struct{}
	done    bool
}

// NewHub returns an empty Hub.
func NewHub() *Hub {
	return &Hub{clients: make(map[chan Event]struct{})}
}

// Handle assigns the event a sequence number, stores it for replay, and
// broadcasts it to every connected client. Sends are non-blocking: a client
// that has fallen clientBuffer events behind misses events rather than
// stalling the scan (it recovers the full history on reconnect).
func (h *Hub) Handle(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.seq++
	e.Seq = h.seq
	h.buffer = append(h.buffer, e)
	if e.Kind == KindScanFinish {
		h.done = true
	}
	for ch := range h.clients {
		select {
		case ch <- e:
		default:
		}
	}
}

// subscribe registers a new client and atomically returns the backlog captured
// at registration time, the client's channel, and an unsubscribe function.
// Because the snapshot and the registration happen under one lock, the client
// sees every event exactly once: anything in the backlog is not yet on the
// channel, and anything sent after is.
func (h *Hub) subscribe() (backlog []Event, ch chan Event, unsub func()) {
	h.mu.Lock()
	defer h.mu.Unlock()

	backlog = make([]Event, len(h.buffer))
	copy(backlog, h.buffer)

	ch = make(chan Event, clientBuffer)
	h.clients[ch] = struct{}{}

	return backlog, ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, ok := h.clients[ch]; ok {
			delete(h.clients, ch)
		}
	}
}

// ListenAndServe binds addr and serves the dashboard in a background goroutine,
// returning the resolved base URL (so addr may use :0 to auto-pick a port).
// addr should be a loopback address; quirn's caller defaults it to 127.0.0.1 so
// captured payloads and model replies are never exposed off-host.
func (h *Hub) ListenAndServe(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("live: bind dashboard %q: %w", addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleIndex)
	mux.HandleFunc("/events", h.handleEvents)

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)

	return "http://" + ln.Addr().String(), nil
}

func (h *Hub) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(dashboardHTML)
}

// handleEvents streams the scan as Server-Sent Events: the backlog first, then
// live events until the scan ends or the client disconnects.
func (h *Hub) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	backlog, ch, unsub := h.subscribe()
	defer unsub()

	for _, e := range backlog {
		writeSSE(w, e)
	}
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-ch:
			writeSSE(w, e)
			flusher.Flush()
		}
	}
}

// writeSSE writes one Event as an SSE "data:" frame. A marshal error is skipped
// rather than corrupting the stream; it cannot happen for the flat Event struct.
func writeSSE(w http.ResponseWriter, e Event) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", b)
}
