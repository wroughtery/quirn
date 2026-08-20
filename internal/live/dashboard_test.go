package live

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHubHandleAssignsMonotonicSeqAndStores(t *testing.T) {
	h := NewHub()
	h.Handle(Event{Kind: KindProbeStart})
	h.Handle(Event{Kind: KindAttackStart})

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.buffer) != 2 {
		t.Fatalf("buffer len = %d, want 2", len(h.buffer))
	}
	if h.buffer[0].Seq != 1 || h.buffer[1].Seq != 2 {
		t.Errorf("seqs = %d,%d, want 1,2", h.buffer[0].Seq, h.buffer[1].Seq)
	}
}

func TestHubScanFinishMarksDone(t *testing.T) {
	h := NewHub()
	h.Handle(Event{Kind: KindProbeStart})
	h.mu.Lock()
	done := h.done
	h.mu.Unlock()
	if done {
		t.Fatal("done set before scan_finish")
	}
	h.Handle(Event{Kind: KindScanFinish})
	h.mu.Lock()
	done = h.done
	h.mu.Unlock()
	if !done {
		t.Error("done not set after scan_finish")
	}
}

func TestHubSubscribeBacklogThenLive(t *testing.T) {
	h := NewHub()
	h.Handle(Event{Kind: KindProbeStart, ProbeID: "a"})
	h.Handle(Event{Kind: KindProbeStart, ProbeID: "b"})

	backlog, ch, unsub := h.subscribe()
	defer unsub()

	if len(backlog) != 2 || backlog[0].ProbeID != "a" || backlog[1].ProbeID != "b" {
		t.Fatalf("backlog snapshot wrong: %+v", backlog)
	}

	// An event sent after subscribe arrives on the channel exactly once.
	h.Handle(Event{Kind: KindProbeStart, ProbeID: "c"})
	select {
	case e := <-ch:
		if e.ProbeID != "c" {
			t.Errorf("live event = %q, want c", e.ProbeID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for live event")
	}
}

func TestHubUnsubStopsDelivery(t *testing.T) {
	h := NewHub()
	_, ch, unsub := h.subscribe()
	unsub()
	h.Handle(Event{Kind: KindProbeStart})

	// After unsub the client channel receives nothing.
	select {
	case e, ok := <-ch:
		if ok {
			t.Errorf("received %+v after unsubscribe", e)
		}
	default:
	}

	h.mu.Lock()
	n := len(h.clients)
	h.mu.Unlock()
	if n != 0 {
		t.Errorf("clients still registered after unsub: %d", n)
	}
}

func TestHubHandleNeverBlocksOnSlowClient(t *testing.T) {
	h := NewHub()
	_, _, unsub := h.subscribe() // a client that never reads
	defer unsub()

	// Sending well past the buffer must not deadlock: excess events are dropped,
	// not blocked on. A regression here would hang the test.
	done := make(chan struct{})
	go func() {
		for i := 0; i < clientBuffer+50; i++ {
			h.Handle(Event{Kind: KindAttackStart})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Handle blocked on a slow client")
	}
}

func TestHubConcurrentHandleAssignsUniqueSeqs(t *testing.T) {
	h := NewHub()
	const n = 200
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.Handle(Event{Kind: KindAttackStart})
		}()
	}
	wg.Wait()

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.buffer) != n {
		t.Fatalf("buffer len = %d, want %d", len(h.buffer), n)
	}
	seen := make(map[int]bool, n)
	for _, e := range h.buffer {
		if e.Seq < 1 || e.Seq > n {
			t.Fatalf("seq %d out of range", e.Seq)
		}
		if seen[e.Seq] {
			t.Fatalf("duplicate seq %d", e.Seq)
		}
		seen[e.Seq] = true
	}
	if len(seen) != n {
		t.Errorf("got %d distinct seqs, want %d", len(seen), n)
	}
}

func TestHandleIndexServesPageAnd404(t *testing.T) {
	h := NewHub()

	rec := httptest.NewRecorder()
	h.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("index status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<title>quirn live</title>") || !strings.Contains(body, "EventSource") {
		t.Error("index body missing expected dashboard markup")
	}

	rec404 := httptest.NewRecorder()
	h.handleIndex(rec404, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec404.Code != http.StatusNotFound {
		t.Errorf("unknown path status = %d, want 404", rec404.Code)
	}
}

func TestHandleEventsReplaysBacklogAsSSE(t *testing.T) {
	h := NewHub()
	h.Handle(Event{Kind: KindProbeStart, ProbeID: "alpha"})
	h.Handle(Event{Kind: KindAttackVerdict, Attack: "x", Verdict: "vulnerable"})

	// A pre-cancelled context makes handleEvents flush the backlog, then return
	// as soon as it enters the streaming loop — deterministic, no sleeps.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/events", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	h.handleEvents(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"data: ", `"probeId":"alpha"`, `"verdict":"vulnerable"`} {
		if !strings.Contains(body, want) {
			t.Errorf("SSE backlog missing %q\n---\n%s", want, body)
		}
	}
}

func TestHandleControlDrivesController(t *testing.T) {
	h := NewHub()

	// No controller wired yet -> unavailable.
	rec := httptest.NewRecorder()
	h.handleControl(rec, httptest.NewRequest(http.MethodPost, "/control?action=pause", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 without controller, got %d", rec.Code)
	}

	ctrl := NewController(nil)
	h.SetController(ctrl)

	// GET is rejected.
	rec = httptest.NewRecorder()
	h.handleControl(rec, httptest.NewRequest(http.MethodGet, "/control?action=pause", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405 for GET, got %d", rec.Code)
	}

	// Pause then resume drive the controller.
	rec = httptest.NewRecorder()
	h.handleControl(rec, httptest.NewRequest(http.MethodPost, "/control?action=pause", nil))
	if rec.Code != http.StatusOK || !ctrl.Paused() {
		t.Fatalf("pause failed: code=%d paused=%v", rec.Code, ctrl.Paused())
	}
	rec = httptest.NewRecorder()
	h.handleControl(rec, httptest.NewRequest(http.MethodPost, "/control?action=resume", nil))
	if rec.Code != http.StatusOK || ctrl.Paused() {
		t.Errorf("resume failed: code=%d paused=%v", rec.Code, ctrl.Paused())
	}

	// Unknown action is a client error.
	rec = httptest.NewRecorder()
	h.handleControl(rec, httptest.NewRequest(http.MethodPost, "/control?action=frobnicate", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for unknown action, got %d", rec.Code)
	}

	// Each valid action broadcasts a state event.
	h.mu.Lock()
	n := len(h.buffer)
	h.mu.Unlock()
	if n < 2 {
		t.Errorf("control actions should broadcast events, buffered %d", n)
	}
}

func TestListenAndServeBindsLoopbackAndServes(t *testing.T) {
	h := NewHub()
	url, err := h.ListenAndServe("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Errorf("url = %q, want loopback", url)
	}

	resp, err := http.Get(url + "/")
	if err != nil {
		t.Fatalf("GET index: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "quirn live") {
		t.Errorf("served index unexpected: status=%d", resp.StatusCode)
	}
}
