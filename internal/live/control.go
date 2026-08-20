package live

import (
	"context"
	"sync"
)

// Gate is the hook the scan loop consults to honor a pause. runAttacks calls
// Wait before each attack; a nil Gate means no pausing (the normal, no-dashboard
// case). Wait blocks while paused and returns the context error if the scan is
// cancelled (stopped or timed out) so the loop can unwind.
type Gate interface {
	Wait(ctx context.Context) error
}

// GateWait calls g.Wait when g is non-nil, so probe code can gate
// unconditionally. It returns ctx.Err() (which may be nil) when g is nil.
func GateWait(g Gate, ctx context.Context) error {
	if g == nil {
		return ctx.Err()
	}
	return g.Wait(ctx)
}

// Controller coordinates pause/resume/stop between the dashboard's HTTP handlers
// and the running scan. It is safe for concurrent use. Stop cancels the scan's
// context (so an in-flight model call unwinds); pause takes effect at the next
// attack boundary, since Wait is consulted between attacks, not mid-call.
type Controller struct {
	mu      sync.Mutex
	paused  bool
	stopped bool
	// resume is closed to release everything blocked in Wait. It is replaced
	// with a fresh open channel each time the scan is paused, so a later pause
	// blocks again. Guarded by mu.
	resume chan struct{}
	cancel context.CancelFunc
}

// NewController returns a Controller that starts un-paused. cancel is the scan
// context's cancel func, invoked by Stop; it may be nil (Stop then only unblocks
// a pause).
func NewController(cancel context.CancelFunc) *Controller {
	c := &Controller{resume: make(chan struct{}), cancel: cancel}
	close(c.resume) // un-paused: Wait never blocks
	return c
}

// Pause halts the scan at the next attack boundary. No-op if already paused or
// stopped.
func (c *Controller) Pause() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused || c.stopped {
		return
	}
	c.paused = true
	c.resume = make(chan struct{}) // open: Wait now blocks
}

// Resume lets a paused scan continue. No-op if not paused.
func (c *Controller) Resume() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.paused {
		return
	}
	c.paused = false
	close(c.resume)
}

// Stop cancels the scan. It also releases any pause so blocked Wait calls
// observe the cancellation and unwind.
func (c *Controller) Stop() {
	c.mu.Lock()
	if !c.stopped {
		c.stopped = true
		if c.paused {
			c.paused = false
			close(c.resume)
		}
	}
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Paused reports whether the scan is currently paused.
func (c *Controller) Paused() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.paused
}

// Wait blocks while the scan is paused, returning as soon as it resumes or the
// context is cancelled. When not paused it returns ctx.Err() immediately, so a
// cancellation (stop/timeout) still propagates.
func (c *Controller) Wait(ctx context.Context) error {
	for {
		c.mu.Lock()
		paused := c.paused
		resume := c.resume
		c.mu.Unlock()
		if !paused {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-resume:
			// Resumed or stopped: loop re-checks paused and returns.
		}
	}
}
