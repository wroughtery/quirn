package live

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestControllerUnpausedWaitReturnsImmediately(t *testing.T) {
	c := NewController(nil)
	done := make(chan error, 1)
	go func() { done <- c.Wait(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unpaused Wait returned %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unpaused Wait blocked")
	}
}

func TestPauseBlocksAndResumeReleases(t *testing.T) {
	c := NewController(nil)
	c.Pause()
	if !c.Paused() {
		t.Fatal("Paused() false after Pause")
	}

	done := make(chan error, 1)
	go func() { done <- c.Wait(context.Background()) }()

	select {
	case <-done:
		t.Fatal("Wait returned while paused")
	case <-time.After(60 * time.Millisecond):
		// still blocked, as expected
	}

	c.Resume()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait after resume returned %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after Resume")
	}
	if c.Paused() {
		t.Error("Paused() true after Resume")
	}
}

func TestStopCancelsAndUnblocksAPausedWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := NewController(cancel)
	c.Pause()

	done := make(chan error, 1)
	go func() { done <- c.Wait(ctx) }()

	// blocked while paused
	select {
	case <-done:
		t.Fatal("Wait returned before Stop")
	case <-time.After(40 * time.Millisecond):
	}

	c.Stop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Wait after Stop returned nil, want context error")
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not unblock a paused Wait")
	}
	if ctx.Err() == nil {
		t.Error("Stop did not cancel the context")
	}
	if c.Paused() {
		t.Error("Paused() true after Stop")
	}
}

func TestWaitUnblocksOnContextCancelWhilePaused(t *testing.T) {
	c := NewController(nil)
	c.Pause()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- c.Wait(ctx) }()
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Wait returned nil on cancelled ctx, want error")
		}
	case <-time.After(time.Second):
		t.Fatal("Wait did not observe ctx cancellation")
	}
}

func TestGateWaitNilIsNoOp(t *testing.T) {
	if err := GateWait(nil, context.Background()); err != nil {
		t.Errorf("GateWait(nil) = %v, want nil", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := GateWait(nil, ctx); err == nil {
		t.Error("GateWait(nil) with cancelled ctx should return the ctx error")
	}
}

func TestConcurrentPauseResumeWaitNoDeadlock(t *testing.T) {
	c := NewController(nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); c.Pause() }()
		go func() { defer wg.Done(); c.Resume() }()
		go func() { defer wg.Done(); _ = c.Wait(context.Background()) }()
	}
	// Ensure the scan can always make progress at the end.
	c.Resume()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent pause/resume/wait deadlocked")
	}
}
