package utils

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestNewManualResetEvent_InitialStateNonSignaled(t *testing.T) {
	e := NewManualResetEvent(false)
	if e.IsSignaled() {
		t.Fatal("expected non-signaled initial state")
	}
}

func TestNewManualResetEvent_InitialStateSignaled(t *testing.T) {
	e := NewManualResetEvent(true)
	if !e.IsSignaled() {
		t.Fatal("expected signaled initial state")
	}
}

func TestSignal_TransitionsToSignaled(t *testing.T) {
	e := NewManualResetEvent(false)
	e.Signal()
	if !e.IsSignaled() {
		t.Fatal("expected signaled after Signal()")
	}
}

func TestSignal_IsIdempotent(t *testing.T) {
	e := NewManualResetEvent(false)
	e.Signal()
	e.Signal() // must not panic (double-close)
	if !e.IsSignaled() {
		t.Fatal("expected still signaled after double Signal()")
	}
}

func TestReset_TransitionsToNonSignaled(t *testing.T) {
	e := NewManualResetEvent(true)
	e.Reset()
	if e.IsSignaled() {
		t.Fatal("expected non-signaled after Reset()")
	}
}

func TestReset_IsIdempotent(t *testing.T) {
	e := NewManualResetEvent(false)
	e.Reset()
	e.Reset()
	if e.IsSignaled() {
		t.Fatal("expected still non-signaled after double Reset()")
	}
}

func TestSignalThenReset(t *testing.T) {
	e := NewManualResetEvent(false)
	e.Signal()
	e.Reset()
	if e.IsSignaled() {
		t.Fatal("expected non-signaled after Signal then Reset")
	}
}

func TestWait_ReturnsImmediatelyWhenAlreadySignaled(t *testing.T) {
	e := NewManualResetEvent(true)
	done := make(chan struct{})
	go func() {
		e.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Wait() blocked on already-signaled event")
	}
}

func TestWait_UnblocksAfterSignal(t *testing.T) {
	e := NewManualResetEvent(false)
	done := make(chan struct{})
	go func() {
		e.Wait()
		close(done)
	}()
	// goroutine must be blocked
	select {
	case <-done:
		t.Fatal("Wait() returned before Signal()")
	case <-time.After(50 * time.Millisecond):
	}
	e.Signal()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Wait() did not unblock after Signal()")
	}
}

func TestWait_BlocksAgainAfterReset(t *testing.T) {
	e := NewManualResetEvent(true)
	e.Reset()
	done := make(chan struct{})
	go func() {
		e.Wait()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Wait() returned on non-signaled event after Reset()")
	case <-time.After(50 * time.Millisecond):
	}
	e.Signal()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Wait() did not unblock after re-Signal()")
	}
}

func TestWait_MultipleWaitersAllUnblock(t *testing.T) {
	e := NewManualResetEvent(false)
	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			e.Wait()
			wg.Done()
		}()
	}
	time.Sleep(20 * time.Millisecond)
	e.Signal()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("not all waiters unblocked after Signal()")
	}
}

func TestWaitContext_ReturnsNilOnSignal(t *testing.T) {
	e := NewManualResetEvent(false)
	ctx := context.Background()
	go func() {
		time.Sleep(20 * time.Millisecond)
		e.Signal()
	}()
	if err := e.WaitContext(ctx); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestWaitContext_ReturnsErrOnCancellation(t *testing.T) {
	e := NewManualResetEvent(false)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err := e.WaitContext(ctx)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestWaitContext_ReturnsErrOnDeadline(t *testing.T) {
	e := NewManualResetEvent(false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := e.WaitContext(ctx)
	if err != context.DeadlineExceeded {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestChannel_ClosedWhenSignaled(t *testing.T) {
	e := NewManualResetEvent(false)
	c := e.Channel()
	e.Signal()
	select {
	case <-c:
	case <-time.After(time.Second):
		t.Fatal("Channel() not closed after Signal()")
	}
}

func TestChannel_SnapshotBecomesStaleAfterReset(t *testing.T) {
	e := NewManualResetEvent(false)
	// Signal → take snapshot of the closed channel → Reset replaces it.
	e.Signal()
	c := e.Channel() // c = closed channel A
	e.Reset()        // e.c = new open channel B; c is now stale
	// c (channel A) is already closed — reading from it returns immediately.
	select {
	case <-c:
	default:
		t.Fatal("stale channel from before Reset should still be readable (it was closed)")
	}
	// The live channel is now open again.
	if e.IsSignaled() {
		t.Fatal("event should be non-signaled after Reset")
	}
}

func TestConcurrent_SignalResetRace(t *testing.T) {
	// Run with -race to catch data races.
	e := NewManualResetEvent(false)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for range 100 {
			e.Signal()
		}
	}()
	go func() {
		defer wg.Done()
		for range 100 {
			e.Reset()
		}
	}()
	go func() {
		defer wg.Done()
		for range 100 {
			e.IsSignaled()
		}
	}()
	wg.Wait()
}

func TestConcurrent_WaitAndReset(t *testing.T) {
	e := NewManualResetEvent(false)
	var wg sync.WaitGroup
	const n = 5
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			_ = e.WaitContext(ctx)
		}()
	}
	go func() {
		for range 20 {
			e.Signal()
			time.Sleep(5 * time.Millisecond)
			e.Reset()
			time.Sleep(5 * time.Millisecond)
		}
		e.Signal()
	}()
	wg.Wait()
}
