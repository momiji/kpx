package utils

import (
	"context"
	"sync"
)

// ManualResetEvent notifies one or more waiting goroutines that an event has occurred.
//
// Once it has been signaled, ManualResetEvent remains signaled until it is manually reset.
// When signaled, all waiting goroutines are released, and all calls to Wait return immediately.
type ManualResetEvent struct {
	mutex   sync.RWMutex
	channel chan struct{}
}

// NewManualResetEvent returns a new ManualResetEvent with initial state s
func NewManualResetEvent(s bool) *ManualResetEvent {
	e := ManualResetEvent{
		channel: make(chan struct{}),
	}
	if s {
		close(e.channel)
	}
	return &e
}

// Signal sets the state of e to signaled, waking one or more waiting goroutines.
func (e *ManualResetEvent) Signal() {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	select {
	case <-e.channel: //ch is closed
	default:
		close(e.channel)
	}
}

// Reset sets the state of e to nonsignaled.
func (e *ManualResetEvent) Reset() {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	select {
	case <-e.channel: //ch is closed
		e.channel = make(chan struct{})
	default:
	}
}

// Wait suspends execution of the calling goroutine until e receives a signal.
func (e *ManualResetEvent) Wait() {
	e.mutex.RLock()
	c := e.channel
	e.mutex.RUnlock()
	<-c
}

// WaitContext suspends execution of the calling goroutine until e receives a signal, or until the context is cancelled.
// The returned error is nil if e received a signal, or ctx.Err()
func (e *ManualResetEvent) WaitContext(ctx context.Context) error {
	e.mutex.RLock()
	c := e.channel
	e.mutex.RUnlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c:
		return nil
	}
}

func (e *ManualResetEvent) Channel() chan struct{} {
	e.mutex.RLock()
	c := e.channel
	e.mutex.RUnlock()
	return c
}

func (e *ManualResetEvent) IsSignaled() bool {
	e.mutex.RLock()
	c := e.channel
	e.mutex.RUnlock()
	select {
	case <-c:
		return true
	default:
		return false
	}
}
