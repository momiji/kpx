package kpx

import "sync/atomic"

// NewAtomicInt creates an AtomicInt with given default value
func NewAtomicInt(val int32) *AtomicInt {
	ab := new(AtomicInt)
	if val != 0 {
		ab.Set(val)
	}
	return ab
}

// AtomicInt is an atomic Integer
// Its methods are all atomic, thus safe to be called by
// multiple goroutines simultaneously
// Note: When embedding into a struct, one should always use
// *AtomicInt to avoid copy
type AtomicInt int32

// Set sets the Integer to value
func (ab *AtomicInt) Set(val int32) {
	atomic.StoreInt32((*int32)(ab), val)
}

// IsSet returns whether the Boolean is true
func (ab *AtomicInt) Get() int32 {
	return atomic.LoadInt32((*int32)(ab))
}

func (ab *AtomicInt) IncrementAndGet(delta int32) int32 {
	return atomic.AddInt32((*int32)(ab), delta)
}

func (ab *AtomicInt) DecrementAndGet(delta int32) int32 {
	return atomic.AddInt32((*int32)(ab), -delta)
}
