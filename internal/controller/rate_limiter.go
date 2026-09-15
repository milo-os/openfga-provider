package controller

import (
	"math/rand"
	"time"

	"k8s.io/client-go/util/workqueue"
)

// jitteredRateLimiter wraps the default per-item exponential backoff with
// +/-50% random jitter. A bulk burst of objects (e.g. fixture/perf load) that
// fail together retries in lockstep under the unjittered default: identical
// failure counts produce identical delays, so the whole batch piles back onto
// OpenFGA at the same instant on every retry cycle, reproducing the
// contention that caused the failures. Jitter spreads a synchronized batch's
// retries out over time instead.
type jitteredRateLimiter[T comparable] struct {
	workqueue.TypedRateLimiter[T]
}

func (r *jitteredRateLimiter[T]) When(item T) time.Duration {
	d := r.TypedRateLimiter.When(item)
	if d <= 0 {
		return d
	}
	return d/2 + time.Duration(rand.Int63n(int64(d)))
}

func newJitteredRateLimiter[T comparable]() workqueue.TypedRateLimiter[T] {
	return &jitteredRateLimiter[T]{TypedRateLimiter: workqueue.DefaultTypedControllerRateLimiter[T]()}
}

// enablePriorityQueue turns on controller-runtime's priority queue, which gives
// events from the initial list-watch and from resyncs a lower priority than
// genuine changes. Without it an object created while a controller is still
// draining its startup backlog waits behind every synced item; with it, real
// changes are reconciled first regardless of how long the backlog takes.
//
// The priority queue is still beta in controller-runtime.
func enablePriorityQueue() *bool {
	enabled := true
	return &enabled
}
