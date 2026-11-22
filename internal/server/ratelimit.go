package server

import (
	"sync"
	"time"
)

// failureLimiter counts failures per key in a fixed window.
type failureLimiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	buckets map[string]*bucket
}

type bucket struct {
	count int
	reset time.Time
}

func newFailureLimiter(max int, window time.Duration) *failureLimiter {
	return &failureLimiter{max: max, window: window, buckets: map[string]*bucket{}}
}

// Allowed reports whether the key has not yet reached the failure limit.
func (l *failureLimiter) Allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok || time.Now().After(b.reset) {
		return true
	}
	return b.count < l.max
}

// Fail records a failure for the key.
func (l *failureLimiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[key]
	if !ok || now.After(b.reset) {
		b = &bucket{reset: now.Add(l.window)}
		l.buckets[key] = b
	}
	b.count++
}

// Cleanup drops expired buckets.
func (l *failureLimiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, b := range l.buckets {
		if now.After(b.reset) {
			delete(l.buckets, k)
		}
	}
}
