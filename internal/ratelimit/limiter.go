// Package ratelimit implements in-memory login throttling.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter combines a sliding-window attempt limit per key with progressive
// lockout after repeated failures per (target) key.
type Limiter struct {
	attempts        int
	window          time.Duration
	failuresToLock  int
	lockDuration    time.Duration
	maxLockDuration time.Duration
	now             func() time.Time

	mu       sync.Mutex
	windows  map[string][]time.Time
	failures map[string]*failState
}

type failState struct {
	count       int
	lockedUntil time.Time
	locks       int
	last        time.Time
}

// New creates a limiter.
func New(attempts int, window time.Duration, failuresToLock int, lock, maxLock time.Duration) *Limiter {
	return &Limiter{
		attempts: attempts, window: window, failuresToLock: failuresToLock,
		lockDuration: lock, maxLockDuration: maxLock, now: time.Now,
		windows: map[string][]time.Time{}, failures: map[string]*failState{},
	}
}

// Allow records an attempt for actorKey and reports whether it may proceed,
// considering both actorKey's rate and targetKey's lockout. When denied it
// returns the time after which a retry may succeed.
func (l *Limiter) Allow(actorKey, targetKey string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gc(now)

	if f, ok := l.failures[targetKey]; ok && now.Before(f.lockedUntil) {
		return false, f.lockedUntil.Sub(now)
	}
	w := l.windows[actorKey]
	cut := now.Add(-l.window)
	i := 0
	for i < len(w) && !w[i].After(cut) {
		i++
	}
	w = w[i:]
	if len(w) >= l.attempts {
		l.windows[actorKey] = w
		return false, w[0].Add(l.window).Sub(now)
	}
	l.windows[actorKey] = append(w, now)
	return true, 0
}

// Failure records a failed authentication for targetKey.
func (l *Limiter) Failure(targetKey string) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.failures[targetKey]
	if f == nil {
		f = &failState{}
		l.failures[targetKey] = f
	}
	f.count++
	f.last = now
	if f.count >= l.failuresToLock {
		d := l.lockDuration << f.locks
		if d > l.maxLockDuration || d <= 0 {
			d = l.maxLockDuration
		}
		f.lockedUntil = now.Add(d)
		f.locks++
		f.count = 0
	}
}

// Success clears failure state for targetKey.
func (l *Limiter) Success(targetKey string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, targetKey)
}

func (l *Limiter) gc(now time.Time) {
	if len(l.windows)+len(l.failures) < 5000 {
		return
	}
	for k, w := range l.windows {
		if len(w) == 0 || now.Sub(w[len(w)-1]) > l.window {
			delete(l.windows, k)
		}
	}
	for k, f := range l.failures {
		if now.After(f.lockedUntil) && now.Sub(f.last) > l.maxLockDuration {
			delete(l.failures, k)
		}
	}
}
