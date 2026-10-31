package api

import (
	"sync"
	"time"
)

const (
	loginMaxFailures   = 5
	loginFailureWindow = 15 * time.Minute
	loginLockout       = 15 * time.Minute
	maxLoginEntries    = 100_000
)

type loginAttempt struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

// loginLimiter is a bounded in-memory failure counter keyed by client IP and
// normalized username. It is per-replica; distributed throttling is deferred.
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginAttempt
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{entries: make(map[string]*loginAttempt)}
}

// check reports whether any key is locked and, if so, how long remains.
func (l *loginLimiter) check(now time.Time, keys ...string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var retry time.Duration
	blocked := false
	for _, key := range keys {
		entry, ok := l.entries[key]
		if !ok {
			continue
		}
		if now.Before(entry.lockedUntil) {
			remaining := entry.lockedUntil.Sub(now)
			if remaining > retry {
				retry = remaining
			}
			blocked = true
		}
	}
	return retry, blocked
}

// failure increments the failure counters; reaching the threshold locks the key.
func (l *loginLimiter) failure(now time.Time, keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.entries) >= maxLoginEntries {
		l.pruneLocked(now)
	}
	for _, key := range keys {
		entry, ok := l.entries[key]
		if !ok || now.Sub(entry.windowStart) > loginFailureWindow {
			entry = &loginAttempt{windowStart: now}
			l.entries[key] = entry
		}
		entry.failures++
		if entry.failures >= loginMaxFailures {
			entry.lockedUntil = now.Add(loginLockout)
			entry.failures = 0
			entry.windowStart = now
		}
	}
}

// success clears counters for the keys after a valid login.
func (l *loginLimiter) success(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		delete(l.entries, key)
	}
}

// pruneLocked drops stale entries so the map stays bounded.
func (l *loginLimiter) pruneLocked(now time.Time) {
	for key, entry := range l.entries {
		stale := now.Sub(entry.windowStart) > loginFailureWindow && !now.Before(entry.lockedUntil)
		if stale {
			delete(l.entries, key)
		}
	}
}
