package api

import (
	"sync"
	"time"
)

const (
	loginWindow      = 5 * time.Minute
	loginMaxAttempts = 10
	loginMaxKeys     = 10000
)

// loginLimiter is deliberately small and local. It protects the single-node
// management endpoint now; the shared Redis state layer should replace it for
// clustered deployments.
type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: make(map[string][]time.Time)}
}

func (l *loginLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-loginWindow)
	items := l.attempts[key]
	kept := items[:0]
	for _, at := range items {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	if len(kept) >= loginMaxAttempts {
		l.attempts[key] = kept
		return false
	}
	if len(l.attempts) >= loginMaxKeys {
		l.removeExpiredLocked(cutoff)
		if len(l.attempts) >= loginMaxKeys {
			// Fail closed for new keys while the table is under pressure. Existing
			// keys continue to be evaluated normally.
			if _, exists := l.attempts[key]; !exists {
				return false
			}
		}
	}
	l.attempts[key] = append(kept, now)
	return true
}

func (l *loginLimiter) removeExpiredLocked(cutoff time.Time) {
	for key, items := range l.attempts {
		if len(items) == 0 || !items[len(items)-1].After(cutoff) {
			delete(l.attempts, key)
		}
	}
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}
