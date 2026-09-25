package memory

import (
	"context"
	"sync"
	"time"

	"jingshield/internal/store"
)

const maxBehaviorScopes = 16384
const maxBehaviorEvents = 131072

type behaviorEvent struct {
	at       time.Time
	category string
}

type behaviorEntry struct {
	events    []behaviorEvent
	blockedTo time.Time
	expiresAt time.Time
}

type behaviorMemory struct {
	mu      sync.Mutex
	entries map[string]*behaviorEntry
	events  int
	calls   uint64
	now     func() time.Time
}

// ObserveBehavior atomically records a scoped probe and evaluates its sliding window.
// Empty categories only read an existing block. Repeated blocked requests never
// extend its expiry; observe-only traffic never creates or enforces a block.
// Cancellation, invalid inputs and bounded-capacity exhaustion return errors.
func (s *Store) ObserveBehavior(ctx context.Context, scope, category string, scannerClient bool, policy store.BehaviorPolicy, enforce bool) (store.BehaviorSnapshot, error) {
	var snapshot store.BehaviorSnapshot
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	if err := store.ValidateBehaviorInput(scope, category, policy); err != nil {
		return snapshot, err
	}
	state := &s.behavior
	state.mu.Lock()
	defer state.mu.Unlock()
	now := time.Now()
	if state.now != nil {
		now = state.now()
	}
	state.calls++
	if state.calls%256 == 0 {
		state.gc(now)
	}
	entry := state.entries[scope]
	if entry != nil && !entry.expiresAt.After(now) {
		state.events -= len(entry.events)
		delete(state.entries, scope)
		entry = nil
	}
	if entry == nil {
		if category == "" {
			return snapshot, nil
		}
		if len(state.entries) >= maxBehaviorScopes {
			state.gc(now)
			if len(state.entries) >= maxBehaviorScopes {
				return snapshot, store.ErrBehaviorCapacity
			}
		}
		if state.entries == nil {
			state.entries = make(map[string]*behaviorEntry)
		}
		entry = &behaviorEntry{expiresAt: now.Add(time.Duration(policy.WindowSeconds) * time.Second)}
		state.entries[scope] = entry
	}
	if enforce && entry.blockedTo.After(now) {
		return store.BehaviorSnapshot{Matched: true, Blocked: true, BlockRemainingSeconds: int((entry.blockedTo.Sub(now) + time.Second - 1) / time.Second)}, nil
	}
	if category == "" {
		return snapshot, nil
	}
	cutoff := now.Add(-time.Duration(policy.WindowSeconds) * time.Second)
	before := len(entry.events)
	kept := entry.events[:0]
	for _, event := range entry.events {
		if event.at.After(cutoff) {
			kept = append(kept, event)
		}
	}
	// Saturating at twice the threshold preserves every possible decision while
	// bounding state even for a sustained probe flood in observation mode.
	if len(kept) >= 2*policy.Threshold {
		kept = kept[len(kept)-2*policy.Threshold+1:]
	}
	state.events -= before - len(kept)
	entry.events = kept
	if state.events >= maxBehaviorEvents {
		state.gc(now)
		if state.events >= maxBehaviorEvents {
			return snapshot, store.ErrBehaviorCapacity
		}
	}
	entry.events = append(entry.events, behaviorEvent{at: now, category: category})
	state.events++
	entry.expiresAt = now.Add(time.Duration(policy.WindowSeconds) * time.Second)
	if entry.blockedTo.After(entry.expiresAt) {
		entry.expiresAt = entry.blockedTo
	}
	seen := make(map[string]struct{}, 4)
	for _, event := range entry.events {
		seen[event.category] = struct{}{}
	}
	snapshot.Hits = len(entry.events)
	snapshot.DistinctCategories = len(seen)
	snapshot.Matched = snapshot.Hits >= policy.Threshold && (snapshot.DistinctCategories >= 2 || scannerClient || snapshot.Hits >= 2*policy.Threshold)
	if snapshot.Matched && enforce {
		entry.blockedTo = now.Add(time.Duration(policy.BlockSeconds) * time.Second)
		entry.expiresAt = entry.blockedTo
		// A completed penalty starts a fresh window, rather than re-blocking
		// immediately using the same probes when block TTL is shorter than window.
		state.events -= len(entry.events)
		entry.events = nil
		snapshot.Blocked = true
		snapshot.BlockRemainingSeconds = policy.BlockSeconds
	}
	return snapshot, nil
}

func (s *behaviorMemory) gc(now time.Time) {
	for scope, entry := range s.entries {
		if !entry.expiresAt.After(now) {
			s.events -= len(entry.events)
			delete(s.entries, scope)
		}
	}
}

func (s *Store) clearBehavior() {
	s.behavior.mu.Lock()
	defer s.behavior.mu.Unlock()
	s.behavior.entries = nil
	s.behavior.events = 0
}
