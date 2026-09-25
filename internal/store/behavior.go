package store

import (
	"context"
	"errors"
)

// ErrBehaviorCapacity reports a bounded in-memory behavior-state budget exhaustion.
var ErrBehaviorCapacity = errors.New("behavior state capacity exceeded")

// BehaviorPolicy defines the sliding probe window, trigger count and fixed block TTL.
// Durations are seconds; invalid policies are rejected without changing state.
type BehaviorPolicy struct {
	WindowSeconds int
	Threshold     int
	BlockSeconds  int
}

// Validate checks the supported limits before storage allocates state.
// It returns an error for out-of-range windows, counts or block durations.
func (p BehaviorPolicy) Validate() error {
	if p.WindowSeconds < 10 || p.WindowSeconds > 3600 || p.Threshold < 2 || p.Threshold > 1000 || p.BlockSeconds < 10 || p.BlockSeconds > 86400 {
		return errors.New("invalid behavior policy")
	}
	return nil
}

// BehaviorSnapshot is the atomically computed probe decision for one host and IP.
// A matched observation need not be blocked when enforcement is disabled.
type BehaviorSnapshot struct {
	Hits                  int
	DistinctCategories    int
	Matched               bool
	Blocked               bool
	BlockRemainingSeconds int
}

// BehaviorStore optionally augments StateStore with shared, atomic behavior decisions.
// category is empty for normal traffic or one of four bounded probe categories;
// scannerClient corroborates a sensitive probe, never normal traffic. Enforcement
// uses a fixed non-renewing block TTL. Storage errors must not produce a block.
type BehaviorStore interface {
	ObserveBehavior(ctx context.Context, scope, category string, scannerClient bool, policy BehaviorPolicy, enforce bool) (BehaviorSnapshot, error)
}

// ValidateBehaviorInput rejects unbounded category names and empty/oversized scopes.
// Callers must hash host/IP before constructing the bounded scope identifier.
func ValidateBehaviorInput(scope, category string, policy BehaviorPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	if scope == "" || len(scope) > 128 {
		return errors.New("invalid behavior scope")
	}
	switch category {
	case "", "secrets", "repository", "diagnostics", "control-plane":
		return nil
	default:
		return errors.New("invalid behavior category")
	}
}
