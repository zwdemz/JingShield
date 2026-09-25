package firewallbridge

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// DryRunDriver simulates TTL and idempotence in bounded process-local state.
// It never invokes a command; a successful result is only a preview.
type DryRunDriver struct {
	mu      sync.Mutex
	entries snapshot
	now     func() time.Time
}

// NewDryRunDriver constructs an empty simulation; no host state is inspected.
func NewDryRunDriver() *DryRunDriver { return &DryRunDriver{entries: make(snapshot), now: time.Now} }

// Name identifies this driver unambiguously as a non-enforcing simulation.
func (*DryRunDriver) Name() string { return "dry-run" }

// Apply checks and previews blocks while preserving stronger existing expiry.
// Invalid batches and capacity overflow do not mutate simulated state.
func (d *DryRunDriver) Apply(ctx context.Context, blocks []Block) (ApplyResult, error) {
	if err := ctx.Err(); err != nil {
		return ApplyResult{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if err := validateBlocks(blocks, now, MaxNFTTTL); err != nil {
		return ApplyResult{}, err
	}
	for ip, expiry := range d.entries {
		if !expiry.IsZero() && !expiry.After(now) {
			delete(d.entries, ip)
		}
	}
	newEntries := 0
	for _, block := range blocks {
		if _, found := d.entries[block.IP]; !found {
			newEntries++
		}
	}
	if len(d.entries)+newEntries > 40000 {
		return ApplyResult{}, errors.New("dry-run capacity exceeded")
	}
	for _, block := range blocks {
		existing, found := d.entries[block.IP]
		if needsExtension(existing, found, block.ExpiresAt) {
			d.entries[block.IP] = block.ExpiresAt
		}
	}
	return ApplyResult{Applied: len(blocks)}, nil
}

// ClearMatching removes simulated managed blocks only; dry-run is not durable.
func (d *DryRunDriver) ClearMatching(ctx context.Context, prefixes []netip.Prefix) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	matched, err := matchingManagedIPs(d.entries, prefixes)
	if err != nil {
		return 0, err
	}
	for _, ip := range matched {
		delete(d.entries, ip)
	}
	return len(matched), nil
}
