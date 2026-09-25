// Package firewallbridge implements a narrowly scoped, authenticated adapter
// for pre-provisioned Linux firewall sets. It never manages unrelated rules.
package firewallbridge

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

const Protocol = "jingshield-v1"
const MaxBatchSize = 500
const MaxIPSetTTL = 2147483
const MaxNFTTTL = 31536000
const ManagedTable = "jingshield"
const ManagedIPv4Set = "jingshield_blocked_v4"
const ManagedIPv6Set = "jingshield_blocked_v6"
const ManagedMarker = "jingshield-managed-v1"

// Block is a normalized exact IP with an absolute deadline; zero is permanent.
type Block struct {
	IP        netip.Addr
	ExpiresAt time.Time
}

// ApplyResult distinguishes confirmed entries from partially applied changes.
// Applied counts entries protected at least until the requested deadline.
type ApplyResult struct {
	Applied int  `json:"applied"`
	Partial bool `json:"partial"`
}

// Driver enforces a bounded batch or returns an explicit failure/partial result.
// Implementations must preserve existing permanent or later-expiring blocks.
type Driver interface {
	Name() string
	Apply(context.Context, []Block) (ApplyResult, error)
}

// WhitelistCleaner removes only previously managed blocks covered by a newly
// accepted whitelist. It never changes unrelated rules or packet filters.
type WhitelistCleaner interface {
	ClearMatching(context.Context, []netip.Prefix) (int, error)
}

func matchingManagedIPs(current snapshot, prefixes []netip.Prefix) ([]netip.Addr, error) {
	matched := make([]netip.Addr, 0)
	for ip := range current {
		for _, prefix := range prefixes {
			if prefix.Contains(ip) {
				matched = append(matched, ip)
				break
			}
		}
	}
	if len(matched) > MaxBatchSize {
		return nil, errors.New("白名单命中超过 500 个已封禁地址，请分批人工核查")
	}
	return matched, nil
}

// Runner permits deterministic CLI tests. Production execution always uses
// fixed executable paths and an argv slice, never a shell command string.
type Runner interface {
	Run(context.Context, string, []string, []byte) ([]byte, error)
}

type snapshot map[netip.Addr]time.Time

// validateBlocks is the driver boundary for normalized exact addresses and
// supported deadlines, rejecting special ranges and duplicates before any CLI.
func validateBlocks(blocks []Block, now time.Time, maxTTL int) error {
	if len(blocks) > MaxBatchSize {
		return errors.New("batch exceeds 500 IPs")
	}
	seen := map[netip.Addr]bool{}
	for _, block := range blocks {
		ip := block.IP.Unmap()
		if !ip.IsValid() || ip != block.IP || seen[ip] || ip.Zone() != "" || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			return errors.New("unsafe block address")
		}
		seen[ip] = true
		if !block.ExpiresAt.IsZero() && (block.ExpiresAt.Before(now) || block.ExpiresAt.After(now.Add(time.Duration(maxTTL)*time.Second))) {
			return errors.New("unsupported expiry")
		}
	}
	return nil
}

func needsExtension(existing time.Time, found bool, requested time.Time) bool {
	if !found {
		return true
	}
	if existing.IsZero() {
		return false
	}
	return requested.IsZero() || requested.After(existing)
}

func setFor(ip netip.Addr) string {
	if ip.Is4() {
		return ManagedIPv4Set
	}
	return ManagedIPv6Set
}

func remainingSeconds(deadline, now time.Time) int64 {
	if deadline.IsZero() {
		return 0
	}
	seconds := int64((deadline.Sub(now) + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}
