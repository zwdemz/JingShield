package firewallbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// NFTDriver updates only marked, pre-existing JingShield IPv4/IPv6 sets.
// Each update is a single nft transaction followed by a fresh kernel readback.
type NFTDriver struct {
	mu     sync.Mutex
	runner Runner
	now    func() time.Time
}

// NewNFTDriver creates an enforcing driver; callers must explicitly opt into
// apply mode. A nil runner selects the constrained Linux command runner.
func NewNFTDriver(runner Runner) *NFTDriver {
	if runner == nil {
		runner = commandRunner{}
	}
	return &NFTDriver{runner: runner, now: time.Now}
}

// Name identifies the native backend without implying a successful deployment.
func (*NFTDriver) Name() string { return "nftables" }

// Apply validates the batch, preserves stronger kernel deadlines, checks a
// generated transaction and verifies membership after applying it. Unconfirmed
// outcomes return an error and Partial=true; unrelated tables are never touched.
func (d *NFTDriver) Apply(ctx context.Context, blocks []Block) (ApplyResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if err := validateBlocks(blocks, now, MaxNFTTTL); err != nil {
		return ApplyResult{}, err
	}
	before, err := d.read(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	var script strings.Builder
	for _, block := range blocks {
		old, exists := before[block.IP]
		if !needsExtension(old, exists, block.ExpiresAt) {
			continue
		}
		set := setFor(block.IP)
		if exists {
			// Add+delete in the same transaction tolerates natural expiry between
			// snapshot and commit; no intermediate state is visible to packets.
			fmt.Fprintf(&script, "add element inet %s %s { %s }\n", ManagedTable, set, block.IP)
			fmt.Fprintf(&script, "delete element inet %s %s { %s }\n", ManagedTable, set, block.IP)
		}
		fmt.Fprintf(&script, "add element inet %s %s { %s", ManagedTable, set, block.IP)
		if !block.ExpiresAt.IsZero() {
			fmt.Fprintf(&script, " timeout %ds", remainingSeconds(block.ExpiresAt, now))
		}
		script.WriteString(" }\n")
	}
	if script.Len() == 0 {
		return ApplyResult{Applied: len(blocks)}, nil
	}
	input := []byte(script.String())
	if _, err = d.runner.Run(ctx, "/usr/sbin/nft", []string{"-c", "-f", "-"}, input); err != nil {
		return ApplyResult{}, errors.New("nftables transaction check failed; no changes applied")
	}
	_, applyErr := d.runner.Run(ctx, "/usr/sbin/nft", []string{"-f", "-"}, input)
	after, readErr := d.read(ctx)
	if readErr != nil {
		return ApplyResult{Partial: true}, errors.New("nftables readback failed; resulting state is unconfirmed")
	}
	confirmed := confirmedCount(blocks, after)
	if confirmed == len(blocks) {
		return ApplyResult{Applied: confirmed}, nil
	}
	if applyErr != nil {
		return ApplyResult{Applied: confirmed, Partial: confirmed > 0}, errors.New("nftables transaction failed; batch not fully confirmed")
	}
	return ApplyResult{Applied: confirmed, Partial: true}, errors.New("nftables kernel membership differs from requested state")
}

// ClearMatching atomically deletes only managed entries covered by the
// received allowlist and confirms their absence in a fresh kernel readback.
func (d *NFTDriver) ClearMatching(ctx context.Context, prefixes []netip.Prefix) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	before, err := d.read(ctx)
	if err != nil {
		return 0, err
	}
	matched, err := matchingManagedIPs(before, prefixes)
	if err != nil || len(matched) == 0 {
		return 0, err
	}
	var script strings.Builder
	for _, ip := range matched {
		fmt.Fprintf(&script, "delete element inet %s %s { %s }\n", ManagedTable, setFor(ip), ip)
	}
	input := []byte(script.String())
	if _, err := d.runner.Run(ctx, "/usr/sbin/nft", []string{"-c", "-f", "-"}, input); err != nil {
		return 0, errors.New("nftables 白名单清理事务校验失败")
	}
	_, applyErr := d.runner.Run(ctx, "/usr/sbin/nft", []string{"-f", "-"}, input)
	after, readErr := d.read(ctx)
	if readErr != nil {
		return 0, errors.New("nftables 白名单清理读回失败，结果未确认")
	}
	for _, ip := range matched {
		if _, stillBlocked := after[ip]; stillBlocked {
			return 0, errors.New("nftables 白名单覆盖地址仍在专属封禁集合中")
		}
	}
	if applyErr != nil {
		return 0, errors.New("nftables 清理结果不确定，请核对专属集合")
	}
	return len(matched), nil
}

func (d *NFTDriver) read(ctx context.Context) (snapshot, error) {
	result := make(snapshot)
	for _, set := range []string{ManagedIPv4Set, ManagedIPv6Set} {
		output, err := d.runner.Run(ctx, "/usr/sbin/nft", []string{"-j", "list", "set", "inet", ManagedTable, set}, nil)
		if err != nil {
			return nil, errors.New("managed nftables set unavailable; initialize it manually")
		}
		entries, err := parseNFTSet(output, set, d.now())
		if err != nil {
			return nil, err
		}
		for ip, expiry := range entries {
			result[ip] = expiry
		}
	}
	return result, nil
}

// parseNFTSet verifies ownership, family and timeout support before consuming a
// bounded exact-IP snapshot. Upstream nft JSON timeout/expires fields use seconds,
// unlike the internal millisecond representation; unsupported shapes fail closed.
func parseNFTSet(raw []byte, name string, now time.Time) (snapshot, error) {
	var document struct {
		NFTables []struct {
			Set *struct {
				Family   string          `json:"family"`
				Table    string          `json:"table"`
				Name     string          `json:"name"`
				Type     string          `json:"type"`
				Comment  string          `json:"comment"`
				Flags    json.RawMessage `json:"flags"`
				Timeout  int64           `json:"timeout"`
				Elements json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if json.Unmarshal(raw, &document) != nil {
		return nil, errors.New("invalid nftables JSON snapshot")
	}
	for _, object := range document.NFTables {
		set := object.Set
		if set == nil {
			continue
		}
		expectedType := "ipv4_addr"
		if name == ManagedIPv6Set {
			expectedType = "ipv6_addr"
		}
		if set.Family != "inet" || set.Table != ManagedTable || set.Name != name || set.Type != expectedType || set.Comment != ManagedMarker || set.Timeout != 0 {
			return nil, errors.New("nftables set ownership/type/default timeout mismatch")
		}
		flags, err := rawList(set.Flags)
		if err != nil {
			return nil, err
		}
		hasTimeout := false
		for _, flag := range flags {
			var value string
			if json.Unmarshal(flag, &value) != nil || value != "timeout" {
				return nil, errors.New("unsupported nftables set flag")
			}
			hasTimeout = true
		}
		if !hasTimeout {
			return nil, errors.New("nftables set requires timeout support")
		}
		entries, err := rawList(set.Elements)
		if err != nil {
			return nil, err
		}
		if len(entries) > 20000 {
			return nil, errors.New("nftables set exceeds adapter snapshot bound")
		}
		result := make(snapshot)
		for _, entry := range entries {
			var address string
			var expiry time.Time
			if json.Unmarshal(entry, &address) != nil {
				var value struct {
					Element *struct {
						Value   string `json:"val"`
						Timeout int64  `json:"timeout"`
						Expires *int64 `json:"expires"`
					} `json:"elem"`
				}
				if json.Unmarshal(entry, &value) != nil || value.Element == nil || value.Element.Timeout < 0 {
					return nil, errors.New("unsupported nftables element")
				}
				address = value.Element.Value
				if value.Element.Expires != nil {
					seconds := *value.Element.Expires
					if seconds < 0 || seconds > MaxNFTTTL {
						return nil, errors.New("invalid nftables expiry")
					}
					expiry = now.Add(time.Duration(seconds+1) * time.Second)
				} else if value.Element.Timeout > 0 {
					return nil, errors.New("nftables timed element has no remaining expiry")
				}
			}
			ip, err := netip.ParseAddr(address)
			if err != nil || ip.Zone() != "" || (name == ManagedIPv4Set) != ip.Is4() {
				return nil, errors.New("nftables element address mismatch")
			}
			result[ip] = expiry
		}
		return result, nil
	}
	return nil, errors.New("managed nftables set missing from snapshot")
}

func rawList(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	if raw[0] == '[' {
		var list []json.RawMessage
		err := json.Unmarshal(raw, &list)
		return list, err
	}
	return []json.RawMessage{raw}, nil
}

func confirmedCount(blocks []Block, current snapshot) int {
	confirmed := 0
	for _, block := range blocks {
		expiry, found := current[block.IP]
		if found && !needsExtension(expiry, true, block.ExpiresAt) {
			confirmed++
		}
	}
	return confirmed
}
