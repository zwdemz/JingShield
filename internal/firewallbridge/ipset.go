package firewallbridge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IPSetDriver manages only two pre-provisioned hash:ip sets. Unlike nftables,
// ipset restore is not assumed atomic; failed batches receive bounded rollback.
type IPSetDriver struct {
	mu     sync.Mutex
	runner Runner
	now    func() time.Time
}

// NewIPSetDriver constructs an opt-in enforcing driver with an injectable runner.
func NewIPSetDriver(runner Runner) *IPSetDriver {
	if runner == nil {
		runner = commandRunner{}
	}
	return &IPSetDriver{runner: runner, now: time.Now}
}

// Name identifies the ipset backend; it does not imply rule/hook validation.
func (*IPSetDriver) Name() string { return "ipset" }

// Apply preserves permanent/later deadlines, applies one bounded restore batch
// and verifies both sets. Failure attempts to restore only this batch's touched
// entries; an incomplete rollback is returned as Partial, never success.
func (d *IPSetDriver) Apply(ctx context.Context, blocks []Block) (ApplyResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if err := validateBlocks(blocks, now, MaxIPSetTTL); err != nil {
		return ApplyResult{}, err
	}
	before, err := d.read(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	changes := []Block{}
	var script strings.Builder
	for _, block := range blocks {
		old, exists := before[block.IP]
		if !needsExtension(old, exists, block.ExpiresAt) {
			continue
		}
		changes = append(changes, block)
		writeIPSetAdd(&script, block.IP, block.ExpiresAt, now)
	}
	if len(changes) == 0 {
		return ApplyResult{Applied: len(blocks)}, nil
	}
	_, applyErr := d.runner.Run(ctx, "/usr/sbin/ipset", []string{"-exist", "restore"}, []byte(script.String()))
	after, readErr := d.read(ctx)
	if readErr == nil && confirmedCount(blocks, after) == len(blocks) {
		return ApplyResult{Applied: len(blocks)}, nil
	}
	// Rollback has its own short deadline because cancellation can occur after
	// ipset applied a prefix. Only dedicated entries touched by this call change.
	rollbackContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	script.Reset()
	for _, block := range changes {
		expiry, found := before[block.IP]
		if !found || (!expiry.IsZero() && !expiry.After(d.now())) {
			fmt.Fprintf(&script, "del %s %s\n", setFor(block.IP), block.IP)
		} else {
			writeIPSetAdd(&script, block.IP, expiry, d.now())
		}
	}
	_, rollbackErr := d.runner.Run(rollbackContext, "/usr/sbin/ipset", []string{"-exist", "restore"}, []byte(script.String()))
	restored, verifyErr := d.read(rollbackContext)
	partial := rollbackErr != nil || verifyErr != nil
	if !partial {
		for _, block := range changes {
			original, wasPresent := before[block.IP]
			current, present := restored[block.IP]
			if !wasPresent {
				if present {
					partial = true
				}
			} else if original.IsZero() {
				if !present || !current.IsZero() {
					partial = true
				}
			} else if original.After(d.now()) {
				if !present || current.IsZero() || current.Before(original.Add(-time.Second)) || current.After(original.Add(3*time.Second)) {
					partial = true
				}
			}
		}
	}
	confirmed := 0
	if verifyErr == nil {
		confirmed = confirmedCount(blocks, restored)
	}
	if partial {
		return ApplyResult{Applied: confirmed, Partial: true}, errors.New("ipset batch failed and rollback is incomplete; inspect dedicated sets")
	}
	_ = applyErr
	return ApplyResult{Applied: confirmed}, errors.New("ipset batch was not confirmed and touched entries were restored")
}

// ClearMatching deletes only managed ipset members covered by the allowlist.
// ipset restore is not atomic: a failed command is reported as unconfirmed.
func (d *IPSetDriver) ClearMatching(ctx context.Context, prefixes []netip.Prefix) (int, error) {
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
		fmt.Fprintf(&script, "del %s %s\n", setFor(ip), ip)
	}
	_, applyErr := d.runner.Run(ctx, "/usr/sbin/ipset", []string{"-exist", "restore"}, []byte(script.String()))
	after, readErr := d.read(ctx)
	if readErr != nil {
		return 0, errors.New("ipset 白名单清理读回失败，结果未确认")
	}
	for _, ip := range matched {
		if _, stillBlocked := after[ip]; stillBlocked {
			return 0, errors.New("ipset 白名单覆盖地址仍在专属封禁集合中")
		}
	}
	if applyErr != nil {
		return 0, errors.New("ipset 清理结果不确定，请核对专属集合")
	}
	return len(matched), nil
}

func writeIPSetAdd(script *strings.Builder, ip netip.Addr, expiry, now time.Time) {
	fmt.Fprintf(script, "add %s %s timeout %d\n", setFor(ip), ip, remainingSeconds(expiry, now))
}

func (d *IPSetDriver) read(ctx context.Context) (snapshot, error) {
	result := make(snapshot)
	for _, set := range []string{ManagedIPv4Set, ManagedIPv6Set} {
		output, err := d.runner.Run(ctx, "/usr/sbin/ipset", []string{"save", set}, nil)
		if err != nil {
			return nil, errors.New("managed ipset unavailable; initialize it manually")
		}
		entries, err := parseIPSet(output, set, d.now())
		if err != nil {
			return nil, err
		}
		for ip, expiry := range entries {
			result[ip] = expiry
		}
	}
	return result, nil
}

// parseIPSet accepts only exact-IP dedicated sets with permanent defaults.
// Eviction and address-mask options fail closed because they can silently evict
// prior blocks or expand one requested host into a broader network rule.
func parseIPSet(raw []byte, name string, now time.Time) (snapshot, error) {
	result := make(snapshot)
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 4096), 65536)
	header := false
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 3 || fields[1] != name {
			return nil, errors.New("unexpected ipset snapshot record")
		}
		switch fields[0] {
		case "create":
			if header || fields[2] != "hash:ip" {
				return nil, errors.New("ipset must be dedicated hash:ip")
			}
			header = true
			family := ""
			timeout := ""
			for index := 3; index < len(fields); index++ {
				if fields[index] == "forceadd" || fields[index] == "netmask" || fields[index] == "bitmask" {
					return nil, errors.New("ipset eviction/address-masking options are not supported")
				}
				if fields[index] == "family" || fields[index] == "timeout" {
					if index+1 >= len(fields) {
						return nil, errors.New("invalid ipset header")
					}
					if fields[index] == "family" {
						family = fields[index+1]
					} else {
						timeout = fields[index+1]
					}
					index++
				}
			}
			expected := "inet"
			if name == ManagedIPv6Set {
				expected = "inet6"
			}
			if family != expected || timeout != "0" {
				return nil, errors.New("ipset family/default timeout mismatch")
			}
		case "add":
			if !header || len(result) >= 20000 {
				return nil, errors.New("ipset header missing or snapshot too large")
			}
			ip, err := netip.ParseAddr(fields[2])
			if err != nil || ip.Zone() != "" || (name == ManagedIPv4Set) != ip.Is4() {
				return nil, errors.New("ipset element address mismatch")
			}
			var expiry time.Time
			for index := 3; index < len(fields); index++ {
				if fields[index] == "timeout" {
					if index+1 >= len(fields) {
						return nil, errors.New("invalid ipset timeout")
					}
					seconds, err := strconv.ParseInt(fields[index+1], 10, 64)
					if err != nil || seconds < 0 || seconds > MaxIPSetTTL {
						return nil, errors.New("invalid ipset timeout")
					}
					if seconds > 0 {
						expiry = now.Add(time.Duration(seconds+1) * time.Second)
					}
					index++
				}
			}
			result[ip] = expiry
		default:
			return nil, errors.New("unsupported ipset snapshot command")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !header {
		return nil, errors.New("managed ipset missing")
	}
	return result, nil
}
