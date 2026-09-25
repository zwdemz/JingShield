package iputil

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// MaxBlockBatch bounds submitted entries before deduplication.
const MaxBlockBatch = 500

// NormalizeBlockIPs accepts only individual unicast IPv4/IPv6 addresses. It
// rejects empty/oversized batches and CIDRs, normalizes mapped IPv4 and dedupes.
func NormalizeBlockIPs(input []string) ([]string, error) {
	if len(input) == 0 || len(input) > MaxBlockBatch {
		return nil, errors.New("每次须提交 1-500 个 IP，重复项也计入提交上限")
	}
	result := make([]string, 0, len(input))
	seen := make(map[string]bool, len(input))
	for index, raw := range input {
		address, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("第 %d 项不是可封禁的独立 IPv4/IPv6 地址", index+1)
		}
		value := address.Unmap().String()
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result, nil
}

// ValidBlockReason rejects missing reasons, oversized metadata and log controls.
func ValidBlockReason(reason string) bool {
	if strings.ContainsAny(reason, "\r\n\x00") {
		return false
	}
	reason = strings.TrimSpace(reason)
	return len(reason) > 0 && len(reason) <= 255 && !strings.ContainsAny(reason, "\r\n\x00")
}
