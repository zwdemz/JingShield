package iputil

import (
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// MaxWhitelistSync is the maximum number of submitted rules in one snapshot.
const MaxWhitelistSync = 500

// NormalizeWhitelistRules validates a complete, bounded whitelist snapshot.
// Contiguous IPv4 suffix wildcards are converted to CIDR so WAF and Linux
// bridge receive identical semantics; irregular wildcards fail the whole batch.
func NormalizeWhitelistRules(input []string) ([]string, error) {
	if len(input) > MaxWhitelistSync {
		return nil, errors.New("白名单快照单次最多 500 条规则")
	}
	seen := make(map[string]struct{}, len(input))
	for _, raw := range input {
		if raw == "" || raw != strings.TrimSpace(raw) || len(raw) > 64 || strings.ContainsAny(raw, "\r\n\x00") {
			return nil, errors.New("白名单规则包含非法字符或长度超限")
		}
		value := raw
		if strings.Contains(value, "*") {
			parts := strings.Split(value, ".")
			if len(parts) != 4 {
				return nil, errors.New("仅支持 IPv4 后缀通配符")
			}
			firstWildcard := -1
			for index, part := range parts {
				if part == "*" {
					if firstWildcard == -1 {
						firstWildcard = index
					}
					parts[index] = "0"
					continue
				}
				if firstWildcard != -1 {
					return nil, errors.New("仅支持连续的 IPv4 后缀通配符")
				}
				number, err := strconv.Atoi(part)
				if err != nil || number < 0 || number > 255 || strconv.Itoa(number) != part {
					return nil, errors.New("IPv4 通配符地址非法")
				}
			}
			if firstWildcard == 0 {
				return nil, errors.New("禁止同步全网白名单")
			}
			value = strings.Join(parts, ".") + "/" + strconv.Itoa(firstWildcard*8)
		}
		if strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix.Addr().Is4In6() || prefix.Bits() == 0 || prefix.Addr().Zone() != "" {
				return nil, errors.New("白名单 CIDR 非法或过于宽泛")
			}
			value = prefix.Masked().String()
		} else {
			address, err := netip.ParseAddr(value)
			if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
				return nil, errors.New("白名单 IP 非法")
			}
			value = address.Unmap().String()
		}
		seen[value] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for rule := range seen {
		result = append(result, rule)
	}
	sort.Strings(result)
	return result, nil
}
