package iputil

// IP 工具：客户端 IP 提取、CIDR 匹配、后台 IP 白名单匹配
// 对应 PHP getClientIP() / ipInRange() / checkAdminIP()

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

const maxForwardedForEntries = 32

// GetClientIP 从 HTTP 请求提取客户端真实 IP
// 只有直接连接方属于 trustedProxies 时才信任 X-Forwarded-For。
// X-Forwarded-For 从右向左解析，跳过可信代理并返回第一个非可信地址。
// X-Real-IP 不作为回退来源，因为它没有独立的可信链信息。
func GetClientIP(r *http.Request, trustedProxies []string) string {
	peer := remoteIP(r.RemoteAddr)
	if peer == "" || !matchesAny(peer, trustedProxies) {
		return peer
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > maxForwardedForEntries {
			return peer
		}
		valid := true
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(parts[i])
			if net.ParseIP(candidate) == nil {
				valid = false
				break
			}
			if !matchesAny(candidate, trustedProxies) {
				return candidate
			}
		}
		if !valid {
			return peer
		}
	}
	return peer
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	if net.ParseIP(remoteAddr) != nil {
		return remoteAddr
	}
	return ""
}

func matchesAny(ip string, rules []string) bool {
	for _, rule := range rules {
		if MatchIPRule(ip, strings.TrimSpace(rule)) {
			return true
		}
	}
	return false
}

// MatchIPRule matches an exact IP, CIDR range, or IPv4 wildcard rule.
func MatchIPRule(ip, rule string) bool {
	if net.ParseIP(ip) == nil {
		return false
	}
	rule = strings.TrimSpace(rule)
	if strings.Contains(rule, "/") {
		return IPInCIDR(ip, rule)
	}
	if strings.Contains(rule, "*") {
		return matchWildcard(ip, rule)
	}
	return net.ParseIP(rule) != nil && ip == rule
}

// IsPrivateIP 判断是否为内网/保留 IP
// 用于 IP 归属地查询时快速识别局域网地址
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// IPv4 私有/保留段
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 127:
			return true
		case ip4[0] == 169 && ip4[1] == 254:
			return true
		}
	}
	return false
}

// IPInCIDR 判断 IP 是否在 CIDR 网段内
// 对应 PHP ipInRange()，但使用标准库实现，正确支持 IPv4/IPv6
func IPInCIDR(ipStr, cidr string) bool {
	// 无前缀长度则按精确 IP 匹配
	if !strings.Contains(cidr, "/") {
		return ipStr == cidr
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ipNet.Contains(ip)
}

// MatchAdminIP 校验客户端 IP 是否在后台白名单中
// 白名单项支持三种格式：
//   - "*"           全部放行
//   - "1.2.3.0/24"  CIDR 网段
//   - "1.2.3.*"     通配符（仅末段）
//   - "1.2.3.4"     精确 IP
//
// 对应 PHP checkAdminIP()
func MatchAdminIP(clientIP string, whitelist []string) bool {
	if clientIP == "" || len(whitelist) == 0 {
		return false
	}
	for _, rule := range whitelist {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		if rule == "*" {
			return true
		}
		// CIDR
		if strings.Contains(rule, "/") {
			if IPInCIDR(clientIP, rule) {
				return true
			}
			continue
		}
		// 通配符（末段 *）
		if strings.Contains(rule, "*") {
			if matchWildcard(clientIP, rule) {
				return true
			}
			continue
		}
		// 精确匹配
		if rule == clientIP {
			return true
		}
	}
	return false
}

// matchWildcard 通配符匹配（仅支持末段 *，如 192.168.1.*）
// 对应 PHP str_replace('*', '[0-9]{1,3}', $ip) 正则方案，此处用字符串前缀匹配更高效
func matchWildcard(ip, pattern string) bool {
	ipParts := strings.Split(ip, ".")
	ruleParts := strings.Split(pattern, ".")
	if len(ipParts) != 4 || len(ruleParts) != 4 {
		return false
	}
	for i := range ruleParts {
		if ruleParts[i] != "*" && ruleParts[i] != ipParts[i] {
			return false
		}
	}
	return true
}

// ValidateIP 校验 IP 格式合法性
func ValidateIP(ipStr string) bool {
	return net.ParseIP(ipStr) != nil
}

// IPToUint32 IPv4 字符串转 uint32（QQWry 等二进制库查询用）
// 对应 PHP ip_parts[0]*16777216 + ... 的计算
func IPToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("非法 IP: %s", ipStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("非 IPv4 地址: %s", ipStr)
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3]), nil
}
