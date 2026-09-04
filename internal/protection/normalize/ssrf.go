package normalize

// SSRF URL 检测器
// 解析 URL 目标地址，检测内网 IP、元数据服务、回环地址、链路本地地址、
// 混淆地址（十进制/八进制 IP）和重定向滥用

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// IPResolver resolves a hostname to every current address. Keeping this as a
// function makes the detector deterministic in tests and allows callers to
// inject a bounded resolver.
type IPResolver func(context.Context, string) ([]net.IP, error)

const SSRFAttackType = "SSRF"

// SSRFResult SSRF 检测结果
type SSRFResult struct {
	Detected bool
	Detail   string
	Risk     SSRFRisk
}

// SSRFRisk SSRF 风险等级
type SSRFRisk int

const (
	SSRFRiskNone     SSRFRisk = iota
	SSRFRiskLow               // 可疑但可能是合法的（如 DNS rebinding 场景）
	SSRFRiskMedium            // 内网地址
	SSRFRiskHigh              // 元数据服务、回环地址
	SSRFRiskCritical          // 云元数据端点
)

// DetectSSRF 对规范化后的 URL 值执行 SSRF 检测
func DetectSSRF(normalized string) SSRFResult {
	return detectSSRF(context.Background(), normalized, nil)
}

// DetectSSRFWithResolver also checks DNS results for hostnames. A caller that
// handles untrusted request data should prefer this variant so a hostname
// resolving to a private or link-local address cannot bypass literal-IP rules.
func DetectSSRFWithResolver(ctx context.Context, normalized string, resolver IPResolver) SSRFResult {
	if ctx == nil {
		ctx = context.Background()
	}
	return detectSSRF(ctx, normalized, resolver)
}

func detectSSRF(ctx context.Context, normalized string, resolver IPResolver) SSRFResult {
	trimmed := strings.TrimSpace(normalized)
	if trimmed == "" {
		return SSRFResult{}
	}

	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return SSRFResult{}
	}

	hostname := strings.ToLower(u.Hostname())

	if r := detectDangerousScheme(u.Scheme); r.Detected {
		return r
	}

	if hostname == "" && (u.Scheme == "file" || u.Scheme == "data") {
		return SSRFResult{Detected: true, Detail: "检测到无主机名危险协议: " + u.Scheme + "://", Risk: SSRFRiskHigh}
	}

	if hostname == "" {
		return SSRFResult{}
	}

	if r := detectSingleHexIP(hostname, u.Scheme); r.Detected {
		return r
	}

	if r := detectMetadataEndpoint(hostname, u.Path); r.Detected {
		return r
	}
	if r := detectInternalHost(hostname); r.Detected {
		return r
	}
	if r := detectObfuscatedIP(hostname); r.Detected {
		return r
	}
	if resolver != nil && net.ParseIP(strings.Trim(hostname, "[]")) == nil {
		ips, err := resolver(ctx, hostname)
		if err == nil {
			for _, resolved := range ips {
				if r := detectMetadataEndpoint(resolved.String(), ""); r.Detected {
					return SSRFResult{Detected: true, Detail: "域名解析到云元数据地址: " + resolved.String(), Risk: r.Risk}
				}
				if r := detectInternalHost(resolved.String()); r.Detected {
					return SSRFResult{Detected: true, Detail: "域名解析到受限地址: " + resolved.String(), Risk: r.Risk}
				}
			}
		}
	}

	return SSRFResult{}
}

// detectMetadataEndpoint 检测云服务商元数据端点
func detectMetadataEndpoint(hostname, path string) SSRFResult {
	if ip := net.ParseIP(strings.Trim(hostname, "[]")); ip != nil {
		if mapped := ip.To4(); mapped != nil {
			hostname = mapped.String()
		}
	}
	metadataHosts := map[string]string{
		"169.254.169.254":          "AWS/GCP 元数据服务",
		"metadata.google.internal": "GCP 元数据服务",
		"100.100.100.200":          "阿里云元数据服务",
		"metadata.tencentyun.com":  "腾讯云元数据服务",
		"169.254.170.2":            "AWS ECS 元数据",
	}
	if desc, ok := metadataHosts[hostname]; ok {
		return SSRFResult{Detected: true, Detail: "检测到云元数据端点: " + desc, Risk: SSRFRiskCritical}
	}
	if strings.Contains(path, "/latest/meta-data") || strings.Contains(path, "/metadata/v1/") {
		return SSRFResult{Detected: true, Detail: "检测到元数据路径模式", Risk: SSRFRiskCritical}
	}
	return SSRFResult{}
}

// detectDangerousScheme 检测非 HTTP(S) 危险协议
func detectDangerousScheme(scheme string) SSRFResult {
	dangerous := map[string]string{
		"file":   "file:// 本地文件读取",
		"gopher": "gopher:// 内网协议探测",
		"dict":   "dict:// 字典协议探测",
		"ftp":    "ftp:// 文件传输",
		"ldap":   "ldap:// 目录服务探测",
		"tftp":   "tftp:// 简单文件传输",
	}
	if desc, ok := dangerous[scheme]; ok {
		return SSRFResult{Detected: true, Detail: "检测到危险协议: " + desc, Risk: SSRFRiskHigh}
	}
	return SSRFResult{}
}

// detectInternalHost 检测内网/回环/链路本地地址
func detectInternalHost(hostname string) SSRFResult {
	if hostname == "localhost" || hostname == "[::1]" {
		return SSRFResult{Detected: true, Detail: "检测到回环地址: " + hostname, Risk: SSRFRiskHigh}
	}

	ip := net.ParseIP(strings.Trim(hostname, "[]"))
	if ip == nil {
		return SSRFResult{}
	}
	// net.ParseIP returns a 16-byte IPv6 value for IPv4-mapped addresses.
	// Normalize it before applying the range checks so forms such as
	// [::ffff:169.254.169.254] cannot evade the IPv4 rules.
	if mapped := ip.To4(); mapped != nil {
		ip = mapped
	}

	if ip.IsLoopback() {
		return SSRFResult{Detected: true, Detail: "检测到回环地址", Risk: SSRFRiskHigh}
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return SSRFResult{Detected: true, Detail: "检测到链路本地地址", Risk: SSRFRiskHigh}
	}
	if ip.IsPrivate() {
		return SSRFResult{Detected: true, Detail: "检测到内网地址: " + ip.String(), Risk: SSRFRiskMedium}
	}
	if ip.IsUnspecified() {
		return SSRFResult{Detected: true, Detail: "检测到未指定地址 (0.0.0.0)", Risk: SSRFRiskMedium}
	}

	return SSRFResult{}
}

// detectObfuscatedIP 检测混淆 IP 格式（十进制、八进制、混合进制）
func detectObfuscatedIP(hostname string) SSRFResult {
	parts := strings.Split(hostname, ".")
	if len(parts) != 4 {
		return SSRFResult{}
	}

	var octets [4]byte
	for i, part := range parts {
		part = strings.TrimSpace(part)
		var val int64
		var err error
		if strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X") {
			val, err = strconv.ParseInt(part[2:], 16, 64)
		} else if strings.HasPrefix(part, "0") && len(part) > 1 {
			val, err = strconv.ParseInt(part, 8, 64)
		} else {
			val, err = strconv.ParseInt(part, 10, 64)
		}
		if err != nil || val < 0 || val > 255 {
			return SSRFResult{}
		}
		octets[i] = byte(val)
	}

	ip := net.IPv4(octets[0], octets[1], octets[2], octets[3])
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return SSRFResult{Detected: true, Detail: "检测到混淆编码的内网/回环 IP", Risk: SSRFRiskHigh}
	}

	return SSRFResult{}
}

// detectSingleHexIP 检测单体十六进制 IP（如 0x7f000001 = 127.0.0.1）
// 也检测纯十进制 IP（如 2130706433 = 127.0.0.1）
func detectSingleHexIP(hostname, scheme string) SSRFResult {
	if hostname == "" {
		return SSRFResult{}
	}

	var val int64
	var err error
	if strings.HasPrefix(hostname, "0x") || strings.HasPrefix(hostname, "0X") {
		val, err = strconv.ParseInt(hostname[2:], 16, 64)
	} else if strings.HasPrefix(hostname, "0") && len(hostname) > 1 && !strings.Contains(hostname, ".") {
		val, err = strconv.ParseInt(hostname, 8, 64)
	} else if !strings.Contains(hostname, ".") && !strings.Contains(hostname, ":") {
		val, err = strconv.ParseInt(hostname, 10, 64)
		if err == nil && val <= 0xFFFFFFFF {
		} else {
			return SSRFResult{}
		}
	} else {
		return SSRFResult{}
	}
	if err != nil || val < 0 || val > 0xFFFFFFFF {
		return SSRFResult{}
	}

	ip := make(net.IP, 4)
	ip[0] = byte(val >> 24)
	ip[1] = byte(val >> 16)
	ip[2] = byte(val >> 8)
	ip[3] = byte(val)

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return SSRFResult{Detected: true, Detail: "检测到数值编码的内网/回环 IP: " + ip.String(), Risk: SSRFRiskHigh}
	}

	return SSRFResult{}
}
