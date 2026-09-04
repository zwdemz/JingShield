package cc

// 穿盾 CC 攻击检测
// 对应 PHP CCProtection::checkShieldBypassAttack()
// 穿盾攻击指攻击者通过 CDN/代理/肉鸡隐藏真实 IP 绕过传统封禁，
// 本检测从请求头完整性、cookie 合法性、代理特征、请求间隔规律性多维度识别

import (
	"context"
	"math"
	"strings"
	"time"

	"jingshield/internal/protection/reqctx"
)

// 穿盾检测参数
const (
	bypassMinSamples     = 8   // 方差分析所需最小样本数
	bypassMaxStdDev      = 0.3 // 请求间隔标准差阈值（秒），低于此值判定为机器规律请求
	bypassProxyThreshold = 3   // 代理 header 数量阈值
	bypassRecentSampleN  = 10  // 取最近 N 次请求做方差分析
)

// requiredHeaders 浏览器必带请求头（缺失则疑似非浏览器）
// 对应 PHP $required_headers
var requiredHeaders = []string{
	"Accept", "Accept-Language", "Accept-Encoding",
	"User-Agent",
}

// proxyHeaders 代理相关请求头
// 对应 PHP $proxy_headers
var proxyHeaders = []string{
	"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
	"Via", "Proxy-Connection", "X-Real-Ip", "X-Proxy-Id",
}

// forbiddenUAPatterns 禁止的 UA 特征（穿盾视角）
// 对应 PHP $forbidden_ua_patterns
var forbiddenUAPatterns = []string{
	"python-requests", "curl", "wget", "scrapy",
	"bot", "spider", "attack", "hack", "loader", "crawler",
}

// checkShieldBypass 检测穿盾攻击
// 对应 PHP checkShieldBypassAttack()
func (d *CCDetector) checkShieldBypass(ctx context.Context, rc *reqctx.RequestContext) bool {
	if !d.dynCfg.GetBool("cc_protection_status") {
		return false
	}

	// 1. 必带请求头完整性检测
	for _, h := range requiredHeaders {
		if rc.Header.Get(h) == "" {
			return true
		}
	}

	// 2. cc_verified 已由 verify.Service 使用 HMAC、客户端 IP 和有效期完成校验。
	// 公共站点在登录前通常没有业务会话 cookie，不能把它作为验证通过的前提，
	// 否则真实访客完成挑战后会立即被误判为穿盾攻击。

	// 3. 请求方法合法性：仅允许 GET/POST/HEAD
	m := strings.ToUpper(rc.Method)
	if m != "GET" && m != "POST" && m != "HEAD" {
		return true
	}

	// 4. 代理 header 数量检测：同时携带多个代理头则疑似代理穿透
	proxyCount := 0
	for _, h := range proxyHeaders {
		if rc.Header.Get(h) != "" {
			proxyCount++
		}
	}
	if proxyCount >= bypassProxyThreshold {
		return true
	}

	// 5. 请求间隔规律性检测：标准差过小判定为机器规律请求
	// 对应 PHP 的 timestamps 方差/标准差计算
	intervals, err := d.store.RecentIntervals(ctx, rc.IP, bypassRecentSampleN)
	if err == nil && len(intervals) >= bypassMinSamples {
		if stdDevSeconds(intervals) < bypassMaxStdDev {
			return true
		}
	}

	// 6. 禁止 UA 特征检测
	uaLower := strings.ToLower(rc.UserAgent)
	for _, p := range forbiddenUAPatterns {
		if strings.Contains(uaLower, p) {
			return true
		}
	}

	// 7. 禁止的 HTTP 方法检测
	if IsForbiddenMethod(rc.Method) {
		return true
	}

	return false
}

// stdDevSeconds 计算 Duration 列表的标准差（秒）
// 对应 PHP 的方差/标准差计算逻辑
func stdDevSeconds(intervals []time.Duration) float64 {
	n := len(intervals)
	if n < 2 {
		return 0
	}
	var sum float64
	seconds := make([]float64, n)
	for i, d := range intervals {
		s := d.Seconds()
		seconds[i] = s
		sum += s
	}
	mean := sum / float64(n)
	var variance float64
	for _, s := range seconds {
		variance += (s - mean) * (s - mean)
	}
	variance /= float64(n)
	return math.Sqrt(variance)
}
