package cc

// 穿盾 CC 攻击检测
// 对应 PHP CCProtection::checkShieldBypassAttack()
// 穿盾攻击指攻击者通过 CDN/代理/肉鸡隐藏真实 IP 绕过传统封禁。
// 本检测仅使用浏览器导航请求头、请求间隔和明确的扫描器标识。

import (
	"context"
	"math"
	"strings"
	"time"

	"jingshield/internal/protection/reqctx"
)

// 穿盾检测参数
const (
	bypassMinSamples    = 8   // 方差分析所需最小样本数
	bypassMaxStdDev     = 0.3 // 请求间隔标准差阈值（秒），低于此值判定为机器规律请求
	bypassRecentSampleN = 10  // 取最近 N 次请求做方差分析
)

// requiredHeaders are expected only for browser navigation requests.
var requiredHeaders = []string{"Accept", "User-Agent"}

// forbiddenUAPatterns contains narrow scanner identifiers, not generic API clients.
var forbiddenUAPatterns = []string{"sqlmap", "nikto", "nuclei"}

// checkShieldBypass 检测穿盾攻击
// 对应 PHP checkShieldBypassAttack()，但降低了 API 客户端误报。
func (d *CCDetector) checkShieldBypass(ctx context.Context, rc *reqctx.RequestContext) bool {
	if !d.dynCfg.GetBool("cc_protection_status") {
		return false
	}

	// Header completeness is meaningful only for browser navigation, not API clients.
	if strings.EqualFold(rc.Header.Get("Sec-Fetch-Mode"), "navigate") {
		for _, h := range requiredHeaders {
			if rc.Header.Get(h) == "" {
				return true
			}
		}
	}

	// 请求间隔规律性检测：标准差过小判定为机器规律请求
	// 对应 PHP 的 timestamps 方差/标准差计算
	intervals, err := d.store.RecentIntervals(ctx, rc.IP, bypassRecentSampleN)
	if err == nil && len(intervals) >= bypassMinSamples {
		if stdDevSeconds(intervals) < bypassMaxStdDev {
			return true
		}
	}

	// 明确的扫描器 UA 特征检测
	uaLower := strings.ToLower(rc.UserAgent)
	for _, p := range forbiddenUAPatterns {
		if strings.Contains(uaLower, p) {
			return true
		}
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
