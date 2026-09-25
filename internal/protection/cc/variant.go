package cc

// 变异 CC 攻击检测
// 对应 PHP CCProtection::checkVariantCCAttack()
// 攻击者不断变换参数与 URL 绕过频率检测；保留明确的扫描器 UA 特征。

import (
	"context"
	"regexp"
	"strings"
	"time"

	"jingshield/internal/protection/reqctx"
)

// 变异 CC 检测参数
const (
	variantCheckTime     = 10 // URL 多样性检测窗口（秒）
	variantMaxUniqueURL  = 10 // 窗口内最大不同 URL 数
	variantMaxParamCount = 30 // 最大参数数量
)

// maliciousUAPatterns 恶意 User-Agent 特征
// 对应 PHP $malicious_ua_patterns
var maliciousUAPatterns = []string{
	"sqlmap", "nikto", "nuclei",
}

// longParamPattern 超长参数名特征正则
// 对应 PHP preg_match('/^[a-zA-Z0-9]{15,}$/', $param)
var longParamPattern = regexp.MustCompile(`^[a-zA-Z0-9]{15,}$`)

// checkVariant 检测变异 CC 攻击
// 对应 PHP checkVariantCCAttack()
func (d *CCDetector) checkVariant(ctx context.Context, rc *reqctx.RequestContext) bool {
	if !d.dynCfg.GetBool("cc_protection_status") {
		return false
	}

	// 1. User-Agent 异常检测
	uaLower := strings.ToLower(rc.UserAgent)
	for _, p := range maliciousUAPatterns {
		if strings.Contains(uaLower, p) {
			return true
		}
	}

	// Parameter shape alone is common in legitimate APIs. Require accompanying
	// URL churn before blocking on it.
	keys := rc.AllParamKeys()
	paramSuspicious := len(keys) > variantMaxParamCount
	for _, key := range keys {
		if len(key) > 20 || longParamPattern.MatchString(key) {
			paramSuspicious = true
		}
	}
	// NAS dashboards load many distinct resources in a short burst. Diversity
	// alone is not an attack signal; require suspicious parameters as well.
	// Ordinary request-volume limits remain enforced by the main CC detector.
	if !paramSuspicious {
		return false
	}

	// 3. URL 多样性检测：窗口内不同 URL 数超阈值
	since := time.Now().Add(-variantCheckTime * time.Second).Format("2006-01-02 15:04:05")
	uniqueURLs, err := d.accessLog.CountDistinctURIByIPSince(ctx, rc.IP, since)
	if err != nil {
		return false
	}
	return uniqueURLs > int64(variantMaxUniqueURL)
}
