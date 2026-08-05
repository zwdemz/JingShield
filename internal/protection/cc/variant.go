package cc

// 变异 CC 攻击检测
// 对应 PHP CCProtection::checkVariantCCAttack()
// 攻击者不断变换请求特征（随机参数、动态 URL、变化 UA）绕过特征检测，
// 本检测从 UA、参数特征、URL 多样性多维度识别

import (
	"context"
	"regexp"
	"strings"
	"time"

	"jingshield/internal/protection/reqctx"
)

// 变异 CC 检测参数
const (
	variantCheckTime    = 10 // URL 多样性检测窗口（秒）
	variantMaxUniqueURL = 10 // 窗口内最大不同 URL 数
	variantMaxParamCount = 30 // 最大参数数量
	variantMinUALength  = 15 // UA 最小长度
)

// maliciousUAPatterns 恶意 User-Agent 特征
// 对应 PHP $malicious_ua_patterns
var maliciousUAPatterns = []string{
	"python-requests", "curl", "wget", "bot", "spider",
	"scanner", "attacker", "exploit", "hack", "sqlmap",
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
	if rc.UserAgent == "" {
		return true
	}
	if len(rc.UserAgent) < variantMinUALength {
		return true
	}
	uaLower := strings.ToLower(rc.UserAgent)
	for _, p := range maliciousUAPatterns {
		if strings.Contains(uaLower, p) {
			return true
		}
	}

	// 2. 参数特征检测
	keys := rc.AllParamKeys()
	if len(keys) > variantMaxParamCount {
		return true
	}
	for _, key := range keys {
		if len(key) > 20 || longParamPattern.MatchString(key) {
			return true
		}
	}

	// 3. URL 多样性检测：窗口内不同 URL 数超阈值
	since := time.Now().Add(-variantCheckTime * time.Second).Format("2006-01-02 15:04:05")
	uniqueURLs, err := d.accessLog.CountDistinctURIByIPSince(ctx, rc.IP, since)
	if err != nil {
		return false
	}
	return uniqueURLs > int64(variantMaxUniqueURL)
}
