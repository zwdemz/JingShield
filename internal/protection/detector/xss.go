package detector

// XSS 攻击检测器
// 对应 PHP safe/XSS/xss_detect.php
// 全部正则模式逐条直译，已验证 RE2 兼容（仅用 i/s 标志 + 字符类 + 非贪婪，无前瞻/反向引用）

import (
	"context"
	"regexp"

	"jingshield/internal/model"
	"jingshield/internal/pkg/errx"
	"jingshield/internal/protection/reqctx"
)

// xssPatterns XSS 攻击特征正则（对应 xss_detect.php 的 $xss_patterns）
// 预编译为包级变量，避免每请求重编译
var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`),
	regexp.MustCompile(`(?is)<iframe[^>]*>.*?</iframe>`),
	regexp.MustCompile(`(?is)<object[^>]*>.*?</object>`),
	regexp.MustCompile(`(?is)<embed[^>]*>.*?</embed>`),
	regexp.MustCompile(`(?is)<applet[^>]*>.*?</applet>`),
	regexp.MustCompile(`(?i)<meta[^>]*http-equiv=["']refresh["'][^>]*>`),
	regexp.MustCompile(`(?i)javascript:`),
	regexp.MustCompile(`(?i)vbscript:`),
	regexp.MustCompile(`(?i)on\w+\s*=\s*["'][^"']*["']`),
	regexp.MustCompile(`(?i)on\w+\s*=\s*[^\s>]+`),
}

// XSSDetector XSS 检测器
type XSSDetector struct{}

// NewXSSDetector 构造
func NewXSSDetector() *XSSDetector { return &XSSDetector{} }

// Name 检测器名称
func (d *XSSDetector) Name() string { return "XSS" }

// Check 检测请求是否含 XSS 攻击特征
// 遍历全部 GET/POST/Cookie 参数值，任一命中即判定为攻击
func (d *XSSDetector) Check(_ context.Context, rc *reqctx.RequestContext) *Result {
	for _, value := range rc.AllParamValues() {
		for _, p := range xssPatterns {
			if p.MatchString(value) {
				return &Result{
					Detected:   true,
					AttackType: model.AttackTypeXSS,
					Detail:     "检测到XSS攻击特征",
					Code:       errx.CodeXSSAttack,
				}
			}
		}
	}
	return &Result{Detected: false}
}
