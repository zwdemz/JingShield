package detector

// SQL 注入检测器
// 对应 PHP safe/SQL/sql_detect.php
// 全部 26 条正则模式逐条直译，已验证 RE2 兼容

import (
	"context"
	"regexp"

	"jingshield/internal/model"
	"jingshield/internal/pkg/errx"
	"jingshield/internal/protection/reqctx"
)

// sqlPatterns SQL 注入特征正则（对应 sql_detect.php 的 $sql_patterns）
// 全部以 (?i) 启用忽略大小写
var sqlPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)'\s*OR\s+1\s*=\s*1`),
	regexp.MustCompile(`(?i)'\s*OR\s+'1'\s*=\s*'1'`),
	regexp.MustCompile(`(?i)'\s*AND\s+1\s*=\s*2`),
	regexp.MustCompile(`(?i)'\s*UNION\s+SELECT`),
	regexp.MustCompile(`(?i)'\s*UNION\s+ALL\s+SELECT`),
	regexp.MustCompile(`(?i)'\s*DROP\s+TABLE`),
	regexp.MustCompile(`(?i)'\s*DELETE\s+FROM`),
	regexp.MustCompile(`(?i)'\s*INSERT\s+INTO`),
	regexp.MustCompile(`(?i)'\s*UPDATE\s+.*?SET`),
	regexp.MustCompile(`(?i)'\s*TRUNCATE\s+TABLE`),
	regexp.MustCompile(`(?i)'\s*ALTER\s+TABLE`),
	regexp.MustCompile(`(?i)'\s*EXEC\s+\(`),
	regexp.MustCompile(`(?i)'\s*EXECUTE\s+\(`),
	regexp.MustCompile(`(?i)'\s*XP_CMDSHELL`),
	regexp.MustCompile(`(?i)'\s*INFORMATION_SCHEMA`),
	regexp.MustCompile(`(?i)'\s*TABLE_SCHEMA`),
	regexp.MustCompile(`(?i)'\s*COLUMN_NAME`),
	regexp.MustCompile(`(?i)'\s*OR\s+'x'\s*=\s*'x'`),
	regexp.MustCompile(`(?i)'\s*AND\s+'x'\s*=\s*'y'`),
	regexp.MustCompile(`(?i)'\s*OR\s+0x`),
	regexp.MustCompile(`(?i)'\s*AND\s+0x`),
	regexp.MustCompile(`(?i)'\s*OR\s+''\s*=\s*''`),
	regexp.MustCompile(`(?i)'\s*AND\s+''\s*=\s*''`),
	regexp.MustCompile(`(?i)'\s*OR\s+\(SELECT`),
	regexp.MustCompile(`(?i)'\s*AND\s+\(SELECT`),
	regexp.MustCompile(`(?i)'\s*OR\s+COUNT`),
}

// SQLDetector SQL 注入检测器
type SQLDetector struct{}

// NewSQLDetector 构造
func NewSQLDetector() *SQLDetector { return &SQLDetector{} }

// Name 检测器名称
func (d *SQLDetector) Name() string { return "SQLInjection" }

// Check 检测请求是否含 SQL 注入特征
// 遍历全部 GET/POST/Cookie 参数值，任一命中即判定为攻击
func (d *SQLDetector) Check(_ context.Context, rc *reqctx.RequestContext) *Result {
	for _, value := range rc.AllParamValues() {
		for _, p := range sqlPatterns {
			if p.MatchString(value) {
				return &Result{
					Detected:   true,
					AttackType: model.AttackTypeSQL,
					Detail:     "检测到SQL注入攻击特征",
					Code:       errx.CodeSQLInjection,
				}
			}
		}
	}
	return &Result{Detected: false}
}
