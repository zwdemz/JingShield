package cc

// CC 攻击检测引擎
// 对应 PHP CCProtection::checkCCAttack() 及其子检测方法
//
// 与 XSS/SQL 的二值检测不同，CC 检测可能触发"验证页"而非直接拦截，
// 因此返回值含动作类型：Allow(放行)/Block(拦截403)/Verify(展示验证页)

import (
	"context"

	"jingshield/internal/config"
	"jingshield/internal/iplib"
	"jingshield/internal/model"
	"jingshield/internal/protection/reqctx"
	"jingshield/internal/repository"
	"jingshield/internal/store"
)

// Action CC 检测后的处置动作
type Action int

const (
	ActionAllow  Action = iota // 放行，转发至 upstream
	ActionBlock                // 拦截，返回 403
	ActionVerify               // 展示验证页
)

// Result CC 检测结果
type Result struct {
	Action     Action
	AttackType string // 命中时的攻击类型（用于日志记录）
	Detail     string
}

// allow / block / verify 快捷构造
func allow() *Result  { return &Result{Action: ActionAllow} }
func block(at, d string) *Result { return &Result{Action: ActionBlock, AttackType: at, Detail: d} }
func verify() *Result { return &Result{Action: ActionVerify} }

// forbiddenMethods 禁止的 HTTP 方法
// 对应 PHP CCProtection::$forbidden_methods
var forbiddenMethods = []string{"OPTIONS", "TRACE", "PUT", "DELETE", "CONNECT", "PATCH"}

// CCDetector CC 攻击检测器
type CCDetector struct {
	store        store.StateStore
	accessLog    *repository.AccessLogRepo
	verifyFail   *repository.VerifyFailRepo
	ipList       *repository.IPListRepo
	locator      iplib.Locator
	dynCfg       *config.DynamicConfig
	session      config.SessionConfig
	verifyMaxAge int
}

// NewCCDetector 构造
func NewCCDetector(
	st store.StateStore,
	accessLog *repository.AccessLogRepo,
	verifyFail *repository.VerifyFailRepo,
	ipList *repository.IPListRepo,
	locator iplib.Locator,
	dynCfg *config.DynamicConfig,
	session config.SessionConfig,
) *CCDetector {
	return &CCDetector{
		store:        st,
		accessLog:    accessLog,
		verifyFail:   verifyFail,
		ipList:       ipList,
		locator:      locator,
		dynCfg:       dynCfg,
		session:      session,
		verifyMaxAge: session.VerifyCookieMaxAge,
	}
}

// Check 执行 CC 攻击检测主流程
// 对应 PHP CCProtection::checkCCAttack()
func (d *CCDetector) Check(ctx context.Context, rc *reqctx.RequestContext) *Result {
	// 排除路径直接放行（对应 excluded_dirs 判断）
	if rc.IsExcludedPath() {
		return allow()
	}

	// CC 防护关闭则放行
	if !d.dynCfg.GetBool("cc_protection_status") {
		return allow()
	}

	// 已通过验证的 cookie：检查是否为穿盾攻击，是则清除 cookie 并继续检测
	if rc.Verified {
		if d.checkShieldBypass(ctx, rc) {
			// 穿盾命中，清除验证 cookie（由调用方清 cookie）
			return block(model.AttackTypeShieldBypass, "穿盾CC脚本攻击，验证已失效")
		}
		return allow()
	}

	// 各子检测，任一命中即返回对应动作
	if d.checkTCP(ctx, rc) {
		return block(model.AttackTypeCC, "TCP连接数异常")
	}
	if d.checkVariant(ctx, rc) {
		return block(model.AttackTypeCC, "变异CC攻击特征")
	}
	if d.checkShieldBypass(ctx, rc) {
		return verify()
	}
	if d.checkURLFrequency(ctx, rc) {
		return verify()
	}
	if d.checkPortScan(ctx, rc) {
		return block(model.AttackTypeCC, "端口扫描行为")
	}
	if d.checkRequestInterval(ctx, rc) {
		return verify()
	}

	// 主频率检测：窗口内访问次数超阈值则触发验证或拦截
	return d.checkMainFrequency(ctx, rc)
}

// checkMainFrequency 主频率检测
// 对应 PHP checkCCAttack() 末段的文件计数 + 阈值比较 + verifyFailLimit 判定
func (d *CCDetector) checkMainFrequency(ctx context.Context, rc *reqctx.RequestContext) *Result {
	ccVisitCount := d.dynCfg.GetIntDefault("cc_visit_count", 100)
	ccVisitTime := d.dynCfg.GetIntDefault("cc_visit_time", 60)

	// 内存滑动窗口计数（替代原文件 cc_{md5(ip)}.txt）
	count, _ := d.store.HitAndCount(ctx, rc.IP, ccVisitTime)

	// 动态阈值
	effectiveCount := GetDynamicThreshold(ccVisitCount)

	if count > effectiveCount {
		// 超阈值：检查验证失败次数限制
		if d.checkVerifyFailLimit(ctx, rc) {
			// 验证失败次数过多 -> 直接拦截并加入临时黑名单
			return block(model.AttackTypeVerifyFail, "验证失败次数超过限制")
		}
		// 触发验证页
		return verify()
	}
	return allow()
}

// checkVerifyFailLimit 验证失败次数限制检查
// 对应 PHP checkVerifyFailLimit()
func (d *CCDetector) checkVerifyFailLimit(ctx context.Context, rc *reqctx.RequestContext) bool {
	verifyFailLimit := d.dynCfg.GetIntDefault("cc_verify_fail_limit", 10)
	failCount, _ := d.verifyFail.GetFailCount(ctx, rc.IP)
	if failCount >= verifyFailLimit {
		// 加入临时黑名单
		blacklistTime := d.dynCfg.GetIntDefault("cc_blacklist_time", 3600)
		_ = d.ipList.AddTempBlacklist(ctx, rc.IP, "验证失败次数超过限制", blacklistTime)
		return true
	}
	return false
}

// IsForbiddenMethod 判断是否为禁止的 HTTP 方法
func IsForbiddenMethod(method string) bool {
	m := method
	for _, fm := range forbiddenMethods {
		if m == fm {
			return true
		}
	}
	return false
}
