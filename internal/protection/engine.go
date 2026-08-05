package protection

// 防护引擎：编排完整保护链
// 对应 PHP CCProtection::enable() 的顺序检测流程
//
// 设计：Engine 返回决策(Decision)，不直接写 HTTP 响应，
// 由 proxy 中间件层将决策翻译为 HTTP 响应（403/验证页/转发），
// 保持引擎与 HTTP 解耦，便于测试。

import (
	"context"
	"net/http"

	"jingshield/internal/config"
	"jingshield/internal/iplib"
	"jingshield/internal/model"
	"jingshield/internal/pkg/errx"
	"jingshield/internal/policy"
	"jingshield/internal/protection/cc"
	"jingshield/internal/protection/detector"
	"jingshield/internal/protection/iplist"
	"jingshield/internal/protection/reqctx"
	"jingshield/internal/protection/verify"
	"jingshield/internal/repository"
)

// DecisionAction 决策动作
type DecisionAction int

const (
	DecisionAllow  DecisionAction = iota // 放行，转发至 upstream
	DecisionBlock                        // 拦截，返回错误响应
	DecisionVerify                       // 展示验证页
)

// Decision 引擎决策
type Decision struct {
	Action       DecisionAction
	StatusCode   int    // Block 时的 HTTP 状态码
	ErrorCode    int    // Block 时的错误码
	ErrorMessage string // Block 时的错误信息
	AttackType   string // 命中攻击时用于日志记录
	AttackDetail string
	VerifyMode   verify.Mode // Verify 时的验证模式
}

// Engine 防护引擎
type Engine struct {
	dynCfg    *config.DynamicConfig
	ipList    *iplist.Service
	cc        *cc.CCDetector
	xss       detector.Detector
	sql       detector.Detector
	verify    *verify.Service
	accessLog *repository.AccessLogRepo
	attackLog *repository.AttackLogRepo
	locator   iplib.Locator
	policies  *policy.Service
}

// NewEngine 构造防护引擎
func NewEngine(
	dynCfg *config.DynamicConfig,
	ipListSvc *iplist.Service,
	ccDetector *cc.CCDetector,
	verifySvc *verify.Service,
	accessLog *repository.AccessLogRepo,
	attackLog *repository.AttackLogRepo,
	locator iplib.Locator,
	policies *policy.Service,
) *Engine {
	return &Engine{
		dynCfg:    dynCfg,
		ipList:    ipListSvc,
		cc:        ccDetector,
		xss:       detector.NewXSSDetector(),
		sql:       detector.NewSQLDetector(),
		verify:    verifySvc,
		accessLog: accessLog,
		attackLog: attackLog,
		locator:   locator,
		policies:  policies,
	}
}

// Evaluate 执行保护链，返回决策
// 对应 PHP CCProtection::enable()
func (e *Engine) Evaluate(ctx context.Context, rc *reqctx.RequestContext) Decision {
	// 1. 系统总开关：关闭则记录访问并放行
	if !e.dynCfg.GetBool("system_status") {
		e.logAccessAsync(ctx, rc, http.StatusOK)
		return Decision{Action: DecisionAllow}
	}

	// 2. 黑名单检测 -> 403
	if e.ipList.IsBlacklisted(ctx, rc.IP) {
		e.logAttackAsync(ctx, rc, model.AttackTypeBlacklist, "IP已被列入黑名单")
		e.logAccessAsync(ctx, rc, http.StatusForbidden)
		return Decision{
			Action:       DecisionBlock,
			StatusCode:   http.StatusForbidden,
			ErrorCode:    errx.CodeBlacklisted,
			ErrorMessage: "IP已被列入黑名单",
			AttackType:   model.AttackTypeBlacklist,
		}
	}

	// 3. 白名单检测 -> 放行（记录访问）
	if e.ipList.IsWhitelisted(ctx, rc.IP) {
		e.logAccessAsync(ctx, rc, http.StatusOK)
		return Decision{Action: DecisionAllow}
	}

	// 4. 海外 IP 检测 -> 403
	if e.ipList.IsOversea(ctx, rc.IP) {
		e.logAttackAsync(ctx, rc, model.AttackTypeOversea, "检测到海外IP访问")
		e.logAccessAsync(ctx, rc, http.StatusForbidden)
		return Decision{
			Action:       DecisionBlock,
			StatusCode:   http.StatusForbidden,
			ErrorCode:    errx.CodeOversea,
			ErrorMessage: "海外IP访问受限",
			AttackType:   model.AttackTypeOversea,
		}
	}

	// 5. CC 攻击检测 -> Block 或 Verify
	if e.policies != nil {
		if match := e.policies.Match(ctx, rc); match != nil {
			e.logPolicyAsync(rc, match.Detail, match.Action == policy.ActionBlock)
			if match.Action == policy.ActionBlock {
				e.logAccessAsync(ctx, rc, http.StatusForbidden)
				return Decision{Action: DecisionBlock, StatusCode: http.StatusForbidden, ErrorCode: errx.CodePolicyAttack, ErrorMessage: "请求命中自定义防护策略", AttackType: model.AttackTypePolicy, AttackDetail: match.Detail}
			}
		}
	}

	// 6. CC 攻击检测 -> Block 或 Verify
	ccResult := e.cc.Check(ctx, rc)
	switch ccResult.Action {
	case cc.ActionBlock:
		e.logAttackAsync(ctx, rc, ccResult.AttackType, ccResult.Detail)
		e.logAccessAsync(ctx, rc, http.StatusForbidden)
		// 验证失败次数过多等场景返回特定错误码
		code := errx.CodeCCAttack
		if ccResult.AttackType == model.AttackTypeVerifyFail {
			code = errx.CodeVerifyFail
		} else if ccResult.AttackType == model.AttackTypeShieldBypass {
			code = errx.CodeCCAttack
		}
		return Decision{
			Action:       DecisionBlock,
			StatusCode:   http.StatusForbidden,
			ErrorCode:    code,
			ErrorMessage: ccResult.Detail,
			AttackType:   ccResult.AttackType,
		}
	case cc.ActionVerify:
		mode := verify.ModeFromInt(e.dynCfg.GetIntDefault("cc_verification_mode", 1))
		return Decision{Action: DecisionVerify, VerifyMode: mode}
	}

	// 6. XSS 检测 -> 错误响应
	if e.dynCfg.GetBool("xss_protection_status") {
		if r := e.xss.Check(ctx, rc); r != nil && r.Detected {
			e.logAttackAsync(ctx, rc, r.AttackType, r.Detail)
			e.logAccessAsync(ctx, rc, http.StatusForbidden)
			return Decision{
				Action:       DecisionBlock,
				StatusCode:   http.StatusForbidden,
				ErrorCode:    r.Code,
				ErrorMessage: "非安全字符",
				AttackType:   r.AttackType,
			}
		}
	}

	// 7. SQL 注入检测 -> 错误响应
	if e.dynCfg.GetBool("sql_protection_status") {
		if r := e.sql.Check(ctx, rc); r != nil && r.Detected {
			e.logAttackAsync(ctx, rc, r.AttackType, r.Detail)
			e.logAccessAsync(ctx, rc, http.StatusForbidden)
			return Decision{
				Action:       DecisionBlock,
				StatusCode:   http.StatusForbidden,
				ErrorCode:    r.Code,
				ErrorMessage: "非安全字符",
				AttackType:   r.AttackType,
			}
		}
	}

	// 8. 通过全部检测，记录访问并放行
	e.logAccessAsync(ctx, rc, http.StatusOK)
	return Decision{Action: DecisionAllow}
}

// logAccessAsync 异步记录访问日志（不阻塞请求）
// 对应 PHP logAccess()
func (e *Engine) logAccessAsync(ctx context.Context, rc *reqctx.RequestContext, status int) {
	go func() {
		log := &model.AccessLog{
			IP:        rc.IP,
			Host:      rc.R.Host,
			URI:       rc.URI,
			Method:    rc.Method,
			UserAgent: rc.UserAgent,
			Referer:   rc.Header.Get("Referer"),
			Status:    status,
		}
		_ = e.accessLog.Insert(context.Background(), log)
	}()
}

func (e *Engine) logPolicyAsync(rc *reqctx.RequestContext, detail string, blocked bool) {
	go func() {
		status := 2
		if blocked {
			status = 1
		}
		_, _ = e.attackLog.UpsertAttack(context.Background(), &model.AttackLog{IP: rc.IP, IPLocation: e.locator.Lookup(rc.IP), Host: rc.R.Host, URI: rc.URI, Method: rc.Method, AttackType: model.AttackTypePolicy, AttackDetail: detail, AttackCount: 1, Status: status})
	}()
}

// logAttackAsync 异步记录攻击日志
// 对应 PHP logAttack()
func (e *Engine) logAttackAsync(ctx context.Context, rc *reqctx.RequestContext, attackType, detail string) {
	go func() {
		ipLocation := e.locator.Lookup(rc.IP)
		log := &model.AttackLog{
			IP:           rc.IP,
			IPLocation:   ipLocation,
			Host:         rc.R.Host,
			URI:          rc.URI,
			Method:       rc.Method,
			AttackType:   attackType,
			AttackDetail: detail,
			AttackCount:  1,
			Status:       1,
		}
		_, _ = e.attackLog.UpsertAttack(context.Background(), log)
	}()
}
