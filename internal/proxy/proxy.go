package proxy

// 反向代理 + 保护中间件链
// 将 protection.Engine 的决策翻译为 HTTP 响应：
//   Allow  -> 转发至 upstream（httputil.ReverseProxy）
//   Block  -> 输出错误响应（JSON 或 HTML，对应 PHP outputError）
//   Verify -> 渲染验证页静态资源（对应 PHP showVerification）

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"jingshield/internal/config"
	"jingshield/internal/model"
	"jingshield/internal/pkg/errx"
	"jingshield/internal/pkg/logx"
	"jingshield/internal/protection"
	"jingshield/internal/protection/reqctx"
	"jingshield/internal/protection/verify"
)

// Proxy 反向代理防护器
type Proxy struct {
	engine    *protection.Engine
	verify    *verify.Service
	dynCfg    *config.DynamicConfig
	sites     SiteResolver
	fallback  *httputil.ReverseProxy
	reverseMu sync.RWMutex
	reverses  map[string]*httputil.ReverseProxy
	upstream  string
	timeout   int
	serverCfg config.ServerConfig
}

const (
	upstreamFailureThreshold = 5
	upstreamOpenDuration     = 30 * time.Second
)

// circuitBreakerTransport prevents a failed origin from consuming one
// timeout-sized connection per incoming request. It is local to each route;
// shared state can be introduced together with the future clustered store.
type circuitBreakerTransport struct {
	base        http.RoundTripper
	mu          sync.Mutex
	failures    int
	openedUntil time.Time
}

func (t *circuitBreakerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	if time.Now().Before(t.openedUntil) {
		t.mu.Unlock()
		return nil, errors.New("源站熔断中")
	}
	t.mu.Unlock()

	response, err := t.base.RoundTrip(req)
	failed := err != nil || (response != nil && response.StatusCode >= http.StatusInternalServerError)
	t.mu.Lock()
	defer t.mu.Unlock()
	if failed {
		t.failures++
		if t.failures >= upstreamFailureThreshold {
			t.openedUntil = time.Now().Add(upstreamOpenDuration)
			t.failures = 0
		}
	} else {
		t.failures = 0
	}
	return response, err
}

// SiteResolver is implemented by repository.SiteRepo. hasSites distinguishes
// legacy single-upstream mode from an unknown/disabled Host in managed mode.
type SiteResolver interface {
	ResolveSite(context.Context, string) (site *model.Site, hasSites bool, err error)
}

// New 构造反向代理
func New(engine *protection.Engine, verifySvc *verify.Service,
	dynCfg *config.DynamicConfig, sites SiteResolver, upstreamCfg config.UpstreamConfig, serverCfg config.ServerConfig) (*Proxy, error) {
	rp, err := newReverseProxy(upstreamCfg.Target, upstreamCfg.PassHost, false, upstreamCfg.Timeout, dynCfg)
	if err != nil {
		return nil, err
	}

	return &Proxy{
		engine:    engine,
		verify:    verifySvc,
		dynCfg:    dynCfg,
		sites:     sites,
		fallback:  rp,
		reverses:  make(map[string]*httputil.ReverseProxy),
		upstream:  upstreamCfg.Target,
		timeout:   upstreamCfg.Timeout,
		serverCfg: serverCfg,
	}, nil
}

func newReverseProxy(rawURL string, passHost, tlsSkipVerify bool, timeout int, dynCfg *config.DynamicConfig) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(rawURL)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, fmt.Errorf("解析 upstream 地址失败: %q", rawURL)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: time.Duration(timeout) * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   time.Duration(timeout) * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: time.Duration(timeout) * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: tlsSkipVerify}, // #nosec G402 -- explicit per-site opt-in for private self-signed origins
	}
	rp.Transport = &circuitBreakerTransport{base: transport}
	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalHost := req.Host
		originalScheme := "http"
		if req.TLS != nil {
			originalScheme = "https"
		}
		originalDirector(req)
		req.Header.Set("X-Forwarded-Host", originalHost)
		req.Header.Set("X-Forwarded-Proto", originalScheme)
		if !passHost {
			// Some origins enforce Go's CrossOriginProtection against Host. A
			// browser request that was same-origin at the public WAF boundary must
			// remain same-origin after Host is rewritten for the private upstream.
			// A genuinely foreign Origin is intentionally left untouched.
			if requestOriginMatches(req.Header.Get("Origin"), originalScheme, originalHost) {
				req.Header.Set("Origin", target.Scheme+"://"+target.Host)
			}
			req.Host = target.Host
		}
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logx.Error("upstream 转发失败", "err", err, "upstream", rawURL, "url", r.URL.String())
		writeError(w, dynCfg, errx.CodeInternal, "后端服务不可用", http.StatusBadGateway)
	}
	return rp, nil
}

func requestOriginMatches(origin, requestScheme, requestHost string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	requestURL := &url.URL{Scheme: requestScheme, Host: requestHost}
	return canonicalOrigin(parsed) == canonicalOrigin(requestURL)
}

func canonicalOrigin(value *url.URL) string {
	scheme := strings.ToLower(value.Scheme)
	host := strings.TrimSuffix(strings.ToLower(value.Hostname()), ".")
	port := value.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return scheme + "://" + host + ":" + port
}

// ServeHTTP 处理请求：先跑保护链，再决定转发或拦截
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	reverse, err := p.reverseFor(r)
	if err != nil {
		logx.Error("加载防护站点路由失败", "host", r.Host, "err", err)
		writeError(w, p.dynCfg, errx.CodeInternal, "防护站点路由暂不可用", http.StatusServiceUnavailable)
		return
	}
	if reverse == nil {
		writeError(w, p.dynCfg, errx.CodeParamInvalid, "该域名尚未配置防护站点", http.StatusMisdirectedRequest)
		return
	}

	// 请求体大小限制（防大包攻击）
	r.Body = http.MaxBytesReader(w, r.Body, p.serverCfg.MaxBodyBytes)

	// 构建请求上下文
	rc, err := reqctx.NewRequestContext(r, p.serverCfg.TrustedProxies)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, p.dynCfg, errx.CodeParamInvalid, "请求体过大", http.StatusRequestEntityTooLarge)
			return
		}
		writeError(w, p.dynCfg, errx.CodeParamInvalid, "无法读取请求体", http.StatusBadRequest)
		return
	}

	// 验证端点由 WAF 自身处理，不能转发到被保护站点。
	if r.URL.Path == "/cc/verify" {
		p.handleVerify(w, r, rc)
		return
	}
	rc.Verified = p.verify.IsVerified(r, rc.IP)

	// 执行保护链评估
	decision := p.engine.Evaluate(r.Context(), rc)

	switch decision.Action {
	case protection.DecisionAllow:
		// 放行，转发至 upstream
		reverse.ServeHTTP(w, r)

	case protection.DecisionBlock:
		if rc.Verified && decision.AttackType == "穿盾攻击" {
			p.verify.ClearVerifiedCookie(w)
		}
		// 拦截：浏览器导航展示安全事件页，程序接口保持 JSON。
		p.writeBlocked(w, r, rc, decision)

	case protection.DecisionVerify:
		// 展示验证页
		p.serveVerificationPage(w, r, rc, decision.VerifyMode)
	}
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func (p *Proxy) writeBlocked(w http.ResponseWriter, r *http.Request, rc *reqctx.RequestContext, decision protection.Decision) {
	eventID := strings.TrimSpace(rc.EventID)
	w.Header().Set("X-JingShield-Event-ID", eventID)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if !wantsBlockedHTML(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(decision.StatusCode)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":     decision.ErrorCode,
			"message":  "请求已被鲸盾安全防护拦截",
			"event_id": eventID,
		})
		return
	}

	contact := strings.TrimSpace(p.dynCfg.GetDefault("security_contact", "网站安全管理员"))
	if contact == "" || len(contact) > 200 {
		contact = "网站安全管理员"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(decision.StatusCode)
	_ = blockedPage.Execute(w, map[string]string{
		"EventID":    eventID,
		"RiskType":   publicRiskType(decision.AttackType),
		"OccurredAt": time.Now().Format("2006-01-02 15:04:05 MST"),
		"Contact":    contact,
	})
}

func wantsBlockedHTML(r *http.Request) bool {
	path := strings.ToLower(r.URL.Path)
	for _, prefix := range []string{"/api", "/openapi", "/cc/"} {
		if path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(path, prefix) {
			return false
		}
	}
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return false
	}
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Dest"), "document") || strings.EqualFold(r.Header.Get("Sec-Fetch-Mode"), "navigate") {
		return true
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "text/html") && !strings.Contains(accept, "application/json")
}

// publicRiskType 只返回面向访客的泛化分类，禁止把规则名、表达式或命中详情带到响应中。
func publicRiskType(attackType string) string {
	switch attackType {
	case model.AttackTypeSQL:
		return "注入攻击风险"
	case model.AttackTypeXSS:
		return "脚本注入风险"
	case model.AttackTypeCC, model.AttackTypeVerifyFail:
		return "访问频率异常"
	case model.AttackTypeBlacklist, model.AttackTypeOversea:
		return "访问策略限制"
	case model.AttackTypeShieldBypass:
		return "异常客户端行为"
	case model.AttackTypePolicy:
		return "请求安全风险"
	case model.AttackTypePathTraversal:
		return "非法路径访问"
	case model.AttackTypeSSRF:
		return "非法请求目标"
	case model.AttackTypeXXE:
		return "非法数据提交"
	default:
		return "请求安全风险"
	}
}

func (p *Proxy) reverseFor(r *http.Request) (*httputil.ReverseProxy, error) {
	if p.sites == nil {
		return p.fallback, nil
	}
	site, hasSites, err := p.sites.ResolveSite(r.Context(), r.Host)
	if err != nil {
		return nil, err
	}
	if site == nil {
		if hasSites {
			return nil, nil
		}
		return p.fallback, nil
	}
	key := fmt.Sprintf("%s|%t|%t", site.Upstream, site.PassHost, site.TLSSkipVerify)
	p.reverseMu.RLock()
	rp := p.reverses[key]
	p.reverseMu.RUnlock()
	if rp != nil {
		return rp, nil
	}
	rp, err = newReverseProxy(site.Upstream, site.PassHost, site.TLSSkipVerify, p.timeout, p.dynCfg)
	if err != nil {
		return nil, err
	}
	p.reverseMu.Lock()
	if existing := p.reverses[key]; existing != nil {
		rp = existing
	} else {
		p.reverses[key] = rp
	}
	p.reverseMu.Unlock()
	return rp, nil
}

// serveVerificationPage 渲染验证页
// 对应 PHP showVerification() 各 showXxxVerification()
// 静态页面由 admin embed.FS 提供，路径 /cc/static/ccN.html
func (p *Proxy) serveVerificationPage(w http.ResponseWriter, r *http.Request, rc *reqctx.RequestContext, mode verify.Mode) {
	token, action, waitSeconds, difficulty, err := p.verify.NewChallenge(rc.IP, mode)
	if err != nil {
		writeError(w, p.dynCfg, errx.CodeInternal, "生成验证挑战失败", http.StatusInternalServerError)
		return
	}
	redirect := r.RequestURI
	if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
		redirect = "/"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = verificationPage.Execute(w, map[string]any{
		"Title": verify.ModeLabel(mode), "Token": token, "Action": action,
		"Wait": waitSeconds, "Difficulty": difficulty, "Redirect": redirect,
	})
}

func (p *Proxy) handleVerify(w http.ResponseWriter, r *http.Request, rc *reqctx.RequestContext) {
	if r.Method != http.MethodPost {
		writeError(w, p.dynCfg, errx.CodeParamInvalid, "仅支持 POST 验证", http.StatusMethodNotAllowed)
		return
	}
	action := rc.Post.Get("action")
	token := rc.Post.Get("token")
	proof := rc.Post.Get("proof")
	ok, err := p.verify.HandleVerify(r.Context(), rc, action, token, proof)
	if err != nil || !ok {
		message := "验证失败"
		if err != nil {
			message = err.Error()
		}
		writeError(w, p.dynCfg, errx.CodeVerifyFail, message, http.StatusForbidden)
		return
	}
	p.verify.IssueVerifiedCookie(w, rc.IP)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "message": "验证成功"})
}

// writeError 输出错误响应
// 对应 PHP CCProtection::outputError()
// 根据 error_output_format 配置输出 JSON 或 HTML
func writeError(w http.ResponseWriter, dynCfg *config.DynamicConfig, code int, message string, status int) {
	format := dynCfg.GetDefault("error_output_format", "json")

	if format == "html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		// HTML 错误页（对应 custom_error_page 模板，含 {{code}}/{{message}} 占位符）
		customPage := dynCfg.GetDefault("custom_error_page", defaultErrorPage)
		tmpl, err := template.New("error").Parse(customPage)
		if err != nil {
			// 模板解析失败兜底 JSON
			writeJSONError(w, code, message)
			return
		}
		_ = tmpl.Execute(w, map[string]string{
			"code":    fmt.Sprintf("%d", code),
			"message": message,
		})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	writeJSONError(w, code, message)
}

// writeJSONError 输出 JSON 错误
func writeJSONError(w http.ResponseWriter, code int, message string) {
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    code,
		"message": message,
	})
}

var verificationPage = template.Must(template.New("verification").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title><style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6fb;font-family:system-ui,sans-serif;color:#253047}
.card{width:min(420px,calc(100% - 40px));padding:36px;background:#fff;border-radius:16px;box-shadow:0 12px 40px #25304720;text-align:center}
button{border:0;border-radius:10px;padding:12px 24px;background:#667eea;color:#fff;font-size:16px;cursor:pointer}button:disabled{opacity:.55;cursor:wait}.msg{min-height:24px;color:#667085}
</style></head><body><main class="card"><h1>{{.Title}}</h1><p class="msg" id="msg">正在执行安全检查，请稍候…</p>
<button id="verify" disabled>继续访问</button></main>
<div id="challenge" data-token="{{.Token}}" data-action="{{.Action}}" data-wait="{{.Wait}}" data-difficulty="{{.Difficulty}}" data-redirect="{{.Redirect}}"></div>
<script>
const c=document.getElementById('challenge'),b=document.getElementById('verify'),m=document.getElementById('msg');
let proof='',waitDone=false,proofDone=false;
const ready=()=>{if(waitDone&&proofDone){b.disabled=false;m.textContent='安全检查完成，请继续'}};
let left=Number(c.dataset.wait); const tick=()=>{if(left<=0){waitDone=true;ready();return;}m.textContent='正在检查，约 '+left+' 秒';left--;setTimeout(tick,1000)};tick();
const zeroBits=(bytes,bits)=>{const full=Math.floor(bits/8),rest=bits%8;for(let i=0;i<full;i++)if(bytes[i]!==0)return false;const mask=(255<<(8-rest))&255;return rest===0||(bytes[full]&mask)===0};
(async()=>{const enc=new TextEncoder(),difficulty=Number(c.dataset.difficulty);for(let i=0;;i++){const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(c.dataset.token+'|'+i)));if(zeroBits(hash,difficulty)){proof=String(i);proofDone=true;ready();return}if(i%500===0)await new Promise(r=>setTimeout(r,0))}})();
b.onclick=async()=>{b.disabled=true;m.textContent='正在验证…';const body=new URLSearchParams({action:c.dataset.action,token:c.dataset.token,proof});
try{const r=await fetch('/cc/verify',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});if(!r.ok)throw new Error((await r.json()).message||'验证失败');location.assign(c.dataset.redirect)}catch(e){m.textContent=e.message;b.disabled=false}};
</script></body></html>`))

var blockedPage = template.Must(template.New("blocked").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<link rel="icon" type="image/svg+xml" href="/admin/favicon.svg">
<link rel="alternate icon" type="image/x-icon" href="/admin/favicon.ico">
<title>请求已拦截 · 鲸盾安全防护</title>
<style>
:root{color-scheme:dark;font-family:Inter,"PingFang SC","Microsoft YaHei",system-ui,sans-serif;background:#050a14;color:#eef7ff}
*{box-sizing:border-box}body{margin:0;min-height:100vh;overflow-x:hidden;background:radial-gradient(circle at 18% 12%,#0f4e6c55 0,transparent 34%),radial-gradient(circle at 82% 84%,#123f7a44 0,transparent 32%),linear-gradient(145deg,#040811 0%,#081423 52%,#050b15 100%)}
body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.28;background-image:linear-gradient(#6bdcff0c 1px,transparent 1px),linear-gradient(90deg,#6bdcff0c 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(to bottom,#000,transparent 90%)}
.shell{position:relative;z-index:1;min-height:100vh;display:grid;place-items:center;padding:36px 20px}.card{width:min(850px,100%);overflow:hidden;border:1px solid #70dfff2b;border-radius:24px;background:linear-gradient(145deg,#0c1929ed,#08111eee);box-shadow:0 32px 90px #000a,0 0 0 1px #ffffff06 inset}
.top{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:22px 28px;border-bottom:1px solid #7bdbff1c;background:#07111d99}.brand{display:flex;align-items:center;gap:12px}.mark{width:42px;height:42px;display:grid;place-items:center;border-radius:13px;color:#75e4ff;background:linear-gradient(145deg,#0e5570,#0b2d49);box-shadow:0 0 28px #39c7f333}.mark svg{width:26px;height:26px}.brand strong{display:block;font-size:17px;letter-spacing:.08em}.brand span{display:block;margin-top:2px;color:#7190a6;font-size:10px;letter-spacing:.22em}.state{display:flex;align-items:center;gap:8px;color:#ff9b9b;font:700 11px/1 system-ui;letter-spacing:.16em}.state i{width:8px;height:8px;border-radius:50%;background:#ff6262;box-shadow:0 0 14px #ff6262}
.content{padding:48px 52px 42px}.status-line{display:flex;align-items:center;gap:10px;color:#62dff6;font-size:12px;font-weight:700;letter-spacing:.14em}.status-line:before{content:"";width:32px;height:1px;background:#62dff6}.content h1{max-width:620px;margin:19px 0 14px;font-size:clamp(30px,5vw,48px);line-height:1.12;letter-spacing:-.04em}.lead{max-width:660px;margin:0;color:#9eb2c3;font-size:16px;line-height:1.8}
.details{display:grid;grid-template-columns:1.45fr 1fr 1fr;gap:12px;margin:34px 0}.item{min-width:0;padding:17px 18px;border:1px solid #77cce81c;border-radius:14px;background:#07101d99}.item span{display:block;margin-bottom:8px;color:#66849a;font-size:11px;letter-spacing:.1em}.item strong,.item time{display:block;overflow-wrap:anywhere;color:#e8f7ff;font-size:14px;font-weight:650}.item.event strong{color:#71e2ff;font-family:"SFMono-Regular",Consolas,monospace;letter-spacing:.02em}
.notice{display:flex;align-items:flex-start;gap:13px;padding:17px 18px;border-left:3px solid #3ed1ec;border-radius:4px 12px 12px 4px;background:#0a2534aa;color:#9fbaca;font-size:13px;line-height:1.7}.notice svg{flex:none;width:19px;height:19px;margin-top:2px;color:#5de0f6}.notice strong{color:#eefaff}.foot{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-top:30px;color:#526c81;font-size:11px}.foot span:last-child{font-family:Consolas,monospace;letter-spacing:.08em}
@media(max-width:680px){.shell{padding:14px}.top{padding:18px}.state{display:none}.content{padding:34px 22px 28px}.details{grid-template-columns:1fr}.foot{align-items:flex-start;flex-direction:column}.content h1{font-size:32px}}
</style>
</head>
<body><main class="shell"><section class="card" aria-labelledby="block-title">
<header class="top"><div class="brand"><div class="mark" aria-hidden="true"><svg viewBox="0 0 64 64" fill="none"><path d="M14 33c7-1 10-7 11-15 7 3 11 8 12 14 4-4 8-6 14-5-2 13-10 22-23 22-9 0-16-5-18-13 8 3 14 1 19-4" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M31 13v7M27.5 16.5h7" stroke="currentColor" stroke-width="3" stroke-linecap="round"/></svg></div><div><strong>捷云鲸盾</strong><span>JINGSHIELD SECURITY</span></div></div><div class="state"><i></i>REQUEST BLOCKED</div></header>
<div class="content"><div class="status-line">SECURITY INTERCEPTION</div><h1 id="block-title">当前请求已被安全防护拦截</h1><p class="lead">鲸盾检测到本次访问存在安全风险，已终止请求以保护业务系统。若这是正常操作，请勿重复提交，并联系网站安全管理员核查。</p>
<div class="details"><div class="item event"><span>事件编号 / EVENT ID</span><strong>{{.EventID}}</strong></div><div class="item"><span>风险类型</span><strong>{{.RiskType}}</strong></div><div class="item"><span>拦截时间</span><time>{{.OccurredAt}}</time></div></div>
<div class="notice"><svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" stroke="currentColor" stroke-width="1.8"/><path d="M12 8v5m0 3h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg><div>如需申诉，请将事件编号 <strong>{{.EventID}}</strong> 提供给：<strong>{{.Contact}}</strong>。</div></div>
<footer class="foot"><span>Protected by JingShield Web Application Firewall</span><span>HTTP SECURITY EVENT</span></footer></div>
</section></main></body></html>`))

// defaultErrorPage 默认 HTML 错误页（对应 PHP 默认 custom_error_page）
const defaultErrorPage = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><title>访问限制</title>
<style>body{font-family:Arial,sans-serif;background:#f4f4f4;margin:0;display:flex;justify-content:center;align-items:center;height:100vh;}
.e{background:#fff;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);text-align:center;}
.c{font-size:48px;font-weight:700;color:#e74c3c;} .m{font-size:18px;color:#333;margin:10px 0;} .d{color:#666;font-size:14px;}</style></head>
<body><div class="e"><div class="c">{{.code}}</div><div class="m">{{.message}}</div><div class="d">如有疑问，请联系网站管理员</div></div></body></html>`

// adminStaticFS 验证页静态资源（由 admin 包注入，避免循环依赖）
// 在 main 启动时通过 SetStaticFS 注入
var adminStaticFS fs.FS

// SetStaticFS 注入静态资源文件系统（验证页 HTML/JS）
func SetStaticFS(fsys fs.FS) {
	adminStaticFS = fsys
}

// Upstream 返回 upstream 地址（供诊断）
func (p *Proxy) Upstream() string { return p.upstream }
