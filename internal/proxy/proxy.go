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
	rp.Transport = &http.Transport{
		ResponseHeaderTimeout: time.Duration(timeout) * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: tlsSkipVerify}, // #nosec G402 -- explicit per-site opt-in for private self-signed origins
	}
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
			req.Host = target.Host
		}
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logx.Error("upstream 转发失败", "err", err, "upstream", rawURL, "url", r.URL.String())
		writeError(w, dynCfg, errx.CodeInternal, "后端服务不可用", http.StatusBadGateway)
	}
	return rp, nil
}

// ServeHTTP 处理请求：先跑保护链，再决定转发或拦截
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		// 拦截：输出错误响应
		writeError(w, p.dynCfg, decision.ErrorCode, decision.ErrorMessage, decision.StatusCode)

	case protection.DecisionVerify:
		// 展示验证页
		p.serveVerificationPage(w, r, rc, decision.VerifyMode)
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
