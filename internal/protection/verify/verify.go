package verify

// 验证流程服务：8 种验证模式 + 签名 cookie
// 对应 PHP verify.php + CCProtection::showVerification()
//
// 安全改进：原 cc_verified cookie 为裸值 "1"，易伪造；
// 本实现用 HMAC-SHA256 签名（payload=ip|expiry），防伪造。

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"jingshield/internal/config"
	"jingshield/internal/protection/reqctx"
	"jingshield/internal/repository"
	"jingshield/internal/store"
)

// Mode 验证模式枚举
// 对应 PHP showVerification() 的 switch case
type Mode int

const (
	Mode5Second       Mode = 1 // 5 秒盾
	ModeSlide         Mode = 2 // 滑动验证
	ModeClick         Mode = 3 // 点击验证
	Mode302Redirect   Mode = 4 // 302 跳转验证
	ModeJSRedirect    Mode = 5 // JS 跳转验证
	ModeRotate        Mode = 6 // 旋转验证
	ModeSecurityCheck Mode = 7 // 安全检测防护模式
	ModeHuman         Mode = 8 // 人机滑块验证
)

// 验证模式对应的静态页面文件名（embed.FS 路径）
var modePageFile = map[Mode]string{
	Mode5Second:       "cc1.html",
	ModeSlide:         "cc2.html",
	ModeClick:         "cc3.html",
	Mode302Redirect:   "cc4.html",
	ModeJSRedirect:    "cc5.html",
	ModeRotate:        "cc6.html",
	ModeSecurityCheck: "cc7.html",
	ModeHuman:         "cc7.html", // 复用人机页面
}

const maxOutstandingChallenges = 10000

// cookieName 验证 cookie 名称
const cookieName = "cc_verified"

// Service 验证服务
type Service struct {
	verifyFail *repository.VerifyFailRepo
	ipList     *repository.IPListRepo
	st         store.StateStore
	dynCfg     *config.DynamicConfig
	session    config.SessionConfig
	mu         sync.Mutex
	challenges map[string]challengeClaims
}

// New 构造验证服务
func New(vf *repository.VerifyFailRepo, ip *repository.IPListRepo, st store.StateStore, dynCfg *config.DynamicConfig, session config.SessionConfig) *Service {
	return &Service{
		verifyFail: vf,
		ipList:     ip,
		st:         st,
		dynCfg:     dynCfg,
		session:    session,
		challenges: make(map[string]challengeClaims),
	}
}

type challengeClaims struct {
	IP         string `json:"ip"`
	Action     string `json:"action"`
	Nonce      string `json:"nonce"`
	Difficulty int    `json:"difficulty"`
	IssuedAt   int64  `json:"iat"`
	ExpiresAt  int64  `json:"exp"`
}

// ModeFromInt 整数配置转验证模式
func ModeFromInt(n int) Mode {
	if n < 1 || n > 8 {
		return Mode5Second
	}
	return Mode(n)
}

// PageFile 取验证模式对应的静态页面文件名
func PageFile(m Mode) string {
	if f, ok := modePageFile[m]; ok {
		return f
	}
	return "cc1.html"
}

// ActionForMode 返回模式对应的验证动作。
func ActionForMode(m Mode) string {
	switch m {
	case ModeSlide:
		return "verify_slide"
	case ModeClick:
		return "verify_click"
	case Mode302Redirect:
		return "verify_302"
	case ModeJSRedirect:
		return "verify_jsredirect"
	case ModeRotate:
		return "verify_rotate"
	case ModeSecurityCheck:
		return "verify_securitycheck"
	case ModeHuman:
		return "verify_human"
	default:
		return "verify_5second"
	}
}

// ModeLabel 返回验证页展示名称。
func ModeLabel(m Mode) string {
	labels := map[Mode]string{
		Mode5Second: "5 秒安全检测", ModeSlide: "滑动验证", ModeClick: "点击验证",
		Mode302Redirect: "跳转验证", ModeJSRedirect: "浏览器验证", ModeRotate: "旋转验证",
		ModeSecurityCheck: "安全检测", ModeHuman: "人机验证",
	}
	if label := labels[m]; label != "" {
		return label
	}
	return labels[Mode5Second]
}

// NewChallenge 签发短期、单次使用且绑定客户端 IP 与验证模式的挑战。
func (s *Service) NewChallenge(ip string, mode Mode) (token, action string, waitSeconds, difficulty int, err error) {
	random := make([]byte, 18)
	if _, err = rand.Read(random); err != nil {
		return "", "", 0, 0, fmt.Errorf("生成验证挑战失败: %w", err)
	}
	now := time.Now()
	action = ActionForMode(mode)
	waitSeconds = 1
	difficulty = 14
	if mode == Mode5Second {
		waitSeconds = 5
	}
	claims := challengeClaims{
		IP: ip, Action: action, Nonce: base64.RawURLEncoding.EncodeToString(random), Difficulty: difficulty,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", "", 0, 0, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	token = encoded + "." + s.sign(encoded)

	s.mu.Lock()
	for nonce, existing := range s.challenges {
		if existing.ExpiresAt <= now.Unix() {
			delete(s.challenges, nonce)
		}
	}
	// 对未完成挑战设置硬上限，避免攻击者只请求验证页而不提交导致内存增长。
	if len(s.challenges) >= maxOutstandingChallenges {
		for nonce := range s.challenges {
			delete(s.challenges, nonce)
			if len(s.challenges) < maxOutstandingChallenges*9/10 {
				break
			}
		}
	}
	s.challenges[claims.Nonce] = claims
	s.mu.Unlock()
	return token, action, waitSeconds, difficulty, nil
}

// HandleVerify 处理验证请求
// 对应 PHP verify.php 的 switch($action)
// action 取值：verify_5second/verify_slide/verify_click/verify_302/verify_jsredirect/verify_rotate/verify_securitycheck/verify_human
func (s *Service) HandleVerify(ctx context.Context, rc *reqctx.RequestContext, action, token, proof string) (bool, error) {
	if err := s.validateChallenge(rc.IP, action, token, proof); err != nil {
		s.recordFailure(ctx, rc.IP)
		return false, err
	}
	return s.verificationSuccess(ctx, rc)
}

func (s *Service) validateChallenge(ip, action, token, proof string) error {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(s.sign(parts[0]))) {
		return errors.New("无效的验证令牌")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("无效的验证令牌")
	}
	var claims challengeClaims
	if json.Unmarshal(payload, &claims) != nil || claims.IP != ip || claims.Action != action {
		return errors.New("验证令牌与当前请求不匹配")
	}
	now := time.Now().Unix()
	if claims.ExpiresAt <= now || claims.IssuedAt > now {
		return errors.New("验证令牌已过期")
	}
	minimumWait := int64(1)
	if action == "verify_5second" {
		minimumWait = 5
	}
	if now-claims.IssuedAt < minimumWait {
		return errors.New("验证尚未完成")
	}
	if !validProof(token, proof, claims.Difficulty) {
		return errors.New("验证工作量证明无效")
	}

	s.mu.Lock()
	stored, ok := s.challenges[claims.Nonce]
	if ok && stored == claims {
		delete(s.challenges, claims.Nonce)
	}
	s.mu.Unlock()
	if !ok || stored != claims {
		return errors.New("验证令牌已使用或不存在")
	}
	return nil
}

func validProof(token, proof string, difficulty int) bool {
	if proof == "" || len(proof) > 20 || difficulty < 8 || difficulty > 24 {
		return false
	}
	digest := sha256.Sum256([]byte(token + "|" + proof))
	fullBytes := difficulty / 8
	remainingBits := difficulty % 8
	for i := 0; i < fullBytes; i++ {
		if digest[i] != 0 {
			return false
		}
	}
	if remainingBits == 0 {
		return true
	}
	mask := byte(0xff << (8 - remainingBits))
	return digest[fullBytes]&mask == 0
}

func (s *Service) recordFailure(ctx context.Context, ip string) {
	count, err := s.verifyFail.RecordFail(ctx, ip)
	if err != nil {
		return
	}
	limit := s.dynCfg.GetIntDefault("cc_verify_fail_limit", 10)
	if count >= limit {
		seconds := s.dynCfg.GetIntDefault("cc_blacklist_time", 3600)
		_ = s.ipList.AddTempBlacklist(ctx, ip, "验证失败次数超过限制", seconds)
	}
}

// verificationSuccess 验证成功处理
// 对应 PHP verify.php verificationSuccess()
// 1. 移除临时黑名单 2. 清零验证失败次数 3. 清理内存状态 4. 设置签名 cookie
func (s *Service) verificationSuccess(ctx context.Context, rc *reqctx.RequestContext) (bool, error) {
	// 移除临时黑名单
	if err := s.ipList.RemoveTempBlacklist(ctx, rc.IP); err != nil {
		return false, fmt.Errorf("移除临时黑名单失败: %w", err)
	}
	// 清零验证失败次数
	if err := s.verifyFail.Reset(ctx, rc.IP); err != nil {
		return false, fmt.Errorf("清理验证失败次数失败: %w", err)
	}
	// 清理内存状态
	if err := s.st.ResetIP(ctx, rc.IP); err != nil {
		return false, fmt.Errorf("清理防护状态失败: %w", err)
	}
	return true, nil
}

// IssueVerifiedCookie 设置已验证签名 cookie
// cookie 值 = base64(ip|expiry).base64(hmac)
func (s *Service) IssueVerifiedCookie(w http.ResponseWriter, ip string) {
	expiry := time.Now().Add(time.Duration(s.session.VerifyCookieMaxAge) * time.Second).Unix()
	payload := ip + "|" + strconv.FormatInt(expiry, 10)
	sig := s.sign(payload)
	value := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		Domain:   s.session.Domain,
		Expires:  time.Unix(expiry, 0),
		MaxAge:   s.session.VerifyCookieMaxAge,
		Secure:   s.session.Secure,
		HttpOnly: true, // 安全属性：禁止 JS 读取
		SameSite: http.SameSiteLaxMode,
	})
}

// IsVerified 校验请求中的 cc_verified cookie 是否合法且未过期
// 对应 PHP checkCCAttack() 中 $_COOKIE['cc_verified']==1 的判断（增强版）
func (s *Service) IsVerified(r *http.Request, ip string) bool {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return false
	}
	return s.validateCookie(c.Value, ip)
}

// ClearVerifiedCookie 清除验证 cookie（穿盾命中时调用）
func (s *Service) ClearVerifiedCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.session.Domain,
		MaxAge:   -1,
		Expires:  time.Now().Add(-time.Hour),
		Secure:   s.session.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// sign 对 payload 计算 HMAC-SHA256 签名，返回 base64
func (s *Service) sign(payload string) string {
	mac := hmac.New(sha256.New, []byte(s.session.Secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// validateCookie 校验签名 cookie：拆分 payload+sig，常量时间比较，并校验 IP 与过期
func (s *Service) validateCookie(value, ip string) bool {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	payload := string(payloadBytes)

	// 常量时间比较签名（防时序攻击）
	expectedSig := s.sign(payload)
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return false
	}

	// 校验 payload 中的 IP 与过期时间
	fields := strings.SplitN(payload, "|", 2)
	if len(fields) != 2 {
		return false
	}
	if fields[0] != ip {
		return false
	}
	expiry, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() < expiry
}
