package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"jingshield/internal/config"
	"jingshield/internal/model"
	"jingshield/internal/protection/reqctx"
	"jingshield/internal/repository"
)

const (
	ActionBlock = 1
	ActionLog   = 2
	maxRulePack = 2 << 20
)

var validTargets = map[string]bool{"all": true, "uri": true, "args": true, "headers": true, "body": true, "method": true}

type RuleInput struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Target      string `json:"target"`
	Pattern     string `json:"pattern"`
	Action      int    `json:"action"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority"`
	Description string `json:"description"`
}

type RulePack struct {
	Schema  string      `json:"schema"`
	Version string      `json:"version"`
	Rules   []RuleInput `json:"rules"`
}

type signedEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type compiledRule struct {
	rule *model.PolicyRule
	re   *regexp.Regexp
}

type Match struct {
	RuleID   int64
	RuleName string
	Action   int
	Detail   string
}

type Service struct {
	repo        *repository.PolicyRepo
	dynamic     *config.DynamicConfig
	mu          sync.RWMutex
	rules       []compiledRule
	loaded      time.Time
	updateMu    sync.Mutex
	lastAttempt time.Time
}

func New(repo *repository.PolicyRepo, dynamic *config.DynamicConfig) *Service {
	return &Service{repo: repo, dynamic: dynamic}
}

func ValidateRule(input RuleInput) (*model.PolicyRule, error) {
	input.Name, input.Category, input.Target = strings.TrimSpace(input.Name), strings.TrimSpace(input.Category), strings.ToLower(strings.TrimSpace(input.Target))
	input.Pattern, input.Description = strings.TrimSpace(input.Pattern), strings.TrimSpace(input.Description)
	if len(input.Name) < 1 || len(input.Name) > 100 || len(input.Category) < 1 || len(input.Category) > 50 || !validTargets[input.Target] {
		return nil, errors.New("策略名称、分类或匹配目标非法")
	}
	if len(input.Pattern) < 1 || len(input.Pattern) > 1000 {
		return nil, errors.New("策略正则长度必须为 1-1000")
	}
	if _, err := regexp.Compile(input.Pattern); err != nil {
		return nil, fmt.Errorf("策略正则不兼容 RE2: %w", err)
	}
	if input.Action != ActionBlock && input.Action != ActionLog {
		return nil, errors.New("策略动作必须为 1=拦截或 2=仅记录")
	}
	if input.Priority < 1 || input.Priority > 10000 || len(input.Description) > 255 {
		return nil, errors.New("策略优先级或描述非法")
	}
	return &model.PolicyRule{Name: input.Name, Category: input.Category, Target: input.Target, Pattern: input.Pattern, Action: input.Action, Enabled: input.Enabled, Priority: input.Priority, Description: input.Description}, nil
}

func (s *Service) List(ctx context.Context) ([]*model.PolicyRule, error) { return s.repo.List(ctx) }
func (s *Service) Create(ctx context.Context, input RuleInput) (*model.PolicyRule, error) {
	rule, err := ValidateRule(input)
	if err != nil {
		return nil, err
	}
	rule.Source, rule.Version = "custom", "1"
	if err := s.repo.Create(ctx, rule); err != nil {
		return nil, err
	}
	s.Invalidate()
	return rule, nil
}
func (s *Service) Update(ctx context.Context, id int64, source, version string, input RuleInput) (*model.PolicyRule, error) {
	rule, err := ValidateRule(input)
	if err != nil {
		return nil, err
	}
	rule.ID, rule.Source, rule.Version = id, source, version
	if err := s.repo.Update(ctx, rule); err != nil {
		return nil, err
	}
	s.Invalidate()
	return rule, nil
}
func (s *Service) Delete(ctx context.Context, id int64) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	s.Invalidate()
	return nil
}

func (s *Service) Import(ctx context.Context, pack RulePack, source string) (int, error) {
	if pack.Schema != "jingshield.rules/v1" || len(pack.Version) < 1 || len(pack.Version) > 50 || len(pack.Rules) > 5000 {
		return 0, errors.New("规则包 schema、版本或规则数量非法")
	}
	rules := make([]*model.PolicyRule, 0, len(pack.Rules))
	for _, input := range pack.Rules {
		rule, err := ValidateRule(input)
		if err != nil {
			return 0, fmt.Errorf("规则 %q 非法: %w", input.Name, err)
		}
		rule.Source, rule.Version = source, pack.Version
		rules = append(rules, rule)
	}
	if err := s.repo.ReplaceSource(ctx, source, rules); err != nil {
		return 0, err
	}
	s.Invalidate()
	return len(rules), nil
}

func (s *Service) Invalidate() { s.mu.Lock(); s.loaded = time.Time{}; s.mu.Unlock() }

func (s *Service) Match(ctx context.Context, rc *reqctx.RequestContext) *Match {
	if err := s.ensureRules(ctx); err != nil {
		return nil
	}
	s.mu.RLock()
	rules := append([]compiledRule(nil), s.rules...)
	s.mu.RUnlock()
	for _, item := range rules {
		if item.re.MatchString(targetValue(item.rule.Target, rc)) {
			return &Match{RuleID: item.rule.ID, RuleName: item.rule.Name, Action: item.rule.Action, Detail: fmt.Sprintf("命中策略 %s（#%d）", item.rule.Name, item.rule.ID)}
		}
	}
	return nil
}

func (s *Service) ensureRules(ctx context.Context) error {
	s.mu.RLock()
	fresh := !s.loaded.IsZero() && time.Since(s.loaded) < 5*time.Second
	s.mu.RUnlock()
	if fresh {
		return nil
	}
	list, err := s.repo.ListEnabled(ctx)
	if err != nil {
		return err
	}
	compiled := make([]compiledRule, 0, len(list))
	for _, rule := range list {
		re, err := regexp.Compile(rule.Pattern)
		if err == nil {
			compiled = append(compiled, compiledRule{rule: rule, re: re})
		}
	}
	s.mu.Lock()
	s.rules, s.loaded = compiled, time.Now()
	s.mu.Unlock()
	return nil
}

func targetValue(target string, rc *reqctx.RequestContext) string {
	args := strings.Join(rc.AllParamValues(), "\n")
	body := strings.Join(rc.BodyValues, "\n")
	headers := make([]string, 0, len(rc.Header))
	for key, values := range rc.Header {
		headers = append(headers, key+":"+strings.Join(values, ","))
	}
	switch target {
	case "uri":
		return rc.URI
	case "args":
		return args
	case "headers":
		return strings.Join(headers, "\n")
	case "body":
		return body
	case "method":
		return rc.Method
	}
	return strings.Join([]string{rc.URI, rc.Method, args, body, strings.Join(headers, "\n")}, "\n")
}

func (s *Service) StartAutoUpdate(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.maybeUpdate(ctx)
			}
		}
	}()
}

func (s *Service) maybeUpdate(ctx context.Context) {
	if !s.dynamic.GetBool("policy_auto_update") {
		return
	}
	interval := time.Duration(s.dynamic.GetIntDefault("policy_update_interval_minutes", 360)) * time.Minute
	s.updateMu.Lock()
	due := s.lastAttempt.IsZero() || time.Since(s.lastAttempt) >= interval
	if due {
		s.lastAttempt = time.Now()
	}
	s.updateMu.Unlock()
	if !due {
		return
	}
	if _, _, err := s.UpdateNow(ctx); err != nil {
		_ = s.dynamic.Set(context.Background(), "policy_last_error", truncate(err.Error(), 500))
	}
}

func (s *Service) UpdateNow(ctx context.Context) (string, int, error) {
	rawURL := s.dynamic.Get("policy_update_url")
	publicKeyText := s.dynamic.Get("policy_update_public_key")
	if err := validatePublicURL(ctx, rawURL); err != nil {
		return "", 0, err
	}
	publicKey, err := decodeBase64(publicKeyText)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return "", 0, errors.New("策略更新 Ed25519 公钥非法")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = safeDialContext
	client := &http.Client{Timeout: 20 * time.Second, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("策略更新重定向过多")
		}
		return validatePublicURL(req.Context(), req.URL.String())
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("策略更新返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRulePack+1))
	if err != nil {
		return "", 0, err
	}
	if len(body) > maxRulePack {
		return "", 0, errors.New("策略更新包超过 2MB")
	}
	var envelope signedEnvelope
	if json.Unmarshal(body, &envelope) != nil {
		return "", 0, errors.New("策略更新包信封格式非法")
	}
	payload, err := decodeBase64(envelope.Payload)
	if err != nil {
		return "", 0, errors.New("策略更新 payload 非法")
	}
	signature, err := decodeBase64(envelope.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return "", 0, errors.New("策略更新签名校验失败")
	}
	var pack RulePack
	if json.Unmarshal(payload, &pack) != nil {
		return "", 0, errors.New("策略更新 payload JSON 非法")
	}
	count, err := s.Import(ctx, pack, "auto")
	if err != nil {
		return "", 0, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_ = s.dynamic.Set(ctx, "policy_last_version", pack.Version)
	_ = s.dynamic.Set(ctx, "policy_last_update", now)
	_ = s.dynamic.Set(ctx, "policy_last_error", "")
	return pack.Version, count, nil
}

func safeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("解析策略更新地址失败: %w", err)
	}
	for _, ip := range ips {
		if !isPublicUpdateIP(ip) {
			return nil, errors.New("策略更新地址不能解析到内网、回环或链路本地 IP")
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	for _, ip := range ips {
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		err = dialErr
	}
	return nil, err
}

func validatePublicURL(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return errors.New("策略更新地址必须是无账号信息的 HTTPS URL")
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", u.Hostname())
	if err != nil {
		return fmt.Errorf("解析策略更新地址失败: %w", err)
	}
	for _, ip := range ips {
		if !isPublicUpdateIP(ip) {
			return errors.New("策略更新地址不能解析到内网、回环或链路本地 IP")
		}
	}
	return nil
}
func isPublicUpdateIP(ip net.IP) bool {
	return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && !ip.IsMulticast()
}
func decodeBase64(value string) ([]byte, error) {
	if data, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return data, nil
	}
	return base64.StdEncoding.DecodeString(value)
}
func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
