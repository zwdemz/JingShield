package operations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"jingshield/internal/pkg/iputil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type peerClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Linkage returns a credential-free snapshot. Vendor names label adapters, not
// native product support; compatibility requires a fresh protocol handshake.
func (s *Service) Linkage() (LinkageConfig, LinkageStatus) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status := s.linkageStatus
	status.IntegrationMode = "same_protocol_adapter_only"
	if status.LastResult != nil {
		copyResult := *status.LastResult
		copyResult.SkippedIPs = append([]string{}, status.LastResult.SkippedIPs...)
		status.LastResult = &copyResult
	}
	return s.linkage, status
}

// ConfigureLinkage persists validated settings and clears prior compatibility.
// It does not send requests or persist the referenced secret's contents.
func (s *Service) ConfigureLinkage(ctx context.Context, cfg LinkageConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if s.store == nil {
		return ErrUnavailable
	}
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	if err := s.store.save(ctx, "operations_linkage_config", cfg); err != nil {
		return err
	}
	s.mu.Lock()
	s.linkage = cfg
	s.linkageStatus = LinkageStatus{}
	s.mu.Unlock()
	return nil
}

// ProbeLinkage checks only authenticated capability metadata, never enforcement.
// Failure messages intentionally omit endpoints, remote bodies and credentials.
func (s *Service) ProbeLinkage(ctx context.Context) (*Capabilities, error) {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	cfg, _ := s.Linkage()
	capabilities, err := s.probe(ctx, cfg)
	s.recordProbe(err)
	return capabilities, err
}

func (s *Service) probe(ctx context.Context, cfg LinkageConfig) (*Capabilities, error) {
	if !cfg.Enabled {
		return nil, errors.New("设备联动已停用")
	}
	var capabilities Capabilities
	if err := s.peerRequest(ctx, cfg, http.MethodGet, "/openapi/v1/capabilities", nil, &capabilities); err != nil {
		return nil, err
	}
	compatible := capabilities.Protocol == Protocol && capabilities.DeviceType == cfg.DeviceType && capabilities.MaxBatchSize >= 1 && capabilities.MaxBatchSize <= MaxBatchSize && capabilities.MaxExpireSeconds >= 0 && capabilities.MaxExpireSeconds <= 31536000
	supportsBatch := false
	for _, operation := range capabilities.Capabilities {
		if operation == "block-batch" {
			supportsBatch = true
		}
	}
	if !compatible || !supportsBatch {
		return nil, errors.New("对端未声明兼容的 jingshield-v1 批量封禁能力；厂商原生 API 不能直接联动")
	}
	return &capabilities, nil
}

func (s *Service) recordProbe(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.linkageStatus.LastProbe = time.Now().UTC().Format(time.RFC3339)
	s.linkageStatus.Compatible = err == nil
	if err != nil {
		s.linkageStatus.LastError = err.Error()
	} else {
		s.linkageStatus.LastError = ""
	}
}

// BlockPeer validates a bounded batch, rechecks protocol capabilities and sends
// exactly one enforcement request. Ambiguous network failures are never retried
// automatically, preventing duplicate side effects on non-idempotent adapters.
func (s *Service) BlockPeer(ctx context.Context, input BlockRequest) (*BlockResult, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	cfg, _ := s.Linkage()
	capabilities, err := s.probe(ctx, cfg)
	s.recordProbe(err)
	if err != nil {
		return nil, err
	}
	if len(input.IPs) > capabilities.MaxBatchSize {
		return nil, errors.New("本次批量数量超过对端能力上限")
	}
	if capabilities.MaxExpireSeconds > 0 && input.ExpireSeconds > capabilities.MaxExpireSeconds {
		return nil, errors.New("本次封禁有效期超过对端能力上限")
	}
	if s.store == nil {
		return nil, ErrUnavailable
	}
	if err = s.store.audit(ctx, "requested", len(input.IPs)); err != nil {
		return nil, errors.New("无法记录联动操作审计，已阻止下发")
	}
	var result BlockResult
	err = s.peerRequest(ctx, cfg, http.MethodPost, "/openapi/v1/ip/block-batch", input, &result)
	if err == nil {
		err = validateBlockResult(input, result)
	}
	outcome := "confirmed"
	if err != nil {
		outcome = "unconfirmed"
	}
	// Complete an outcome record even if the requesting browser disconnected.
	auditContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	auditError := s.store.audit(auditContext, outcome, len(input.IPs))
	cancel()
	if auditError != nil && err == nil {
		err = errors.New("对端已响应但结果审计失败，请核查设备状态，勿自动重试")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.linkageStatus.LastError = err.Error()
		return nil, err
	}
	s.linkageStatus.LastSuccess = time.Now().UTC().Format(time.RFC3339)
	s.linkageStatus.LastError = ""
	s.linkageStatus.LastResult = &result
	return &result, nil
}

// PushWhitelist performs a fresh capability handshake and one explicit snapshot
// delivery. It records intent before the network call and never retries an
// ambiguous result automatically. Rules from other sources remain untouched.
func (s *Service) PushWhitelist(ctx context.Context, input WhitelistRequest) (*WhitelistResult, error) {
	if input.Source == "" || input.Revision <= 0 {
		return nil, errors.New("白名单来源或版本非法")
	}
	rules, err := iputil.NormalizeWhitelistRules(input.Rules)
	if err != nil {
		return nil, err
	}
	input.Rules = rules
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	cfg, _ := s.Linkage()
	if input.Source != cfg.SourceID || cfg.SourceID == "" {
		return nil, errors.New("请先配置与本节点对应的白名单来源 ID")
	}
	capabilities, err := s.probe(ctx, cfg)
	s.recordProbe(err)
	if err != nil {
		return nil, err
	}
	supportsWhitelist := false
	for _, operation := range capabilities.Capabilities {
		if operation == "whitelist-sync" {
			supportsWhitelist = true
		}
	}
	if !supportsWhitelist || len(input.Rules) > capabilities.MaxBatchSize {
		return nil, errors.New("对端未声明兼容的白名单快照能力或上限不足")
	}
	if s.store == nil {
		return nil, ErrUnavailable
	}
	if err := s.store.auditWhitelist(ctx, "requested", len(rules)); err != nil {
		return nil, errors.New("白名单下发审计不可用，已阻止发送")
	}
	var result WhitelistResult
	err = s.peerRequest(ctx, cfg, http.MethodPost, "/openapi/v1/ip/whitelist/sync", input, &result)
	if err == nil {
		digest := sha256.Sum256([]byte(strings.Join(rules, "\n")))
		if result.Source != input.Source || result.Revision != input.Revision || result.Count != len(rules) || result.Digest != hex.EncodeToString(digest[:]) {
			err = errors.New("对端白名单确认内容不一致，请核对对端状态")
		}
	}
	outcome := "confirmed"
	if err != nil {
		outcome = "unconfirmed"
	}
	auditContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	auditError := s.store.auditWhitelist(auditContext, outcome, len(rules))
	cancel()
	if auditError != nil && err == nil {
		err = errors.New("对端已响应但结果审计失败，请核对对端状态")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.linkageStatus.LastError = err.Error()
		return nil, err
	}
	s.linkageStatus.LastWhitelist = &result
	s.linkageStatus.LastSuccess = time.Now().UTC().Format(time.RFC3339)
	s.linkageStatus.LastError = ""
	return &result, nil
}

func validateBlockResult(input BlockRequest, result BlockResult) error {
	unique := map[string]bool{}
	for _, value := range input.IPs {
		unique[net.ParseIP(strings.TrimSpace(value)).String()] = true
	}
	if result.Requested != len(input.IPs) || result.Unique != len(unique) || result.Blocked < 0 || result.SkippedWhitelist < 0 || result.Blocked+result.SkippedWhitelist != len(unique) || len(result.SkippedIPs) != result.SkippedWhitelist {
		return errors.New("对端未返回可信的逐批封禁结果，请核查设备状态")
	}
	seen := map[string]bool{}
	for _, value := range result.SkippedIPs {
		ip := net.ParseIP(value)
		if ip == nil || !unique[ip.String()] || seen[ip.String()] {
			return errors.New("对端跳过 IP 结果不一致，请核查设备状态")
		}
		seen[ip.String()] = true
	}
	return nil
}

func (s *Service) peerRequest(ctx context.Context, cfg LinkageConfig, method, path string, input, output any) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	secret := os.Getenv(cfg.SecretEnv)
	if len(secret) < 16 || len(secret) > 4096 || strings.ContainsAny(secret, "\r\n\x00") {
		return errors.New("联动专用密钥环境变量未配置或长度非法")
	}
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return errors.New("联动请求编码失败")
		}
		body = bytes.NewReader(data)
	}
	requestContext, cancel := context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, method, strings.TrimSuffix(cfg.Endpoint, "/")+path, body)
	if err != nil {
		return errors.New("联动请求配置非法")
	}
	request.Header.Set("X-API-Key", secret)
	request.Header.Set("Content-Type", "application/json")
	client := s.clientFactory(cfg)
	if closer, ok := client.(interface{ CloseIdleConnections() }); ok {
		defer closer.CloseIdleConnections()
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("联动网络或 TLS 校验失败；未自动重试，请核查对端状态")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("联动对端返回 HTTP %d，未确认封禁成功", response.StatusCode)
	}
	limited := io.LimitReader(response.Body, 65537)
	raw, err := io.ReadAll(limited)
	if err != nil || len(raw) > 65536 {
		return errors.New("联动响应过大或无法读取")
	}
	var envelope struct {
		Code *int            `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Code == nil || *envelope.Code != 0 || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return errors.New("联动对端响应协议不兼容")
	}
	if json.Unmarshal(envelope.Data, output) != nil {
		return errors.New("联动响应字段非法")
	}
	return nil
}

func newPeerClient(cfg LinkageConfig) peerClient {
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, ResponseHeaderTimeout: time.Duration(cfg.TimeoutSeconds) * time.Second, DialContext: validatedDial}
	return &http.Client{Transport: transport, Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects disabled") }}
}

// validatedDial permits explicitly configured LAN/loopback adapters, but blocks
// multicast, unspecified and link-local/metadata destinations after DNS lookup.
func validatedDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("empty DNS result")
	}
	for _, value := range ips {
		if value.IP.IsUnspecified() || value.IP.IsMulticast() || value.IP.IsLinkLocalUnicast() || value.IP.IsLinkLocalMulticast() {
			return nil, errors.New("unsafe destination")
		}
	}
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}
