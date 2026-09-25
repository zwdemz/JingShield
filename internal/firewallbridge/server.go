package firewallbridge

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"jingshield/internal/pkg/iputil"
)

// AuditEvent contains operational metadata, never API credentials or raw bodies.
type AuditEvent struct {
	Time            time.Time `json:"time"`
	Action          string    `json:"action"`
	SourceIP        string    `json:"source_ip"`
	Driver          string    `json:"driver"`
	IPs             []string  `json:"ips"`
	ExpireSeconds   int       `json:"expire_seconds"`
	Applied         int       `json:"applied"`
	Partial         bool      `json:"partial"`
	DryRun          bool      `json:"dry_run"`
	WhitelistSource string    `json:"whitelist_source,omitempty"`
	Revision        int64     `json:"revision,omitempty"`
	RuleCount       int       `json:"rule_count,omitempty"`
}

// AuditWriter must return persistence errors; a failed intent log prevents apply.
type AuditWriter func(AuditEvent) error

// Server enforces source CIDRs, TLS, authentication, bounded requests and a
// single in-flight mutation before invoking the configured driver.
type Server struct {
	config             Config
	driver             Driver
	key                string
	audit              AuditWriter
	allowed, protected []netip.Prefix
	baseProtected      []netip.Prefix
	whitelist          whitelistFile
	mu                 sync.Mutex
	window             time.Time
	requests           int
	active             chan struct{}
}

// NewServer validates all dependencies and reads the dedicated API key. Applying
// native drivers outside Linux fails; dry-run remains usable cross-platform.
func NewServer(cfg Config, driver Driver, audit AuditWriter) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if driver == nil || audit == nil {
		return nil, errors.New("driver and auditable sink are required")
	}
	if cfg.Apply && runtime.GOOS != "linux" {
		return nil, errors.New("native firewall apply is supported on Linux only")
	}
	if cfg.Apply && driver.Name() == "dry-run" || !cfg.Apply && driver.Name() != "dry-run" {
		return nil, errors.New("configured mode and driver disagree")
	}
	key := os.Getenv(cfg.APIKeyEnv)
	if len(key) < 32 || len(key) > 4096 || strings.ContainsAny(key, "\r\n\x00") {
		return nil, errors.New("dedicated firewall API key must contain 32-4096 safe bytes")
	}
	server := &Server{config: cfg, driver: driver, key: key, audit: audit, active: make(chan struct{}, 1)}
	for _, raw := range cfg.AllowedCIDRs {
		prefix, _ := netip.ParsePrefix(raw)
		server.allowed = append(server.allowed, prefix.Masked())
		server.protected = append(server.protected, prefix.Masked())
	}
	for _, raw := range cfg.WhitelistCIDRs {
		prefix, _ := netip.ParsePrefix(raw)
		server.protected = append(server.protected, prefix.Masked())
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, errors.New("cannot determine local addresses for self-protection")
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil {
			ip := prefix.Addr().Unmap()
			server.protected = append(server.protected, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	server.baseProtected = append([]netip.Prefix{}, server.protected...)
	server.whitelist = whitelistFile{Sources: map[string]whitelistSnapshot{}}
	if cfg.Apply && cfg.WhitelistStateFile != "" {
		stored, err := readWhitelistState(cfg.WhitelistStateFile)
		if err != nil {
			return nil, err
		}
		server.whitelist = stored
		server.protected = server.whitelistPrefixes(stored)
		if cleaner, ok := driver.(WhitelistCleaner); ok {
			context, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.RequestTimeoutSeconds)*time.Second)
			_, err = cleaner.ClearMatching(context, server.protected)
			cancel()
			if err != nil {
				return nil, errors.New("received whitelist cannot be reconciled with managed firewall sets")
			}
		} else {
			return nil, errors.New("firewall driver does not support whitelist reconciliation")
		}
	}
	return server, nil
}

// HTTPServer returns an HTTPS-only server with bounded header/body I/O timeouts.
// The caller must start it with ListenAndServeTLS using the validated TLS files.
func (s *Server) HTTPServer() *http.Server {
	timeout := time.Duration(s.config.RequestTimeoutSeconds) * time.Second
	return &http.Server{Addr: s.config.Listen, Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: timeout, WriteTimeout: timeout + 5*time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
}

// ServeHTTP implements only capability inspection and bounded block-batch. It
// ignores forwarding headers and never exposes general command execution.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.TLS == nil {
		s.reply(w, 400, -400, "HTTPS is required", nil)
		return
	}
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !inPrefixes(remote.Addr().Unmap(), s.allowed) {
		s.reply(w, 403, -403, "source is not allowed", nil)
		return
	}
	if !s.allow() {
		w.Header().Set("Retry-After", "60")
		s.reply(w, 429, -429, "request rate exceeded", nil)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-API-Key")), []byte(s.key)) != 1 {
		s.reply(w, 401, -401, "invalid API key", nil)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/openapi/v1/capabilities":
		capability := "block-batch"
		whitelistCapability := "whitelist-sync"
		if !s.config.Apply {
			capability = "preview-block-batch"
			whitelistCapability = "preview-whitelist-sync"
		}
		capabilities := []string{capability}
		if s.config.WhitelistStateFile != "" {
			capabilities = append(capabilities, whitelistCapability)
		}
		maximum := MaxNFTTTL
		if s.config.Backend == "ipset" {
			maximum = MaxIPSetTTL
		}
		s.reply(w, 200, 0, "success", map[string]any{"protocol": Protocol, "device_type": "firewall", "capabilities": capabilities, "max_batch_size": MaxBatchSize, "max_expire_seconds": maximum, "driver": s.config.Backend, "dry_run": !s.config.Apply})
	case r.Method == http.MethodPost && r.URL.Path == "/openapi/v1/ip/block-batch":
		s.blockBatch(w, r, remote.Addr().Unmap())
	case r.Method == http.MethodPost && r.URL.Path == "/openapi/v1/ip/whitelist/sync":
		s.whitelistSync(w, r, remote.Addr().Unmap())
	default:
		s.reply(w, 404, -404, "endpoint not found", nil)
	}
}

func (s *Server) allow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Sub(s.window) >= time.Minute {
		s.window = now
		s.requests = 0
	}
	if s.requests >= s.config.RequestsPerMinute {
		return false
	}
	s.requests++
	return true
}

type blockInput struct {
	IPs           []string `json:"ips"`
	Reason        string   `json:"reason"`
	ExpireSeconds int      `json:"expire_seconds"`
}
type blockOutput struct {
	Requested        int      `json:"requested"`
	Unique           int      `json:"unique"`
	Blocked          int      `json:"blocked"`
	SkippedWhitelist int      `json:"skipped_whitelist"`
	SkippedIPs       []string `json:"skipped_ips"`
	DryRun           bool     `json:"dry_run"`
	WouldBlock       int      `json:"would_block,omitempty"`
	Partial          bool     `json:"partial"`
}

// blockBatch validates before mutation, protects management/local addresses and
// requires an audit intent. Driver errors or incomplete readback cannot produce
// a successful enforcement response, even when some entries were changed.
func (s *Server) blockBatch(w http.ResponseWriter, r *http.Request, source netip.Addr) {
	var input blockInput
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		s.reply(w, 400, -400, "invalid or oversized JSON body", nil)
		return
	}
	maximum := MaxNFTTTL
	if s.config.Backend == "ipset" {
		maximum = MaxIPSetTTL
	}
	ips, err := iputil.NormalizeBlockIPs(input.IPs)
	if err != nil || !iputil.ValidBlockReason(input.Reason) || input.ExpireSeconds < 0 || input.ExpireSeconds > maximum {
		s.reply(w, 400, -400, "invalid exact-IP batch, reason or supported expiry", nil)
		return
	}
	select {
	case s.active <- struct{}{}:
		defer func() { <-s.active }()
	default:
		s.reply(w, 429, -429, "another batch is in progress", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.config.RequestTimeoutSeconds)*time.Second)
	defer cancel()
	result := blockOutput{Requested: len(input.IPs), Unique: len(ips), SkippedIPs: []string{}, DryRun: !s.config.Apply}
	blocks := []Block{}
	expires := time.Time{}
	if input.ExpireSeconds > 0 {
		expires = time.Now().Add(time.Duration(input.ExpireSeconds) * time.Second)
	}
	for _, value := range ips {
		ip, _ := netip.ParseAddr(value)
		if ip == source || inPrefixes(ip, s.protected) {
			result.SkippedIPs = append(result.SkippedIPs, value)
			result.SkippedWhitelist++
			continue
		}
		blocks = append(blocks, Block{IP: ip, ExpiresAt: expires})
	}
	event := AuditEvent{Time: time.Now().UTC(), Action: "requested", SourceIP: source.String(), Driver: s.driver.Name(), IPs: ips, ExpireSeconds: input.ExpireSeconds, DryRun: result.DryRun}
	if s.audit(event) != nil {
		s.reply(w, 503, -503, "audit unavailable; no changes applied", nil)
		return
	}
	applied := ApplyResult{}
	if len(blocks) > 0 {
		applied, err = s.driver.Apply(ctx, blocks)
	}
	if result.DryRun {
		result.WouldBlock = applied.Applied
	} else {
		result.Blocked = applied.Applied
	}
	result.Partial = applied.Partial
	event.Time = time.Now().UTC()
	event.Applied = applied.Applied
	event.Partial = applied.Partial
	event.Action = "confirmed"
	if result.DryRun {
		event.Action = "preview"
	}
	if err != nil || applied.Partial || applied.Applied != len(blocks) {
		event.Action = "unconfirmed"
	}
	if s.audit(event) != nil {
		s.reply(w, 503, -503, "outcome audit failed; inspect device state before retrying", result)
		return
	}
	if err != nil || applied.Partial || applied.Applied != len(blocks) {
		s.reply(w, 502, -502, "batch not fully confirmed; inspect dedicated sets and adapter audit", result)
		return
	}
	s.reply(w, 200, 0, "success", result)
}

func inPrefixes(ip netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
func (s *Server) reply(w http.ResponseWriter, status, code int, message string, data any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": message, "data": data})
}
