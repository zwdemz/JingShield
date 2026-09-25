package detector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"jingshield/internal/model"
	"jingshield/internal/pkg/errx"
	"jingshield/internal/pkg/logx"
	"jingshield/internal/protection/reqctx"
	"jingshield/internal/store"
)

// BehaviorConfig provides dynamic settings without coupling the detector to storage.
// Missing keys must return the supplied defaults.
type BehaviorConfig interface {
	GetDefault(key, fallback string) string
	GetIntDefault(key string, fallback int) int
}

// ScannerDetector correlates high-confidence probes within one host/IP scope.
// Browser fingerprints and ordinary NAS downloads never aggregate across clients.
type ScannerDetector struct {
	store       store.BehaviorStore
	config      BehaviorConfig
	checked     atomic.Uint64
	probes      atomic.Uint64
	matched     atomic.Uint64
	observed    atomic.Uint64
	blocked     atomic.Uint64
	stateErrors atomic.Uint64
}

// NewScannerDetector accepts shared state and an optional live configuration.
// Stores without BehaviorStore support fail open with a visible error counter.
func NewScannerDetector(state store.StateStore, configs ...BehaviorConfig) *ScannerDetector {
	behavior, _ := state.(store.BehaviorStore)
	detector := &ScannerDetector{store: behavior}
	if len(configs) > 0 {
		detector.config = configs[0]
	}
	return detector
}

// Name returns the stable detector identifier; it performs no I/O and cannot fail.
func (d *ScannerDetector) Name() string { return "Scanner" }

// Check correlates sensitive probes and returns an observed or blocked decision.
// Normal traffic only checks a prior scoped penalty. Invalid request contexts,
// disabled detection and storage failures are allowed; storage errors are counted.
func (d *ScannerDetector) Check(ctx context.Context, rc *reqctx.RequestContext) *Result {
	if d == nil || rc == nil || rc.R == nil || rc.R.URL == nil || d.setting("scanner_protection_status", "1") != "1" {
		return nil
	}
	d.checked.Add(1)
	scope := scannerScope(rc)
	if scope == "" {
		return nil
	}
	category := sensitiveProbeCategory(rc.R.URL.Path)
	if category != "" {
		d.probes.Add(1)
	}
	if d.store == nil {
		d.recordStateError()
		return nil
	}
	policy := store.BehaviorPolicy{
		WindowSeconds: d.integer("behavior_window_seconds", 300),
		Threshold:     d.integer("behavior_threshold", 8),
		BlockSeconds:  d.integer("behavior_block_seconds", 600),
	}
	// Invalid runtime policy falls back to safe limits while API validation reports
	// bad configuration. An unknown mode is observation-only, never a silent block.
	if policy.Validate() != nil {
		policy = store.BehaviorPolicy{WindowSeconds: 300, Threshold: 8, BlockSeconds: 600}
	}
	enforce := d.setting("behavior_mode", "block") == "block"
	probeCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	snapshot, err := d.store.ObserveBehavior(probeCtx, scope, category, scannerClient(rc.UserAgent), policy, enforce)
	if err != nil {
		d.recordStateError()
		return nil
	}
	if !snapshot.Matched {
		return nil
	}
	d.matched.Add(1)
	observe := !enforce || !snapshot.Blocked
	if observe {
		d.observed.Add(1)
	} else {
		d.blocked.Add(1)
	}
	return &Result{
		Detected: true, ObserveOnly: observe, AttackType: model.AttackTypeScanner,
		Detail: fmt.Sprintf("敏感路径行为分析：窗口 %d 秒，探测 %d 次，信号 %d 类，阈值 %d，临时阻断剩余 %d 秒", policy.WindowSeconds, snapshot.Hits, snapshot.DistinctCategories, policy.Threshold, snapshot.BlockRemainingSeconds),
		Code:   errx.CodeCCAttack,
	}
}

// Metrics returns aggregate behavior counters without exposing IPs or hostnames.
// Storage failures are observable even when the fail-open policy allows a request.
func (d *ScannerDetector) Metrics() map[string]any {
	return map[string]any{
		"checked_total": d.checked.Load(), "probe_total": d.probes.Load(),
		"matched_total": d.matched.Load(), "observed_total": d.observed.Load(),
		"blocked_total": d.blocked.Load(), "state_errors_total": d.stateErrors.Load(),
		"state_available": d.store != nil,
	}
}

func (d *ScannerDetector) setting(key, fallback string) string {
	if d.config == nil {
		return fallback
	}
	return d.config.GetDefault(key, fallback)
}

func (d *ScannerDetector) integer(key string, fallback int) int {
	if d.config == nil {
		return fallback
	}
	return d.config.GetIntDefault(key, fallback)
}

// recordStateError keeps operational visibility without recording client secrets
// or emitting one warning for every request during a shared-storage outage.
func (d *ScannerDetector) recordStateError() {
	if count := d.stateErrors.Add(1); (count == 1 || count%1000 == 0) && logx.Logger() != nil {
		logx.Warn("行为防护状态不可用，当前检测放行", "state_errors_total", count)
	}
}

func scannerScope(rc *reqctx.RequestContext) string {
	address, err := netip.ParseAddr(strings.TrimSpace(rc.IP))
	if err != nil {
		return ""
	}
	parsed, err := url.Parse("http://" + strings.ToLower(strings.TrimSpace(rc.R.Host)))
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	host := strings.TrimSuffix(parsed.Hostname(), ".")
	if hostAddress, err := netip.ParseAddr(host); err == nil {
		host = hostAddress.Unmap().String()
	}
	if port := parsed.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	}
	sum := sha256.Sum256([]byte(host + "\x00" + address.Unmap().String()))
	return hex.EncodeToString(sum[:])
}

// sensitiveProbeCategory intentionally excludes extensions and generic backup,
// config, debug, package or media paths: those are ordinary NAS application data.
// Only bounded, well-known secret/repository/diagnostic targets add evidence.
func sensitiveProbeCategory(rawPath string) string {
	normalized := strings.ToLower(path.Clean("/" + strings.TrimPrefix(rawPath, "/")))
	segments := strings.Split(strings.Trim(normalized, "/"), "/")
	for _, segment := range segments {
		if segment == ".git" || segment == ".svn" || segment == ".hg" {
			return "repository"
		}
	}
	switch normalized {
	case "/.env", "/.env.local", "/.env.production", "/.env.development", "/config/.env", "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/id_ed25519", "/wp-config.php.bak", "/wp-config.php.save":
		return "secrets"
	case "/phpinfo.php", "/phpinfo", "/server-status", "/actuator/heapdump", "/actuator/env", "/actuator/configprops", "/debug/pprof", "/debug/pprof/heap", "/debug/pprof/profile":
		return "diagnostics"
	case "/vendor/phpunit/phpunit/src/util/php/eval-stdin.php", "/jolokia/exec", "/jolokia/read", "/cgi-bin/luci/;stok=/locale":
		return "control-plane"
	default:
		return ""
	}
}

func scannerClient(userAgent string) bool {
	lowered := strings.ToLower(userAgent)
	for _, marker := range []string{"sqlmap/", "nikto/", "nuclei", "masscan/", "zgrab/", "acunetix"} {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return false
}
