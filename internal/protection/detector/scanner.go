package detector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"

	"jingshield/internal/model"
	"jingshield/internal/pkg/errx"
	"jingshield/internal/protection/reqctx"
	"jingshield/internal/store"
)

const (
	scannerWindowSeconds = 300
	scannerIPThreshold   = 4
	scannerFPThreshold   = 8
)

// ScannerDetector identifies high-confidence reconnaissance rather than
// blocking on IP reputation alone. The fingerprint aggregation lets a proxy
// pool be treated as one activity when it reuses the same client profile.
type ScannerDetector struct {
	store store.StateStore
}

func NewScannerDetector(state store.StateStore) *ScannerDetector {
	return &ScannerDetector{store: state}
}

func (d *ScannerDetector) Name() string { return "Scanner" }

func (d *ScannerDetector) Check(ctx context.Context, rc *reqctx.RequestContext) *Result {
	if d == nil || d.store == nil || !isSensitiveProbe(rc) {
		return nil
	}
	fingerprint := scannerFingerprint(rc)
	ipCount, _ := d.store.HitAndCount(ctx, "scanner|ip|"+rc.IP, scannerWindowSeconds)
	fpCount, _ := d.store.HitAndCount(ctx, "scanner|fp|"+fingerprint, scannerWindowSeconds)
	if ipCount >= scannerIPThreshold || fpCount >= scannerFPThreshold {
		return &Result{
			Detected:   true,
			AttackType: model.AttackTypeScanner,
			Detail:     "检测到敏感路径扫描（IP次数: " + strconv.Itoa(ipCount) + "，指纹聚合次数: " + strconv.Itoa(fpCount) + "）",
			Code:       errx.CodeCCAttack,
		}
	}
	return nil
}

func isSensitiveProbe(rc *reqctx.RequestContext) bool {
	path := strings.ToLower(rc.R.URL.Path)
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		return false
	}
	for _, marker := range []string{
		"/.env", "/.git/", "/.svn/", "/.hg/", "/wp-config", "/phpmyadmin",
		"/actuator/", "/jolokia/", "/server-status", "/phpinfo", "/debug/",
		"/backup", "/backups/", "/dump.sql", "/database.sql", "/config.yml",
		"/config.yaml", "/package.json", "/composer.json",
	} {
		if strings.Contains(path, marker) {
			return true
		}
	}
	if strings.HasSuffix(path, ".zip") || strings.HasSuffix(path, ".tar.gz") || strings.HasSuffix(path, ".sql") || strings.HasSuffix(path, ".bak") {
		return true
	}
	return false
}

func scannerFingerprint(rc *reqctx.RequestContext) string {
	values := []string{
		rc.UserAgent,
		rc.Header.Get("Accept"),
		rc.Header.Get("Accept-Language"),
		rc.Header.Get("Sec-CH-UA"),
		rc.Header.Get("Sec-Fetch-Site"),
	}
	// Include the normalized host, but never query parameters or credentials.
	if host := strings.ToLower(strings.TrimSpace(rc.R.Host)); host != "" {
		if parsed, err := url.Parse("http://" + host); err == nil {
			values = append(values, parsed.Hostname())
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return hex.EncodeToString(sum[:])
}
