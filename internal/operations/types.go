// Package operations separates log delivery from remote enforcement. No transport
// acknowledgement is treated as proof that a remote firewall blocked traffic.
package operations

import (
	"errors"
	"jingshield/internal/pkg/iputil"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const Protocol = "jingshield-v1"
const MaxBatchSize = iputil.MaxBlockBatch

var ErrQueueFull = errors.New("syslog 队列已满，攻击记录仍保留在本地")
var ErrUnavailable = errors.New("运营服务不可用")

// SyslogConfig contains non-secret transport settings. TLS always verifies the
// server certificate against the OS trust store; timeout is bounded to 10 s.
type SyslogConfig struct {
	Enabled        bool   `json:"enabled"`
	Transport      string `json:"transport"`
	Address        string `json:"address"`
	ServerName     string `json:"server_name"`
	Facility       int    `json:"facility"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	MaxRetries     int    `json:"max_retries"`
	QueueCapacity  int    `json:"queue_capacity"`
}

// Validate rejects invalid network settings without making any network request.
func (c SyslogConfig) Validate() error {
	if c.Transport != "tcp" && c.Transport != "udp" && c.Transport != "tls" {
		return errors.New("syslog 传输协议必须为 tcp、udp 或 tls")
	}
	if c.Facility < 0 || c.Facility > 23 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 10 || c.MaxRetries < 0 || c.MaxRetries > 5 || c.QueueCapacity < 1 || c.QueueCapacity > 10000 {
		return errors.New("syslog facility、超时、重试或队列上限非法")
	}
	if c.Address != "" {
		host, port, err := net.SplitHostPort(c.Address)
		number, _ := strconv.Atoi(port)
		if err != nil || !validHost(host) || number < 1 || number > 65535 {
			return errors.New("syslog 地址必须是有效的 host:port")
		}
	} else if c.Enabled {
		return errors.New("启用 syslog 必须配置接收地址")
	}
	if c.ServerName != "" && !validHost(c.ServerName) {
		return errors.New("syslog TLS 服务名非法")
	}
	return nil
}

// LinkageConfig references a deployment-provided environment variable instead
// of persisting credentials. Only explicitly compatible peers are supported.
type LinkageConfig struct {
	Enabled        bool   `json:"enabled"`
	DeviceVendor   string `json:"device_vendor"`
	Protocol       string `json:"protocol"`
	DeviceType     string `json:"device_type"`
	Endpoint       string `json:"endpoint"`
	SecretEnv      string `json:"secret_env"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	SourceID       string `json:"source_id"`
}

var envName = regexp.MustCompile(`^JINGSHIELD_LINKAGE_[A-Z0-9_]{1,100}$`)

// Validate enforces HTTPS, explicit protocol and dedicated secret references;
// invalid settings return a user-safe error, never credentials or endpoint data.
func (c LinkageConfig) Validate() error {
	if !map[string]bool{"": true, "jingshield": true, "system": true, "360": true, "huawei": true, "zte": true, "cisco": true, "adapter": true}[c.DeviceVendor] {
		return errors.New("联动厂商标记非法；非同协议设备需要专用适配器")
	}
	if c.Protocol != Protocol || (c.DeviceType != "waf" && c.DeviceType != "firewall") {
		return errors.New("仅支持 jingshield-v1 同协议 WAF 或防火墙")
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 10 {
		return errors.New("联动超时必须为 1 到 10 秒")
	}
	if c.Endpoint != "" {
		u, err := url.Parse(c.Endpoint)
		if err != nil || u.Scheme != "https" || !validHost(u.Hostname()) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return errors.New("联动地址必须为 HTTPS 根地址，不允许凭据、路径、查询或片段")
		}
		if u.Port() != "" {
			p, err := strconv.Atoi(u.Port())
			if err != nil || p < 1 || p > 65535 {
				return errors.New("联动端口非法")
			}
		}
	} else if c.Enabled {
		return errors.New("启用联动必须配置 HTTPS 地址")
	}
	if c.SecretEnv != "" && !envName.MatchString(c.SecretEnv) {
		return errors.New("密钥环境变量必须以 JINGSHIELD_LINKAGE_ 开头且仅含大写字母、数字、下划线")
	}
	if c.Enabled && c.SecretEnv == "" {
		return errors.New("启用联动必须配置专用密钥环境变量")
	}
	if c.SourceID != "" && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`).MatchString(c.SourceID) {
		return errors.New("白名单来源 ID 必须为 1-64 位字母、数字、下划线或短横线")
	}
	return nil
}

func validHost(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\r\n\t /\\@?#%") {
		return false
	}
	if ip := net.ParseIP(value); ip != nil {
		return !ip.IsUnspecified() && !ip.IsMulticast()
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}

// Event is the complete allowlist of fields that may leave the node via syslog.
// URI, host, headers, body and attack detail are deliberately excluded.
type Event struct {
	DeliveryID string    `json:"delivery_id,omitempty"`
	ID         string    `json:"event_id"`
	IP         string    `json:"source_ip"`
	AttackType string    `json:"attack_type"`
	Severity   int       `json:"severity"`
	Action     string    `json:"action"`
	Time       time.Time `json:"occurred_at"`
}

// deliveryKey preserves old queued payloads while new deliveries distinguish
// independent decisions about one request (for example observed then blocked).
func (event Event) deliveryKey() string {
	if event.DeliveryID != "" {
		return event.DeliveryID
	}
	return event.ID
}

// SyslogStatus exposes persistent backlog plus explicitly process-local counters.
type SyslogStatus struct {
	Running           bool   `json:"running"`
	Queued            int    `json:"queued"`
	Failed            int    `json:"failed"`
	QueueCapacity     int    `json:"queue_capacity"`
	SentTotal         uint64 `json:"sent_total"`
	RetriedTotal      uint64 `json:"retried_total"`
	DroppedTotal      uint64 `json:"dropped_total"`
	LastSuccess       string `json:"last_success"`
	LastError         string `json:"last_error"`
	DeliverySemantics string `json:"delivery_semantics"`
	CounterScope      string `json:"counter_scope"`
}

// Capabilities must be explicitly advertised by the remote authenticated peer.
type Capabilities struct {
	Protocol         string   `json:"protocol"`
	DeviceType       string   `json:"device_type"`
	Capabilities     []string `json:"capabilities"`
	MaxBatchSize     int      `json:"max_batch_size"`
	MaxExpireSeconds int      `json:"max_expire_seconds,omitempty"`
}

// BlockRequest accepts precise IPs only; expiry zero requests a permanent block.
type BlockRequest struct {
	IPs           []string `json:"ips"`
	Reason        string   `json:"reason"`
	ExpireSeconds int      `json:"expire_seconds"`
}

// Validate checks the raw request limit before deduplication to prevent bypass.
func (r BlockRequest) Validate() error {
	if _, err := iputil.NormalizeBlockIPs(r.IPs); err != nil {
		return err
	}
	if !iputil.ValidBlockReason(r.Reason) || r.ExpireSeconds < 0 || r.ExpireSeconds > 31536000 {
		return errors.New("批量封禁单次必须为 1 到 500 个 IP，原因和有效期须合法")
	}
	return nil
}

// BlockResult reports peer-confirmed changes, not merely HTTP delivery success.
type BlockResult struct {
	Requested        int      `json:"requested"`
	Unique           int      `json:"unique"`
	Blocked          int      `json:"blocked"`
	SkippedWhitelist int      `json:"skipped_whitelist"`
	SkippedIPs       []string `json:"skipped_ips"`
}

// LinkageStatus is cleared when peer settings change to prevent stale trust.
type LinkageStatus struct {
	IntegrationMode string           `json:"integration_mode"`
	Compatible      bool             `json:"compatible"`
	LastProbe       string           `json:"last_probe"`
	LastSuccess     string           `json:"last_success"`
	LastError       string           `json:"last_error"`
	LastResult      *BlockResult     `json:"last_result"`
	LastWhitelist   *WhitelistResult `json:"last_whitelist"`
}

// WhitelistRequest is a complete manual-rule snapshot owned by one peer.
// A higher revision atomically replaces that peer's previous rules.
type WhitelistRequest struct {
	Source   string   `json:"source"`
	Revision int64    `json:"revision"`
	Rules    []string `json:"rules"`
}

// WhitelistResult acknowledges a source-owned, durable snapshot.
type WhitelistResult struct {
	Source   string `json:"source"`
	Revision int64  `json:"revision"`
	Count    int    `json:"count"`
	Digest   string `json:"digest"`
}
