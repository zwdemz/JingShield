package firewallbridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// Config contains operational settings only. The credential itself is obtained
// from APIKeyEnv at startup and never serialized in configuration or responses.
type Config struct {
	Listen                string   `json:"listen"`
	TLSCert               string   `json:"tls_cert"`
	TLSKey                string   `json:"tls_key"`
	APIKeyEnv             string   `json:"api_key_env"`
	Backend               string   `json:"backend"`
	Apply                 bool     `json:"apply"`
	AllowedCIDRs          []string `json:"allowed_cidrs"`
	WhitelistCIDRs        []string `json:"whitelist_cidrs"`
	WhitelistStateFile    string   `json:"whitelist_state_file"`
	RequestsPerMinute     int      `json:"requests_per_minute"`
	RequestTimeoutSeconds int      `json:"request_timeout_seconds"`
}

var secretVariable = regexp.MustCompile(`^JINGSHIELD_LINKAGE_[A-Z0-9_]{1,100}$`)

// LoadConfig strictly decodes at most 64 KiB and fills conservative defaults.
// Malformed, unknown and trailing fields fail before opening any listener.
func LoadConfig(path string) (Config, error) {
	cfg := Config{Listen: "127.0.0.1:9443", APIKeyEnv: "JINGSHIELD_LINKAGE_FIREWALL_KEY", Backend: "nftables", RequestsPerMinute: 60, RequestTimeoutSeconds: 8}
	file, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(data) > 65536 {
		return cfg, errors.New("firewall configuration exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&cfg); err != nil {
		return cfg, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return cfg, errors.New("configuration must contain exactly one JSON object")
	}
	return cfg, cfg.Validate()
}

// Validate checks listener, dedicated secret reference and trusted source ranges;
// it performs no firewall or network operations.
func (c Config) Validate() error {
	host, port, err := net.SplitHostPort(c.Listen)
	number, _ := strconv.Atoi(port)
	if err != nil || number < 1024 || number > 65535 || (host != "" && net.ParseIP(host) == nil) {
		return errors.New("listen must use an IP literal and unprivileged port 1024-65535")
	}
	if c.TLSCert == "" || c.TLSKey == "" || !secretVariable.MatchString(c.APIKeyEnv) {
		return errors.New("TLS files and dedicated JINGSHIELD_LINKAGE_ secret reference are required")
	}
	if c.Backend != "nftables" && c.Backend != "ipset" {
		return errors.New("backend must be nftables or ipset")
	}
	if c.RequestsPerMinute < 1 || c.RequestsPerMinute > 600 || c.RequestTimeoutSeconds < 2 || c.RequestTimeoutSeconds > 60 {
		return errors.New("request rate/timeout is outside bounds")
	}
	if len(c.AllowedCIDRs) == 0 || len(c.AllowedCIDRs) > 64 || len(c.WhitelistCIDRs) > 256 {
		return errors.New("explicit allowed CIDRs and bounded whitelist are required")
	}
	for _, raw := range append(append([]string{}, c.AllowedCIDRs...), c.WhitelistCIDRs...) {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Addr().Is4In6() || prefix.Bits() == 0 {
			return errors.New("invalid or unrestricted management/whitelist CIDR")
		}
	}
	if c.WhitelistStateFile != "" && (!filepath.IsAbs(c.WhitelistStateFile) || filepath.Clean(c.WhitelistStateFile) != c.WhitelistStateFile || filepath.Ext(c.WhitelistStateFile) != ".json") {
		return errors.New("whitelist_state_file must be an absolute, normalized JSON file path")
	}
	return nil
}
