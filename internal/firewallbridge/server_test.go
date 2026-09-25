package firewallbridge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{Listen: "127.0.0.1:9443", TLSCert: "test-cert.pem", TLSKey: "test-key.pem", APIKeyEnv: "JINGSHIELD_LINKAGE_FIREWALL_TEST", Backend: "nftables", AllowedCIDRs: []string{"192.0.2.10/32"}, WhitelistCIDRs: []string{"198.51.100.0/24"}, RequestsPerMinute: 600, RequestTimeoutSeconds: 2}
}
func testServer(t *testing.T) (*Server, *[]AuditEvent) {
	t.Helper()
	key := strings.Repeat("test-only-", 4)
	t.Setenv(testConfig().APIKeyEnv, key)
	events := []AuditEvent{}
	server, err := NewServer(testConfig(), NewDryRunDriver(), func(event AuditEvent) error { events = append(events, event); return nil })
	if err != nil {
		t.Fatal(err)
	}
	return server, &events
}
func bridgeRequest(server *Server, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://adapter.example"+path, strings.NewReader(body))
	request.RemoteAddr = "192.0.2.10:30000"
	request.Header.Set("X-API-Key", strings.Repeat("test-only-", 4))
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}
func outputFrom(t *testing.T, recorder *httptest.ResponseRecorder) blockOutput {
	t.Helper()
	var envelope struct {
		Data blockOutput `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Data
}

func TestServerDryRunCapabilityCannotBeMistakenForEnforcement(t *testing.T) {
	server, _ := testServer(t)
	for _, backend := range []string{"nftables", "ipset"} {
		server.config.Backend = backend
		recorder := bridgeRequest(server, "GET", "/openapi/v1/capabilities", "")
		var response struct {
			Data struct {
				Protocol     string   `json:"protocol"`
				Type         string   `json:"device_type"`
				Capabilities []string `json:"capabilities"`
				Max          int      `json:"max_batch_size"`
				TTL          int      `json:"max_expire_seconds"`
				DryRun       bool     `json:"dry_run"`
			} `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != 200 || response.Data.Protocol != Protocol || response.Data.Type != "firewall" || !response.Data.DryRun || response.Data.Max != 500 || len(response.Data.Capabilities) != 1 || response.Data.Capabilities[0] != "preview-block-batch" {
			t.Fatalf("invalid capability: %s", recorder.Body)
		}
		if backend == "ipset" && response.Data.TTL != MaxIPSetTTL {
			t.Fatal("ipset limit not advertised")
		}
	}
	server.config.Apply = true // Protocol-only mock; no native driver is invoked.
	recorder := bridgeRequest(server, "GET", "/openapi/v1/capabilities", "")
	if !strings.Contains(recorder.Body.String(), `"capabilities":["block-batch"]`) {
		t.Fatal(recorder.Body.String())
	}
}

func TestServerRejectsUnauthenticatedTransportAndSource(t *testing.T) {
	for _, test := range []struct {
		name   string
		modify func(*http.Request)
		status int
	}{
		{"plaintext", func(r *http.Request) { r.TLS = nil }, 400},
		{"source", func(r *http.Request) {
			r.RemoteAddr = "203.0.113.1:1234"
			r.Header.Set("X-Forwarded-For", "192.0.2.10")
		}, 403},
		{"malformed-source", func(r *http.Request) { r.RemoteAddr = "invalid" }, 403},
		{"missing-key", func(r *http.Request) { r.Header.Del("X-API-Key") }, 401},
		{"wrong-key", func(r *http.Request) { r.Header.Set("X-API-Key", strings.Repeat("invalid-test-", 4)) }, 401},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, events := testServer(t)
			request := httptest.NewRequest("POST", "https://adapter.example/openapi/v1/ip/block-batch", strings.NewReader(`{"ips":["203.0.113.5"],"reason":"test"}`))
			request.RemoteAddr = "192.0.2.10:1234"
			request.Header.Set("X-API-Key", strings.Repeat("test-only-", 4))
			test.modify(request)
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, request)
			if recorder.Code != test.status || len(*events) != 0 {
				t.Fatalf("status %d events %#v", recorder.Code, *events)
			}
		})
	}
}

func TestServerBoundedBatchAndWhiteList(t *testing.T) {
	server, events := testServer(t)
	body := `{"ips":["192.0.2.10","198.51.100.15","203.0.113.8","203.0.113.8","2001:db8::9"],"reason":"security test","expire_seconds":120}`
	for attempt := 0; attempt < 2; attempt++ {
		recorder := bridgeRequest(server, "POST", "/openapi/v1/ip/block-batch", body)
		result := outputFrom(t, recorder)
		if recorder.Code != 200 || result.Requested != 5 || result.Unique != 4 || result.Blocked != 0 || !result.DryRun || result.WouldBlock != 2 || result.SkippedWhitelist != 2 {
			t.Fatalf("bad preview: %s", recorder.Body)
		}
	}
	if len(*events) != 4 || (*events)[0].Action != "requested" || (*events)[1].Action != "preview" {
		t.Fatalf("audit missing: %#v", *events)
	}
	encoded, _ := json.Marshal(events)
	if strings.Contains(string(encoded), "security test") || strings.Contains(string(encoded), strings.Repeat("test-only-", 4)) {
		t.Fatal("sensitive input appeared in audit")
	}
	protected := bridgeRequest(server, "POST", "/openapi/v1/ip/block-batch", `{"ips":["192.0.2.10"],"reason":"test"}`)
	if protected.Code != 200 || outputFrom(t, protected).WouldBlock != 0 {
		t.Fatal("all-protected batch failed")
	}
}

func TestServerRejectsMalformedAndOutOfBoundsBatches(t *testing.T) {
	server, _ := testServer(t)
	server.config.Backend = "ipset"
	oversized, _ := json.Marshal(blockInput{IPs: make([]string, 501), Reason: "test"})
	for _, body := range []string{
		`{`, `{}`, `{"ips":["203.0.113.8"],"reason":"test","unexpected":true}`,
		`{"ips":["203.0.113.8"],"reason":"test"}{}`, `{"ips":["203.0.113.0/24"],"reason":"test"}`,
		`{"ips":["127.0.0.1"],"reason":"test"}`, `{"ips":["fe80::1"],"reason":"test"}`,
		`{"ips":["203.0.113.8"],"reason":"a\nb"}`, `{"ips":["203.0.113.8"],"reason":"test","expire_seconds":-1}`,
		`{"ips":["203.0.113.8"],"reason":"test","expire_seconds":2147484}`, string(oversized), strings.Repeat(" ", 65537) + `{}`,
	} {
		if recorder := bridgeRequest(server, "POST", "/openapi/v1/ip/block-batch", body); recorder.Code != 400 {
			t.Fatalf("bad input accepted with %d: %.100s", recorder.Code, body)
		}
	}
}

type stubDriver struct {
	result ApplyResult
	err    error
	calls  int
}

func (*stubDriver) Name() string { return "test-native" }
func (d *stubDriver) Apply(ctx context.Context, blocks []Block) (ApplyResult, error) {
	d.calls++
	if _, ok := ctx.Deadline(); !ok {
		return ApplyResult{}, errors.New("missing deadline")
	}
	return d.result, d.err
}

func TestServerHonestFailureAndAuditBoundaries(t *testing.T) {
	for _, test := range []struct {
		name        string
		result      ApplyResult
		failure     error
		auditFailAt int
		status      int
	}{
		{"enforced", ApplyResult{Applied: 1}, nil, 0, 200},
		{"partial", ApplyResult{Partial: true}, errors.New("private native detail"), 0, 502},
		{"count-mismatch", ApplyResult{}, nil, 0, 502},
		{"intent-audit", ApplyResult{Applied: 1}, nil, 1, 503},
		{"outcome-audit", ApplyResult{Applied: 1}, nil, 2, 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, _ := testServer(t)
			server.config.Apply = true
			driver := &stubDriver{result: test.result, err: test.failure}
			server.driver = driver
			calls := 0
			server.audit = func(AuditEvent) error {
				calls++
				if calls == test.auditFailAt {
					return errors.New("private audit detail")
				}
				return nil
			}
			recorder := bridgeRequest(server, "POST", "/openapi/v1/ip/block-batch", `{"ips":["203.0.113.8"],"reason":"test"}`)
			if recorder.Code != test.status || strings.Contains(recorder.Body.String(), "private") {
				t.Fatalf("bad error contract %s", recorder.Body)
			}
			if test.auditFailAt == 1 && driver.calls != 0 {
				t.Fatal("applied without audit intent")
			}
			if test.status == 200 && outputFrom(t, recorder).Blocked != 1 {
				t.Fatal("confirmed count missing")
			}
		})
	}
}

func TestServerRateConcurrencyAndTLSBounds(t *testing.T) {
	server, _ := testServer(t)
	server.config.RequestsPerMinute = 1
	if bridgeRequest(server, "GET", "/openapi/v1/capabilities", "").Code != 200 {
		t.Fatal("first request denied")
	}
	if bridgeRequest(server, "GET", "/openapi/v1/capabilities", "").Code != 429 {
		t.Fatal("rate bound missing")
	}
	server.window = time.Now().Add(-2 * time.Minute)
	if bridgeRequest(server, "GET", "/unknown", "").Code != 404 {
		t.Fatal("window did not reset")
	}
	server.config.RequestsPerMinute = 600
	server.active <- struct{}{}
	if bridgeRequest(server, "POST", "/openapi/v1/ip/block-batch", `{"ips":["203.0.113.8"],"reason":"test"}`).Code != 429 {
		t.Fatal("concurrency bound missing")
	}
	<-server.active
	httpServer := server.HTTPServer()
	if httpServer.TLSConfig.MinVersion != tls.VersionTLS12 || httpServer.ReadHeaderTimeout <= 0 || httpServer.ReadTimeout <= 0 || httpServer.WriteTimeout <= 0 || httpServer.MaxHeaderBytes > 16<<10 {
		t.Fatal("HTTP limits missing")
	}
}

func TestConfigStrictDecodingAndSafeDefaults(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, []byte(`{"tls_cert":"test.pem","tls_key":"test-key.pem","allowed_cidrs":["192.0.2.10/32"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil || cfg.Apply || cfg.Backend != "nftables" || cfg.RequestsPerMinute != 60 || cfg.RequestTimeoutSeconds != 8 {
		t.Fatalf("bad defaults %#v %v", cfg, err)
	}
	for _, raw := range []string{`{}`, `{"unknown":1}`, `{} {}`, "null", strings.Repeat(" ", 65537)} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatalf("invalid config accepted %.80s", raw)
		}
	}
	if _, err := LoadConfig(filepath.Join(directory, "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestConfigValidationAndStartupDependencies(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Listen = "localhost:9443" }, func(c *Config) { c.Listen = "127.0.0.1:80" }, func(c *Config) { c.APIKeyEnv = "SECRET" }, func(c *Config) { c.TLSCert = "" }, func(c *Config) { c.Backend = "shell" }, func(c *Config) { c.RequestsPerMinute = 601 }, func(c *Config) { c.RequestTimeoutSeconds = 61 }, func(c *Config) { c.AllowedCIDRs = nil }, func(c *Config) { c.AllowedCIDRs = []string{"0.0.0.0/0"} }, func(c *Config) { c.AllowedCIDRs = []string{"::ffff:192.0.2.10/128"} }, func(c *Config) { c.WhitelistCIDRs = []string{"invalid"} },
	} {
		cfg := testConfig()
		mutate(&cfg)
		if cfg.Validate() == nil {
			t.Fatalf("invalid configuration accepted %#v", cfg)
		}
	}
	cfg := testConfig()
	audit := func(AuditEvent) error { return nil }
	t.Setenv(cfg.APIKeyEnv, "short")
	if _, err := NewServer(cfg, NewDryRunDriver(), audit); err == nil {
		t.Fatal("short key accepted")
	}
	t.Setenv(cfg.APIKeyEnv, strings.Repeat("test-only-", 4))
	if _, err := NewServer(cfg, nil, audit); err == nil {
		t.Fatal("nil driver accepted")
	}
	if _, err := NewServer(cfg, NewDryRunDriver(), nil); err == nil {
		t.Fatal("nil audit accepted")
	}
	if _, err := NewServer(cfg, NewNFTDriver(nil), audit); err == nil {
		t.Fatal("native dry-run mismatch accepted")
	}
	cfg.Apply = true
	if _, err := NewServer(cfg, NewDryRunDriver(), audit); err == nil {
		t.Fatal("dry-run apply mismatch accepted")
	}
	if runtime.GOOS != "linux" {
		if _, err := NewServer(cfg, NewNFTDriver(nil), audit); err == nil {
			t.Fatal("non-Linux apply accepted")
		}
	}
}

func TestBoundedCommandOutputAndExecutableGuard(t *testing.T) {
	output := &boundedOutput{limit: 4}
	if count, err := output.Write([]byte("abcdef")); count != 6 || err != nil || !output.overflow || output.String() != "abcd" {
		t.Fatal("output was not bounded")
	}
	_, _ = output.Write([]byte("second"))
	if output.Len() != 4 {
		t.Fatal("overflow grew buffer")
	}
	if _, err := (commandRunner{}).Run(context.Background(), "forbidden-executable", nil, nil); err == nil {
		t.Fatal("unapproved executable accepted")
	}
	if NewNFTDriver(nil).Name() != "nftables" || NewIPSetDriver(nil).Name() != "ipset" {
		t.Fatal("driver identity mismatch")
	}
}
