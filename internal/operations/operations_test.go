package operations

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"jingshield/internal/model"
)

type memoryPersistence struct {
	mu         sync.Mutex
	settings   map[string][]byte
	queue      []*queuedEvent
	failed     map[int64]bool
	saveError  error
	auditError error
	audits     []string
}

func newMemoryPersistence() *memoryPersistence {
	return &memoryPersistence{settings: map[string][]byte{}, failed: map[int64]bool{}}
}
func (p *memoryPersistence) load(_ context.Context, key string, out any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if value := p.settings[key]; value != nil {
		return json.Unmarshal(value, out)
	}
	return nil
}
func (p *memoryPersistence) save(_ context.Context, key string, input any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.saveError != nil {
		return p.saveError
	}
	p.settings[key], _ = json.Marshal(input)
	return nil
}
func (p *memoryPersistence) enqueue(_ context.Context, event Event, capacity int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, item := range p.queue {
		if item.Event.deliveryKey() == event.deliveryKey() {
			return nil
		}
	}
	if len(p.queue) >= capacity {
		return ErrQueueFull
	}
	p.queue = append(p.queue, &queuedEvent{ID: int64(len(p.queue) + 1), Event: event})
	return nil
}
func (p *memoryPersistence) claim(_ context.Context) (*queuedEvent, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, item := range p.queue {
		if !p.failed[item.ID] {
			copyItem := *item
			return &copyItem, nil
		}
	}
	return nil, nil
}
func (p *memoryPersistence) finish(_ context.Context, item *queuedEvent, success, failed bool, _ time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for index, candidate := range p.queue {
		if candidate.ID == item.ID {
			if success {
				p.queue = append(p.queue[:index], p.queue[index+1:]...)
			} else {
				candidate.Attempts++
				p.failed[candidate.ID] = failed
			}
			return nil
		}
	}
	return errors.New("missing queue entry")
}
func (p *memoryPersistence) retry(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, item := range p.queue {
		if p.failed[item.ID] {
			p.failed[item.ID] = false
			item.Attempts = 0
		}
	}
	return nil
}
func (p *memoryPersistence) counts(context.Context) (int, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	queued, failed := 0, 0
	for _, item := range p.queue {
		if p.failed[item.ID] {
			failed++
		} else {
			queued++
		}
	}
	return queued, failed, nil
}
func (p *memoryPersistence) audit(_ context.Context, outcome string, _ int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.auditError != nil {
		return p.auditError
	}
	p.audits = append(p.audits, outcome)
	return nil
}
func (p *memoryPersistence) auditWhitelist(_ context.Context, outcome string, _ int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.auditError != nil {
		return p.auditError
	}
	p.audits = append(p.audits, "whitelist_"+outcome)
	return nil
}

func enabledService(t *testing.T) (*Service, *memoryPersistence) {
	t.Helper()
	memory := newMemoryPersistence()
	service := newService(memory)
	cfg := service.syslog
	cfg.Enabled = true
	cfg.Address = "127.0.0.1:6514"
	if err := service.ConfigureSyslog(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	return service, memory
}

func TestSyslogValidation(t *testing.T) {
	base := SyslogConfig{Enabled: true, Transport: "tls", Address: "nas.local:6514", Facility: 16, TimeoutSeconds: 3, MaxRetries: 3, QueueCapacity: 1000}
	for _, name := range []string{"transport", "endpoint", "inject", "port", "timeout", "retries", "capacity", "facility", "server"} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			switch name {
			case "transport":
				cfg.Transport = "http"
			case "endpoint":
				cfg.Address = "https://server:6514"
			case "inject":
				cfg.Address = "evil\r\n:514"
			case "port":
				cfg.Address = "host:65536"
			case "timeout":
				cfg.TimeoutSeconds = 0
			case "retries":
				cfg.MaxRetries = 6
			case "capacity":
				cfg.QueueCapacity = 10001
			case "facility":
				cfg.Facility = 24
			case "server":
				cfg.ServerName = "user@host"
			}
			if cfg.Validate() == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSyslogOnlyExportsMetadataAndBoundsQueue(t *testing.T) {
	service, memory := enabledService(t)
	service.syslog.QueueCapacity = 1
	log := &model.AttackLog{EventID: "evt\r\nFAKE", IP: "192.0.2.4", URI: "/private?token=secret", RequestPacket: "Authorization: secret", AttackDetail: "password=secret", AttackType: "sql\nforged", Severity: 4, Status: 2}
	if err := service.Enqueue(context.Background(), log); err != nil {
		t.Fatal(err)
	}
	if err := service.Enqueue(context.Background(), log); err != nil {
		t.Fatal("dedup", err)
	}
	log.EventID = "second"
	if !errors.Is(service.Enqueue(context.Background(), log), ErrQueueFull) {
		t.Fatal("unbounded queue")
	}
	message := string(FormatRFC5424(service.syslog, memory.queue[0].Event))
	if strings.ContainsAny(message, "\r\n") || strings.Contains(message, "secret") || strings.Contains(message, "/private") || !strings.Contains(message, `"action":"observed"`) {
		t.Fatalf("unsafe export: %s", message)
	}
	_, status, err := service.Syslog(context.Background())
	if err != nil || status.Queued != 1 || status.DroppedTotal != 1 {
		t.Fatalf("bad stats %#v: %v", status, err)
	}
}

func TestSyslogRetryExhaustionAndManualResume(t *testing.T) {
	service, memory := enabledService(t)
	service.syslog.MaxRetries = 2
	if err := service.Enqueue(context.Background(), &model.AttackLog{EventID: "1", IP: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	service.send = func(context.Context, SyslogConfig, Event) error {
		attempts++
		return errors.New("private endpoint must not leak")
	}
	for service.processOne(context.Background()) {
	}
	_, status, _ := service.Syslog(context.Background())
	if attempts != 3 || status.Failed != 1 || status.RetriedTotal != 2 || strings.Contains(status.LastError, "private") {
		t.Fatalf("retry mismatch: %d %#v", attempts, status)
	}
	if len(memory.queue) != 1 {
		t.Fatal("exhausted event lost")
	}
	if err := service.Sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	service.send = func(context.Context, SyslogConfig, Event) error { return nil }
	service.processOne(context.Background())
	_, status, _ = service.Syslog(context.Background())
	if status.Queued != 0 || status.Failed != 0 || status.SentTotal != 1 || status.LastSuccess == "" {
		t.Fatalf("bad retry outcome %#v", status)
	}
}

func TestConfigurationFailureKeepsRuntimeSettings(t *testing.T) {
	service, memory := enabledService(t)
	original := service.syslog
	memory.saveError = errors.New("db down")
	changed := original
	changed.Address = "other:514"
	if service.ConfigureSyslog(context.Background(), changed) == nil || service.syslog != original {
		t.Fatal("partial config change")
	}
}

func TestShutdownLeavesUnconfirmedEvent(t *testing.T) {
	service, memory := enabledService(t)
	started := make(chan struct{})
	service.send = func(ctx context.Context, _ SyslogConfig, _ Event) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	if err := service.Enqueue(context.Background(), &model.AttackLog{EventID: "1", IP: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("worker not started")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if len(memory.queue) != 1 {
		t.Fatal("unconfirmed event lost at shutdown")
	}
}

func TestSyslogTCPUsesOctetCounting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
		reader := bufio.NewReader(connection)
		prefix, err := reader.ReadString(' ')
		if err != nil {
			result <- err.Error()
			return
		}
		size, _ := strconv.Atoi(strings.TrimSpace(prefix))
		message := make([]byte, size)
		_, err = io.ReadFull(reader, message)
		if err != nil {
			result <- err.Error()
			return
		}
		result <- string(message)
	}()
	cfg := SyslogConfig{Transport: "tcp", Address: listener.Addr().String(), TimeoutSeconds: 1, Facility: 16}
	event := Event{ID: "tcp-test", Time: time.Now()}
	if err = sendSyslog(context.Background(), cfg, event); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-result:
		if message != string(FormatRFC5424(cfg, event)) {
			t.Fatalf("frame mismatch %q", message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no syslog message")
	}
}

func TestSyslogUDPHasNoStreamPrefix(t *testing.T) {
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	cfg := SyslogConfig{Transport: "udp", Address: connection.LocalAddr().String(), TimeoutSeconds: 1, Facility: 16}
	event := Event{Time: time.Now()}
	if err = sendSyslog(context.Background(), cfg, event); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4096)
	count, _, err := connection.ReadFrom(buffer)
	if err != nil || string(buffer[:count]) != string(FormatRFC5424(cfg, event)) {
		t.Fatalf("invalid datagram %v", err)
	}
}

func TestSyslogTLSRejectsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	cfg := SyslogConfig{Transport: "tls", Address: strings.TrimPrefix(server.URL, "https://"), TimeoutSeconds: 1}
	if sendSyslog(context.Background(), cfg, Event{Time: time.Now()}) == nil {
		t.Fatal("untrusted TLS accepted")
	}
}

type fakeClient func(*http.Request) (*http.Response, error)

func (client fakeClient) Do(request *http.Request) (*http.Response, error) { return client(request) }

func linkedService(t *testing.T) (*Service, *memoryPersistence) {
	t.Helper()
	service, memory := enabledService(t)
	t.Setenv("JINGSHIELD_LINKAGE_TEST_KEY", strings.Repeat("test-only-", 4))
	cfg := LinkageConfig{Enabled: true, Protocol: Protocol, DeviceType: "waf", Endpoint: "https://peer.example", SecretEnv: "JINGSHIELD_LINKAGE_TEST_KEY", TimeoutSeconds: 1}
	if err := service.ConfigureLinkage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	return service, memory
}

func jsonResponse(data any) *http.Response {
	body, _ := json.Marshal(map[string]any{"code": 0, "data": data})
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body)))}
}

func TestWhitelistPushRequiresCapabilityAndConfirmsExactSnapshot(t *testing.T) {
	for _, supported := range []bool{false, true} {
		service, memory := linkedService(t)
		cfg, _ := service.Linkage()
		cfg.SourceID = "nas_waf"
		if err := service.ConfigureLinkage(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		posts := 0
		service.clientFactory = func(LinkageConfig) peerClient {
			return fakeClient(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet {
					abilities := []string{"block-batch"}
					if supported {
						abilities = append(abilities, "whitelist-sync")
					}
					return jsonResponse(Capabilities{Protocol: Protocol, DeviceType: "waf", Capabilities: abilities, MaxBatchSize: 500}), nil
				}
				posts++
				if request.URL.Path != "/openapi/v1/ip/whitelist/sync" {
					t.Fatalf("unexpected path %s", request.URL.Path)
				}
				var input WhitelistRequest
				if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
					t.Fatal(err)
				}
				if len(input.Rules) != 1 || input.Rules[0] != "198.51.100.0/24" {
					t.Fatalf("not normalized: %+v", input)
				}
				checksum := sha256.Sum256([]byte(input.Rules[0]))
				return jsonResponse(WhitelistResult{Source: input.Source, Revision: input.Revision, Count: 1, Digest: hex.EncodeToString(checksum[:])}), nil
			})
		}
		result, err := service.PushWhitelist(context.Background(), WhitelistRequest{Source: "nas_waf", Revision: 42, Rules: []string{"198.51.100.*"}})
		if !supported && (err == nil || posts != 0 || len(memory.audits) != 0) {
			t.Fatalf("unsupported peer received rules: err=%v posts=%d audits=%v", err, posts, memory.audits)
		}
		if supported && (err != nil || posts != 1 || result == nil || result.Count != 1 || fmt.Sprint(memory.audits) != "[whitelist_requested whitelist_confirmed]") {
			t.Fatalf("unconfirmed snapshot: result=%+v err=%v posts=%d audits=%v", result, err, posts, memory.audits)
		}
	}
}

func TestBatchLimitEnforcedBeforeAnyNetwork(t *testing.T) {
	service, _ := linkedService(t)
	calls := 0
	service.clientFactory = func(LinkageConfig) peerClient {
		return fakeClient(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("should not call") })
	}
	for _, ips := range [][]string{{}, make([]string, 501), {"192.0.2.0/24"}, {"invalid"}} {
		if _, err := service.BlockPeer(context.Background(), BlockRequest{IPs: ips}); err == nil {
			t.Fatal("invalid batch accepted")
		}
	}
	if calls != 0 {
		t.Fatal("network before validation")
	}
}

func TestProtocolMismatchCannotEnforce(t *testing.T) {
	service, _ := linkedService(t)
	requests := []string{}
	service.clientFactory = func(LinkageConfig) peerClient {
		return fakeClient(func(request *http.Request) (*http.Response, error) {
			requests = append(requests, request.Method)
			return jsonResponse(Capabilities{Protocol: "vendor-native", DeviceType: "waf", Capabilities: []string{"block-batch"}, MaxBatchSize: 500}), nil
		})
	}
	if _, err := service.BlockPeer(context.Background(), BlockRequest{IPs: []string{"192.0.2.1"}, Reason: "regression"}); err == nil {
		t.Fatal("incompatible device accepted")
	}
	if len(requests) != 1 || requests[0] != "GET" {
		t.Fatal("enforcement sent to incompatible peer")
	}
}

func TestCompatibleBatchUsesFreshHandshakeAndConfirmsCounts(t *testing.T) {
	service, memory := linkedService(t)
	calls := 0
	service.clientFactory = func(LinkageConfig) peerClient {
		return fakeClient(func(request *http.Request) (*http.Response, error) {
			calls++
			if request.Header.Get("X-API-Key") == "" {
				t.Error("missing auth")
			}
			if request.Method == "GET" {
				return jsonResponse(Capabilities{Protocol: Protocol, DeviceType: "waf", Capabilities: []string{"block-batch"}, MaxBatchSize: 500}), nil
			}
			return jsonResponse(BlockResult{Requested: 3, Unique: 2, Blocked: 1, SkippedWhitelist: 1, SkippedIPs: []string{"192.0.2.2"}}), nil
		})
	}
	result, err := service.BlockPeer(context.Background(), BlockRequest{IPs: []string{"192.0.2.1", "192.0.2.1", "192.0.2.2"}, Reason: "regression"})
	if err != nil || result.Blocked != 1 || calls != 2 {
		t.Fatalf("bad result %#v %v %d", result, err, calls)
	}
	_, status := service.Linkage()
	if !status.Compatible || status.LastSuccess == "" || fmt.Sprint(memory.audits) != "[requested confirmed]" {
		t.Fatalf("bad state %#v %#v", status, memory.audits)
	}
}

func TestRemoteFailureIsNotRetriedOrClaimedSuccess(t *testing.T) {
	service, memory := linkedService(t)
	posts := 0
	service.clientFactory = func(LinkageConfig) peerClient {
		return fakeClient(func(request *http.Request) (*http.Response, error) {
			if request.Method == "GET" {
				return jsonResponse(Capabilities{Protocol: Protocol, DeviceType: "waf", Capabilities: []string{"block-batch"}, MaxBatchSize: 500}), nil
			}
			posts++
			return nil, errors.New("secret error payload")
		})
	}
	_, err := service.BlockPeer(context.Background(), BlockRequest{IPs: []string{"192.0.2.1"}, Reason: "regression"})
	if err == nil || strings.Contains(err.Error(), "secret") || posts != 1 {
		t.Fatalf("unsafe retry/error %v %d", err, posts)
	}
	_, status := service.Linkage()
	if status.LastSuccess != "" || status.LastResult != nil || fmt.Sprint(memory.audits) != "[requested unconfirmed]" {
		t.Fatal("unconfirmed action treated as success")
	}
}

func TestLinkageValidationAndSecretReference(t *testing.T) {
	service, _ := linkedService(t)
	base, _ := service.Linkage()
	for _, endpoint := range []string{"http://peer", "https://user:password@peer", "https://peer/path", "https://peer?key=secret", "https://peer#fragment", "https://169.254.169.254:0"} {
		cfg := base
		cfg.Endpoint = endpoint
		if cfg.Validate() == nil {
			t.Fatalf("unsafe endpoint %s", endpoint)
		}
	}
	cfg := base
	cfg.SecretEnv = "AWS_SECRET_ACCESS_KEY"
	if cfg.Validate() == nil {
		t.Fatal("unrestricted environment reference")
	}
	if _, err := validatedDial(context.Background(), "tcp", "169.254.169.254:443"); err == nil {
		t.Fatal("metadata destination allowed")
	}
}

func TestInvalidPeerResultRejected(t *testing.T) {
	input := BlockRequest{IPs: []string{"192.0.2.1", "192.0.2.2"}}
	for _, result := range []BlockResult{{Requested: 2, Unique: 2, Blocked: 500}, {Requested: 2, Unique: 2, Blocked: 1, SkippedWhitelist: 1, SkippedIPs: []string{"192.0.2.9"}}, {Requested: 2, Unique: 2, SkippedWhitelist: 2, SkippedIPs: []string{"192.0.2.1", "192.0.2.1"}}} {
		if validateBlockResult(input, result) == nil {
			t.Fatalf("invalid result accepted %#v", result)
		}
	}
}

func TestCrossNodeSettingsRefreshInvalidatesPeerTrust(t *testing.T) {
	service, memory := linkedService(t)
	service.linkageStatus.Compatible = true
	newSyslog := service.syslog
	newSyslog.Enabled = false
	newLinkage := service.linkage
	newLinkage.Endpoint = "https://other.example"
	if err := memory.save(context.Background(), "operations_syslog_config", newSyslog); err != nil {
		t.Fatal(err)
	}
	if err := memory.save(context.Background(), "operations_linkage_config", newLinkage); err != nil {
		t.Fatal(err)
	}
	service.refreshSettings(context.Background())
	cfg, status := service.Linkage()
	if service.syslog.Enabled || cfg.Endpoint != newLinkage.Endpoint || status.Compatible {
		t.Fatal("stale multi-node settings/trust")
	}
	memory.settings["operations_syslog_config"] = []byte(`invalid`)
	service.refreshSettings(context.Background())
	if service.syslogStatus.LastError != "settings_refresh_failed" {
		t.Fatal("refresh error hidden")
	}
}

func TestStandaloneProbeAndSafeTransportDefaults(t *testing.T) {
	service, _ := linkedService(t)
	service.clientFactory = func(LinkageConfig) peerClient {
		return fakeClient(func(*http.Request) (*http.Response, error) {
			return jsonResponse(Capabilities{Protocol: Protocol, DeviceType: "waf", Capabilities: []string{"block-batch"}, MaxBatchSize: 500}), nil
		})
	}
	if _, err := service.ProbeLinkage(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg, _ := service.Linkage()
	client := newPeerClient(cfg).(*http.Client)
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 || transport.Proxy != nil {
		t.Fatal("unsafe transport defaults")
	}
	if client.CheckRedirect(nil, nil) == nil {
		t.Fatal("credential-bearing redirects allowed")
	}
	cfg.Enabled = false
	if err := service.ConfigureLinkage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ProbeLinkage(context.Background()); err == nil {
		t.Fatal("disabled peer probed")
	}
}

func TestUnavailableAndDisabledOperationsDoNotClaimSuccess(t *testing.T) {
	service := New(nil)
	if !errors.Is(service.Start(context.Background()), ErrUnavailable) {
		t.Fatal("nil database accepted")
	}
	if _, _, err := service.Syslog(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unavailable queue called healthy")
	}
	if err := service.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if service.Sync(context.Background(), true) == nil {
		t.Fatal("disabled sync accepted")
	}
	if err := service.Enqueue(context.Background(), nil); err != nil {
		t.Fatal("nil event", err)
	}
	if service.processOne(context.Background()) {
		t.Fatal("disabled worker processed event")
	}
}
