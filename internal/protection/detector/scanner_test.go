package detector

import (
	"context"
	"errors"
	"net/http/httptest"
	"strconv"
	"testing"

	"jingshield/internal/protection/reqctx"
	"jingshield/internal/store"
	"jingshield/internal/store/memory"
)

type behaviorTestConfig map[string]string

func (c behaviorTestConfig) GetDefault(key, fallback string) string {
	if value, exists := c[key]; exists {
		return value
	}
	return fallback
}

func (c behaviorTestConfig) GetIntDefault(key string, fallback int) int {
	value, err := strconv.Atoi(c[key])
	if err != nil {
		return fallback
	}
	return value
}

func behaviorRequest(host, ip, path string) *reqctx.RequestContext {
	request := httptest.NewRequest("GET", "https://"+host+path, nil)
	request.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0 Safari/537.36")
	return &reqctx.RequestContext{R: request, IP: ip, UserAgent: request.UserAgent(), URI: request.RequestURI, Method: request.Method, Header: request.Header}
}

func TestScannerAllowsNASDownloadsAndOrdinaryRoutes(t *testing.T) {
	detector := NewScannerDetector(memory.New())
	for _, requestPath := range []string{"/v", "/music/", "/downloads/archive.zip", "/backup", "/backups/weekly.tar.gz", "/downloads/database.sql", "/files/config.bak", "/config.yml", "/package.json", "/debug/player", "/.github/workflows/test.yaml"} {
		for count := 0; count < 20; count++ {
			if result := detector.Check(context.Background(), behaviorRequest("nas.example:5667", "192.0.2.1", requestPath)); result != nil {
				t.Fatalf("normal NAS route %s unexpectedly detected: %+v", requestPath, result)
			}
		}
	}
	if detector.Metrics()["probe_total"] != uint64(0) {
		t.Fatal("normal downloads must not contribute to behavior state")
	}
}

func TestScannerScopesByHostAndIPNotBrowserFingerprint(t *testing.T) {
	detector := NewScannerDetector(memory.New(), behaviorTestConfig{"behavior_threshold": "2"})
	for _, client := range []struct{ host, ip string }{{"nas.example:5667", "192.0.2.1"}, {"nas.example:5667", "192.0.2.2"}, {"other.example:5667", "192.0.2.1"}, {"nas.example:2345", "192.0.2.1"}} {
		if result := detector.Check(context.Background(), behaviorRequest(client.host, client.ip, "/.env")); result != nil {
			t.Fatalf("first probe inherited another host/IP's state: %+v", result)
		}
	}
	result := detector.Check(context.Background(), behaviorRequest("nas.example:5667", "192.0.2.1", "/.git/config"))
	if result == nil || result.ObserveOnly {
		t.Fatalf("two corroborated probes should block: %+v", result)
	}
	if result := detector.Check(context.Background(), behaviorRequest("nas.example:5667", "192.0.2.2", "/music/")); result != nil {
		t.Fatalf("block leaked to another same-UA client: %+v", result)
	}
	if result := detector.Check(context.Background(), behaviorRequest("NAS.EXAMPLE.:5667", "192.0.2.1", "/music/")); result == nil {
		t.Fatal("normalized host must retain its scoped temporary block")
	}
}

func TestScannerRequiresCorroborationOrRepeatedHighConfidenceProbe(t *testing.T) {
	detector := NewScannerDetector(memory.New(), behaviorTestConfig{"behavior_threshold": "2"})
	for count := 1; count <= 4; count++ {
		result := detector.Check(context.Background(), behaviorRequest("nas.example", "192.0.2.1", "/.env"))
		if (result != nil) != (count == 4) {
			t.Fatalf("single-category repetition %d: %+v", count, result)
		}
	}
	toolDetector := NewScannerDetector(memory.New(), behaviorTestConfig{"behavior_threshold": "2"})
	request := behaviorRequest("nas.example", "192.0.2.1", "/.env")
	request.UserAgent = "sqlmap/1.8"
	if result := toolDetector.Check(context.Background(), request); result != nil {
		t.Fatal("scanner UA alone must not bypass the count threshold")
	}
	if result := toolDetector.Check(context.Background(), request); result == nil {
		t.Fatal("tool fingerprint should corroborate repeated sensitive probes")
	}
}

func TestScannerObservationAndDynamicDisable(t *testing.T) {
	settings := behaviorTestConfig{"behavior_threshold": "2", "behavior_mode": "observe"}
	detector := NewScannerDetector(memory.New(), settings)
	detector.Check(context.Background(), behaviorRequest("nas.example", "192.0.2.1", "/.env"))
	result := detector.Check(context.Background(), behaviorRequest("nas.example", "192.0.2.1", "/.git/config"))
	if result == nil || !result.ObserveOnly {
		t.Fatalf("observed detection must never block: %+v", result)
	}
	if result := detector.Check(context.Background(), behaviorRequest("nas.example", "192.0.2.1", "/music/")); result != nil {
		t.Fatal("observation mode created a temporary block")
	}
	settings["behavior_mode"] = "block"
	if result := detector.Check(context.Background(), behaviorRequest("nas.example", "192.0.2.1", "/.env")); result == nil || result.ObserveOnly {
		t.Fatal("runtime block mode was not applied")
	}
	settings["scanner_protection_status"] = "0"
	if result := detector.Check(context.Background(), behaviorRequest("nas.example", "192.0.2.1", "/music/")); result != nil {
		t.Fatal("disabled detector enforced an existing block")
	}
	if metrics := detector.Metrics(); metrics["observed_total"] != uint64(1) || metrics["blocked_total"] != uint64(1) {
		t.Fatalf("unexpected behavior metrics: %+v", metrics)
	}
}

type failingBehaviorStore struct{ *memory.Store }

func (s failingBehaviorStore) ObserveBehavior(context.Context, string, string, bool, store.BehaviorPolicy, bool) (store.BehaviorSnapshot, error) {
	return store.BehaviorSnapshot{Matched: true, Blocked: true}, errors.New("simulated state failure")
}

func TestScannerStateFailureIsObservableAndFailOpen(t *testing.T) {
	detector := NewScannerDetector(failingBehaviorStore{memory.New()})
	if result := detector.Check(context.Background(), behaviorRequest("nas.example", "192.0.2.1", "/.env")); result != nil {
		t.Fatalf("storage failure must not produce a block: %+v", result)
	}
	if detector.Metrics()["state_errors_total"] != uint64(1) {
		t.Fatal("storage failure was not visible in metrics")
	}
}
