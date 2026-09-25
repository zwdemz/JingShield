package api_test

import (
	"database/sql/driver"
	"errors"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"jingshield/internal/config"
	"jingshield/tests/testdb"
)

func TestProtectionSettingsAuthenticatedSnapshot(t *testing.T) {
	fixture := newFixture(t, true)
	data := requireResponse(t, fixture.request(t, "GET", "/api/v1/protection/settings", nil, "session"), http.StatusOK)
	if data["profile"] != "standard" || len(data["engines"].([]any)) != 8 {
		t.Fatalf("implemented engine snapshot is incomplete: %+v", data)
	}
	values := data["values"].(map[string]any)
	if values["behavior_threshold"] != "8" || values["behavior_mode"] != "block" {
		t.Fatalf("unexpected NAS-safe behavior defaults: %+v", values)
	}
}

func TestProtectionPresetAndIndependentOverridePersistAtomically(t *testing.T) {
	for _, preset := range config.ProtectionProfiles() {
		t.Run(preset.ID, func(t *testing.T) {
			values := preset.Values
			values["scanner_protection_status"] = "0"
			keys := make([]string, 0, len(values))
			for key := range values {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			steps := []testdb.Step{{Kind: "begin"}}
			for _, key := range keys {
				steps = append(steps, testdb.Step{Kind: "exec", Contains: "INSERT INTO jyj_config", Check: checkArguments(key, values[key], values[key])})
			}
			steps = append(steps, testdb.Step{Kind: "commit"})
			fixture := newFixture(t, true, steps...)
			data := requireResponse(t, fixture.request(t, "PUT", "/api/v1/protection/settings", map[string]any{"profile": preset.ID, "values": map[string]string{"scanner_protection_status": "0"}}, "csrf"), http.StatusOK)
			if data["profile"] != "custom" || fixture.dynamic.Get("scanner_protection_status") != "0" || fixture.dynamic.Get("behavior_threshold") != values["behavior_threshold"] {
				t.Fatalf("preset or override not published: %+v", data)
			}
		})
	}
}

func TestProtectionSettingsRejectMalformedAndMissingParameters(t *testing.T) {
	for _, input := range []any{
		map[string]any{}, map[string]any{"profile": "unknown"}, map[string]any{"values": map[string]string{"file_check_status": "1"}},
		map[string]any{"values": map[string]string{"behavior_threshold": "1"}}, map[string]any{"values": map[string]string{"behavior_window_seconds": "3601"}},
		map[string]any{"values": map[string]string{"behavior_block_seconds": "86401"}}, map[string]any{"values": map[string]string{"behavior_mode": "allow"}},
		map[string]any{"values": map[string]string{"sql_protection_status": "2"}}, map[string]any{"unexpected": true},
	} {
		fixture := newFixture(t, true)
		requireResponse(t, fixture.request(t, "PUT", "/api/v1/protection/settings", input, "csrf"), http.StatusBadRequest)
	}
}

func TestProtectionSettingsAcceptsThresholdTwentyAsString(t *testing.T) {
	fixture := newFixture(t, true,
		testdb.Step{Kind: "begin"},
		testdb.Step{Kind: "exec", Contains: "INSERT INTO jyj_config", Check: checkArguments("behavior_threshold", "20", "20")},
		testdb.Step{Kind: "commit"},
	)
	data := requireResponse(t, fixture.request(t, "PUT", "/api/v1/protection/settings", map[string]any{"values": map[string]string{"behavior_threshold": "20"}}, "csrf"), http.StatusOK)
	if fixture.dynamic.Get("behavior_threshold") != "20" || data["values"].(map[string]any)["behavior_threshold"] != "20" {
		t.Fatalf("threshold 20 was not persisted: %+v", data)
	}
}

func TestProtectionTransactionFailureDoesNotReportSuccessOrChangeMemory(t *testing.T) {
	for _, failCommit := range []bool{false, true} {
		steps := []testdb.Step{{Kind: "begin"}, {Kind: "exec", Contains: "INSERT INTO jyj_config"}}
		if failCommit {
			steps = append(steps, testdb.Step{Kind: "commit", Error: errors.New("simulated commit failure")})
		} else {
			steps[1].Error = errors.New("simulated config write failure")
			steps = append(steps, testdb.Step{Kind: "rollback"})
		}
		fixture := newFixture(t, true, steps...)
		requireResponse(t, fixture.request(t, "PUT", "/api/v1/protection/settings", map[string]any{"values": map[string]string{"scanner_protection_status": "0"}}, "csrf"), http.StatusInternalServerError)
		if fixture.dynamic.Get("scanner_protection_status") != "1" {
			t.Fatal("failed transaction changed live engine configuration")
		}
	}
}

func TestWAFStatusIncludesSharedStateSiteCountsAndBehaviorMetrics(t *testing.T) {
	now := time.Now()
	fixture := newFixture(t, true, testdb.Step{Kind: "query", Contains: "FROM jyj_sites ORDER BY id DESC", Columns: []string{"id", "name", "host", "upstream", "enabled", "pass_host", "tls_skip_verify", "created_at", "updated_at"}, Values: [][]driver.Value{
		{int64(1), "NAS", "nas.test", "https://127.0.0.1:5667", true, true, false, now, now},
		{int64(2), "Download", "download.test", "http://127.0.0.1:2345", false, true, false, now, now},
	}})
	data := requireResponse(t, fixture.request(t, "GET", "/api/v1/system/waf-status", nil, "session"), http.StatusOK)
	sites := data["sites"].(map[string]any)
	metrics := data["metrics"].(map[string]any)
	if data["state_backend"] != "redis" || data["shared_state"] != true || sites["total"] != float64(2) || sites["enabled"] != float64(1) || metrics["evaluated_total"] != float64(42) {
		t.Fatalf("incorrect detailed WAF status: %+v", data)
	}
	if metrics["behavior"].(map[string]any)["state_errors_total"] != float64(3) || data["started_at"] == "" {
		t.Fatal("state errors or lifecycle metadata missing")
	}
}

func TestAdministrativeRoutesEnforceSessionAndCSRFBeforeOperations(t *testing.T) {
	routes := []struct{ method, path string }{
		{"GET", "/api/v1/protection/settings"}, {"PUT", "/api/v1/protection/settings"}, {"GET", "/api/v1/system/waf-status"},
		{"GET", "/api/v1/system/syslog"}, {"PUT", "/api/v1/system/syslog"}, {"POST", "/api/v1/system/syslog/sync"},
		{"GET", "/api/v1/system/linkage"}, {"PUT", "/api/v1/system/linkage"}, {"POST", "/api/v1/system/linkage/probe"}, {"POST", "/api/v1/system/linkage/block-batch"},
		{"GET", "/api/v1/attacks/ip-summary"}, {"POST", "/api/v1/ip-list/block-batch"},
	}
	fixture := newFixture(t, true)
	for _, route := range routes {
		t.Run(route.method+route.path, func(t *testing.T) {
			requireResponse(t, fixture.request(t, route.method, route.path, map[string]any{}, "none"), http.StatusUnauthorized)
			if route.method != "GET" {
				requireResponse(t, fixture.request(t, route.method, route.path, map[string]any{}, "session"), http.StatusForbidden)
			}
			if strings.HasPrefix(route.path, "/api/v1/system/syslog") || strings.HasPrefix(route.path, "/api/v1/system/linkage") {
				requireResponse(t, fixture.request(t, route.method, route.path, map[string]any{}, "csrf"), http.StatusServiceUnavailable)
			}
		})
	}
}

func TestProtectionMasterSwitchIsExplicitAndPresetsNeverOverrideIt(t *testing.T) {
	steps := []testdb.Step{
		{Kind: "begin"},
		{Kind: "exec", Contains: "INSERT INTO jyj_config", Check: checkArguments("system_status", "0", "0")},
		{Kind: "commit"},
		{Kind: "begin"},
	}
	values := config.ProtectionDefaults()
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		steps = append(steps, testdb.Step{Kind: "exec", Contains: "INSERT INTO jyj_config", Check: checkArguments(key, values[key], values[key])})
	}
	steps = append(steps, testdb.Step{Kind: "commit"})
	fixture := newFixture(t, true, steps...)
	data := requireResponse(t, fixture.request(t, "PUT", "/api/v1/protection/settings", map[string]any{"values": map[string]string{"system_status": "0"}}, "csrf"), http.StatusOK)
	if data["values"].(map[string]any)["system_status"] != "0" {
		t.Fatal("master switch was not exposed after explicit update")
	}
	data = requireResponse(t, fixture.request(t, "PUT", "/api/v1/protection/settings", map[string]string{"profile": "standard"}, "csrf"), http.StatusOK)
	if fixture.dynamic.Get("system_status") != "0" || data["values"].(map[string]any)["system_status"] != "0" {
		t.Fatal("preset silently enabled the master switch")
	}
}
