package api_test

import (
	"database/sql/driver"
	"net/http"
	"testing"

	"jingshield/tests/testdb"
)

func TestWhitelistReceiverRequiresKeyAndRejectsInvalidRules(t *testing.T) {
	fixture := newFixture(t, false)
	request := map[string]any{"source": "nas_waf", "revision": 42, "rules": []string{"192.0.2.0/24"}}
	requireResponse(t, fixture.request(t, "POST", "/openapi/v1/ip/whitelist/sync", request, "none"), http.StatusUnauthorized)
	requireResponse(t, fixture.request(t, "POST", "/openapi/v1/ip/whitelist/sync", map[string]any{"source": "nas_waf", "revision": 42, "rules": []string{"*.*.*.*"}}, "api"), http.StatusBadRequest)
	requireResponse(t, fixture.request(t, "POST", "/openapi/v1/ip/whitelist/sync", map[string]any{"source": "../other", "revision": 42, "rules": []string{}}, "api"), http.StatusBadRequest)
}

func TestWhitelistReceiverReplacesOnlyItsSourceAtomically(t *testing.T) {
	steps := []testdb.Step{
		{Kind: "begin"},
		{Kind: "query", Contains: "FROM jyj_synced_whitelist_state WHERE source_id", Columns: []string{"revision", "digest"}, Check: checkArguments("nas_waf")},
		{Kind: "query", Contains: "SELECT COUNT(*) FROM jyj_synced_whitelist_state", Columns: []string{"count"}, Values: [][]driver.Value{{int64(1)}}},
		{Kind: "exec", Contains: "DELETE FROM jyj_synced_whitelist WHERE source_id", Check: checkArguments("nas_waf")},
		{Kind: "exec", Contains: "INSERT INTO jyj_synced_whitelist (source_id,rule)", Check: checkArguments("nas_waf", "198.51.100.0/24")},
		{Kind: "exec", Contains: "INSERT INTO jyj_synced_whitelist_state"},
		{Kind: "exec", Contains: "INSERT INTO jyj_device_events"},
		{Kind: "commit"},
	}
	fixture := newFixture(t, false, steps...)
	data := requireResponse(t, fixture.request(t, "POST", "/openapi/v1/ip/whitelist/sync", map[string]any{"source": "nas_waf", "revision": 42, "rules": []string{"198.51.100.*"}}, "api"), http.StatusOK)
	if data["source"] != "nas_waf" || data["revision"] != float64(42) || data["count"] != float64(1) {
		t.Fatalf("bad acknowledgement: %+v", data)
	}
}
