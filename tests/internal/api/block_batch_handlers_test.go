package api_test

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"jingshield/tests/testdb"
)

type batchRoute struct{ path, authentication, actor string }

var batchRoutes = []batchRoute{
	{path: "/api/v1/ip-list/block-batch", authentication: "csrf", actor: "admin:7"},
	{path: "/openapi/v1/ip/block-batch", authentication: "api", actor: "openapi"},
}

func batchPayload(ips []string, reason string) map[string]any {
	return map[string]any{"ips": ips, "reason": reason, "expire_seconds": 600}
}

func makeMockIPs(count int) []string {
	ips := make([]string, count)
	for index := range ips {
		ips[index] = fmt.Sprintf("198.18.%d.%d", index/250+1, index%250+1)
	}
	return ips
}

func TestBatchRoutesRejectUnauthorizedAndInvalidRequests(t *testing.T) {
	for _, route := range batchRoutes {
		t.Run(route.path, func(t *testing.T) {
			fixture := newFixture(t, route.authentication == "csrf")
			requireResponse(t, fixture.request(t, "POST", route.path, batchPayload([]string{"192.0.2.1"}, "test"), "none"), http.StatusUnauthorized)
			if route.authentication == "csrf" {
				requireResponse(t, fixture.request(t, "POST", route.path, batchPayload([]string{"192.0.2.1"}, "test"), "session"), http.StatusForbidden)
			}
			for _, ips := range [][]string{nil, {}, makeMockIPs(501), {"not-an-ip"}, {"192.0.2.0/24"}, {"0.0.0.0"}, {"127.0.0.1"}, {"::1"}, {"ff02::1"}, {"fe80::1"}, {"192.0.2.1", "bad"}} {
				requireResponse(t, fixture.request(t, "POST", route.path, batchPayload(ips, "test"), route.authentication), http.StatusBadRequest)
			}
			duplicates := make([]string, 501)
			for index := range duplicates {
				duplicates[index] = "192.0.2.1"
			}
			requireResponse(t, fixture.request(t, "POST", route.path, batchPayload(duplicates, "test"), route.authentication), http.StatusBadRequest)
			for _, reason := range []string{"", "  ", "line\nbreak", "\nleading newline", "trailing newline\r\n", "nul\x00value", strings.Repeat("a", 256)} {
				requireResponse(t, fixture.request(t, "POST", route.path, batchPayload([]string{"192.0.2.1"}, reason), route.authentication), http.StatusBadRequest)
			}
			for _, expires := range []int{-1, 31536001} {
				payload := batchPayload([]string{"192.0.2.1"}, "test")
				payload["expire_seconds"] = expires
				requireResponse(t, fixture.request(t, "POST", route.path, payload, route.authentication), http.StatusBadRequest)
			}
			requireResponse(t, fixture.request(t, "POST", route.path, map[string]any{}, route.authentication), http.StatusBadRequest)
		})
	}
}

func TestBatchRoutesAcceptExactlyFiveHundredWithTransactionalAudit(t *testing.T) {
	for _, route := range batchRoutes {
		t.Run(route.path, func(t *testing.T) {
			ips := makeMockIPs(500)
			sorted := append([]string{}, ips...)
			sort.Strings(sorted)
			steps := batchStart(nil)
			for _, ip := range sorted {
				steps = append(steps, blockOneSteps(ip)...)
			}
			steps = append(steps, testdb.Step{Kind: "exec", Contains: "INSERT INTO jyj_ip_action_log", Check: func(arguments []driver.NamedValue) error {
				if len(arguments) != 7 || arguments[0].Value != route.actor || arguments[3].Value != int64(500) || arguments[4].Value != int64(500) || arguments[5].Value != int64(0) {
					return fmt.Errorf("incorrect atomic batch audit: %+v", arguments)
				}
				return nil
			}}, testdb.Step{Kind: "commit"})
			fixture := newFixture(t, route.authentication == "csrf", steps...)
			data := requireResponse(t, fixture.request(t, "POST", route.path, batchPayload(ips, "mock batch"), route.authentication), http.StatusOK)
			if data["requested"] != float64(500) || data["blocked"] != float64(500) || data["unique"] != float64(500) || data["skipped_whitelist"] != float64(0) {
				t.Fatalf("incorrect 500-IP result: %+v", data)
			}
		})
	}
}

func TestBatchRoutesNormalizeDeduplicateAndRespectWhitelist(t *testing.T) {
	for _, route := range batchRoutes {
		t.Run(route.path, func(t *testing.T) {
			steps := batchStart([][]driver.Value{{"192.0.2.0/24"}, {"198.51.100.*"}})
			steps = append(steps, blockOneSteps("2001:db8::1")...)
			steps = append(steps, testdb.Step{Kind: "exec", Contains: "INSERT INTO jyj_ip_action_log"}, testdb.Step{Kind: "commit"})
			fixture := newFixture(t, route.authentication == "csrf", steps...)
			ips := []string{"192.0.2.10", "::ffff:192.0.2.10", "198.51.100.20", "2001:0DB8:0:0:0:0:0:1", "2001:db8::1"}
			data := requireResponse(t, fixture.request(t, "POST", route.path, batchPayload(ips, "mock whitelist check"), route.authentication), http.StatusOK)
			if data["requested"] != float64(5) || data["unique"] != float64(3) || data["blocked"] != float64(1) || data["skipped_whitelist"] != float64(2) || len(data["skipped_ips"].([]any)) != 2 {
				t.Fatalf("normalization or whitelist bypassed: %+v", data)
			}
		})
	}
}

func TestBatchTransactionFailureNeverReturnsPartialSuccess(t *testing.T) {
	for _, route := range batchRoutes {
		for _, failure := range []string{"insert", "audit", "commit"} {
			t.Run(route.path+"/"+failure, func(t *testing.T) {
				steps := append(batchStart(nil), blockOneSteps("192.0.2.1")...)
				if failure == "insert" {
					steps[len(steps)-1].Error = errors.New("simulated private database failure")
					steps = append(steps, testdb.Step{Kind: "rollback"})
				} else {
					steps = append(steps, testdb.Step{Kind: "exec", Contains: "INSERT INTO jyj_ip_action_log"})
					if failure == "audit" {
						steps[len(steps)-1].Error = errors.New("simulated audit failure")
						steps = append(steps, testdb.Step{Kind: "rollback"})
					} else {
						steps = append(steps, testdb.Step{Kind: "commit", Error: errors.New("simulated commit failure")})
					}
				}
				fixture := newFixture(t, route.authentication == "csrf", steps...)
				response := fixture.request(t, "POST", route.path, batchPayload([]string{"192.0.2.1"}, "mock failure"), route.authentication)
				requireResponse(t, response, http.StatusInternalServerError)
				if strings.Contains(response.Body.String(), "simulated") || strings.Contains(response.Body.String(), `"blocked":1`) {
					t.Fatal("failed transaction leaked internals or partial success")
				}
			})
		}
	}
}

func batchStart(whitelist [][]driver.Value) []testdb.Step {
	return []testdb.Step{{Kind: "begin"}, {Kind: "query", Contains: "SELECT ip FROM jyj_ip_list WHERE type = ? FOR UPDATE", Columns: []string{"ip"}, Values: whitelist}, {Kind: "query", Contains: "SELECT rule FROM jyj_synced_whitelist", Columns: []string{"rule"}}}
}

func blockOneSteps(ip string) []testdb.Step {
	checkIP := func(arguments []driver.NamedValue) error {
		if len(arguments) == 0 || arguments[0].Value != ip {
			return fmt.Errorf("batch address got %+v expected %s", arguments, ip)
		}
		return nil
	}
	return []testdb.Step{
		{Kind: "query", Contains: "SELECT type, expire_time FROM jyj_ip_list WHERE ip", Columns: []string{"type", "expire_time"}, Check: checkIP},
		{Kind: "exec", Contains: "DELETE FROM jyj_ip_list WHERE ip", Check: checkIP},
		{Kind: "exec", Contains: "INSERT INTO jyj_ip_list (ip, type, reason, expire_time)", Check: checkIP},
	}
}
