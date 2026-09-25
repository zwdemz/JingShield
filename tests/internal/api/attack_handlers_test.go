package api_test

import (
	"database/sql/driver"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"jingshield/tests/testdb"
)

func TestAttackIPQueriesNormalizeExactPrefixesAndCIDRs(t *testing.T) {
	tests := []struct {
		name, mode, input, predicate string
		arguments                    []any
	}{
		{"exact-ipv4", "exact", "192.0.2.10", "AND ip = ?", []any{"192.0.2.10"}},
		{"mapped-ipv4", "exact", "::ffff:192.0.2.10", "AND ip = ?", []any{"192.0.2.10"}},
		{"canonical-ipv6", "exact", "2001:0DB8:0:0:0:0:0:1", "AND ip = ?", []any{"2001:db8::1"}},
		{"ipv4-prefix", "prefix", "192.0.2.", "INET6_ATON(ip) BETWEEN", []any{"192.0.2.0", "192.0.2.0", "192.0.2.255"}},
		{"ipv6-prefix", "prefix", "2001:db8:", "INET6_ATON(ip) BETWEEN", []any{"2001:db8::", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"}},
		{"ipv4-cidr-masked", "cidr", "192.0.2.7/24", "INET6_ATON(ip) BETWEEN", []any{"192.0.2.0", "192.0.2.0", "192.0.2.255"}},
		{"ipv6-cidr-masked", "cidr", "2001:db8::7/64", "INET6_ATON(ip) BETWEEN", []any{"2001:db8::", "2001:db8::", "2001:db8::ffff:ffff:ffff:ffff"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listArguments := append(append([]any{}, test.arguments...), 10, 0)
			fixture := newFixture(t, true,
				testdb.Step{Kind: "query", Contains: test.predicate, Columns: []string{"count"}, Values: [][]driver.Value{{int64(0)}}, Check: checkArguments(test.arguments...)},
				testdb.Step{Kind: "query", Contains: "ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?", Columns: []string{"id"}, Check: checkArguments(listArguments...)},
			)
			query := url.Values{"ip": {test.input}, "ip_mode": {test.mode}}
			data := requireResponse(t, fixture.request(t, "GET", "/api/v1/attacks?"+query.Encode(), nil, "session"), http.StatusOK)
			if data["total"] != float64(0) || len(data["list"].([]any)) != 0 {
				t.Fatalf("unexpected empty query response: %+v", data)
			}
		})
	}
}

func TestAttackIPQueryValidationRejectsInvalidInputsBeforeSQL(t *testing.T) {
	fixture := newFixture(t, true)
	for _, test := range []struct{ mode, input string }{
		{"invalid", "192.0.2.1"}, {"exact", "192.0.2."}, {"exact", "fe80::1%eth0"}, {"exact", "1' OR 1=1"},
		{"prefix", "192.0.02."}, {"prefix", "192.0.256."}, {"prefix", "192.0.2"}, {"prefix", "2001::db8:"},
		{"prefix", "2001:zzzz:"}, {"cidr", "192.0.2.1/33"}, {"cidr", "2001:db8::1/129"}, {"cidr", "::ffff:192.0.2.1/120"},
	} {
		t.Run(fmt.Sprintf("%s-%s", test.mode, test.input), func(t *testing.T) {
			query := url.Values{"ip": {test.input}, "ip_mode": {test.mode}}
			requireResponse(t, fixture.request(t, "GET", "/api/v1/attacks?"+query.Encode(), nil, "session"), http.StatusBadRequest)
		})
	}
	for _, query := range []string{"", "?ip=192.0.2.&ip_mode=prefix", "?ip=192.0.2.0%2F24&ip_mode=cidr", "?ip=invalid"} {
		requireResponse(t, fixture.request(t, "GET", "/api/v1/attacks/ip-summary"+query, nil, "session"), http.StatusBadRequest)
	}
}
