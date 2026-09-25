package protection

import (
	"context"
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"testing"

	"jingshield/internal/config"
	"jingshield/internal/model"
	"jingshield/internal/protection/iplist"
	"jingshield/internal/protection/reqctx"
	"jingshield/internal/repository"
	"jingshield/tests/testdb"
)

func TestReceivedWhitelistOverridesExistingBlockWithoutDeletingIt(t *testing.T) {
	database := testdb.Open(t,
		testdb.Step{Kind: "query", Contains: "UNION SELECT rule FROM jyj_synced_whitelist", Columns: []string{"ip"}, Values: [][]driver.Value{{"192.0.2.0/24"}}},
		testdb.Step{Kind: "query", Contains: "UNION SELECT rule FROM jyj_synced_whitelist", Columns: []string{"ip"}},
		testdb.Step{Kind: "query", Contains: "SELECT ip FROM jyj_ip_list", Columns: []string{"ip"}, Values: [][]driver.Value{{"192.0.2.5"}}},
	)
	dynamic := config.NewDynamicConfig(nil)
	if err := dynamic.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{dynCfg: dynamic, ipList: iplist.New(repository.NewIPListRepo(database), nil, dynamic), locator: behaviorTestLocator{}, audit: &auditWriter{access: make(chan *model.AccessLog, 2), attack: make(chan *model.AttackLog, 2)}}
	request := httptest.NewRequest(http.MethodGet, "https://nas.example/", nil)
	context := &reqctx.RequestContext{R: request, IP: "192.0.2.5", Header: request.Header, Method: request.Method, URI: request.RequestURI}
	if result := engine.Evaluate(request.Context(), context); result.Action != DecisionAllow {
		t.Fatalf("white-over-black failed: %+v", result)
	}
	if result := engine.Evaluate(request.Context(), context); result.Action != DecisionBlock || result.StatusCode != http.StatusForbidden {
		t.Fatalf("old block did not reactivate after whitelist removal: %+v", result)
	}
}
