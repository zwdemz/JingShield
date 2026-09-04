package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"jingshield/internal/config"
	"jingshield/internal/model"
	"jingshield/internal/protection"
	"jingshield/internal/protection/reqctx"
)

func testDynamicConfig(t *testing.T) *config.DynamicConfig {
	t.Helper()
	dynamic := config.NewDynamicConfig(nil)
	if err := dynamic.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return dynamic
}

func TestBlockedPageShowsTraceableGenericEventWithoutRuleDetails(t *testing.T) {
	p := &Proxy{dynCfg: testDynamicConfig(t)}
	r := httptest.NewRequest(http.MethodGet, "https://app.example.test/search?q=blocked", nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.Header.Set("Sec-Fetch-Dest", "document")
	w := httptest.NewRecorder()
	rc := &reqctx.RequestContext{EventID: "JS-20260806T120000-A1B2C3D4E5F6"}
	decision := protection.Decision{
		StatusCode:   http.StatusForbidden,
		ErrorCode:    -403,
		ErrorMessage: "命中私密规则 SECRET-RULE-42",
		AttackType:   model.AttackTypePolicy,
		AttackDetail: "regex=(?i)secret-payload",
	}

	p.writeBlocked(w, r, rc, decision)
	body := w.Body.String()
	for _, expected := range []string{"捷云鲸盾", rc.EventID, "请求安全风险", "网站安全管理员"} {
		if !strings.Contains(body, expected) {
			t.Errorf("blocked page does not contain %q", expected)
		}
	}
	for _, secret := range []string{"SECRET-RULE-42", "secret-payload", decision.ErrorMessage, decision.AttackDetail} {
		if strings.Contains(body, secret) {
			t.Errorf("blocked page leaked %q", secret)
		}
	}
	if got := w.Header().Get("X-JingShield-Event-ID"); got != rc.EventID {
		t.Fatalf("event header = %q, want %q", got, rc.EventID)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("blocked page is missing restrictive CSP")
	}
}

func TestBlockedAPIResponseRemainsJSONAndDoesNotLeakRuleDetails(t *testing.T) {
	p := &Proxy{dynCfg: testDynamicConfig(t)}
	r := httptest.NewRequest(http.MethodPost, "https://app.example.test/api/orders", nil)
	r.Header.Set("Accept", "text/html,application/json")
	w := httptest.NewRecorder()
	rc := &reqctx.RequestContext{EventID: "JS-20260806T120001-112233445566"}
	decision := protection.Decision{
		StatusCode:   http.StatusForbidden,
		ErrorCode:    -403,
		ErrorMessage: "命中私密规则 SECRET-RULE-42",
		AttackType:   model.AttackTypeSQL,
		AttackDetail: "UNION SELECT secret_payload",
	}

	p.writeBlocked(w, r, rc, decision)
	body := w.Body.String()
	if contentType := w.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Fatalf("content type = %q", contentType)
	}
	if !strings.Contains(body, rc.EventID) || strings.Contains(body, "SECRET-RULE-42") || strings.Contains(body, "secret_payload") {
		t.Fatalf("unexpected JSON block body: %s", body)
	}
	if strings.Contains(body, "<!doctype html>") {
		t.Fatal("API block response unexpectedly rendered HTML")
	}
}

func TestPublicRiskTypeIsStableAndGeneric(t *testing.T) {
	tests := map[string]string{
		model.AttackTypeSQL:          "注入攻击风险",
		model.AttackTypeXSS:          "脚本注入风险",
		model.AttackTypeCC:           "访问频率异常",
		model.AttackTypeBlacklist:    "访问策略限制",
		model.AttackTypeShieldBypass: "异常客户端行为",
		"private-rule-name":          "请求安全风险",
	}
	for input, want := range tests {
		if got := publicRiskType(input); got != want {
			t.Errorf("publicRiskType(%q) = %q, want %q", input, got, want)
		}
	}
}
