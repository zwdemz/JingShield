package reqctx

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSanitizedRequestPacketRedactsCredentialsAndKeepsAttackEvidence(t *testing.T) {
	body := `{"username":"alice","password":"do-not-store","nested":{"access_token":"token-value"},"query":"1 UNION SELECT password FROM users"}`
	request := httptest.NewRequest("POST", "https://waf.example/login?token=query-secret&next=%2F", strings.NewReader(body))
	request.Host = "waf.example"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer header-secret")
	request.Header.Set("Cookie", "session=cookie-secret")
	request.Header.Set("X-Request-ID", "request-123")
	rc, err := NewRequestContext(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	packet := rc.SanitizedRequestPacket()
	for _, secret := range []string{"do-not-store", "token-value", "query-secret", "header-secret", "cookie-secret"} {
		if strings.Contains(packet, secret) {
			t.Errorf("packet leaked %q:\n%s", secret, packet)
		}
	}
	for _, evidence := range []string{"POST /login?", "Host: waf.example", "Authorization: [REDACTED]", "X-Request-Id: request-123", "UNION SELECT"} {
		if !strings.Contains(packet, evidence) {
			t.Errorf("packet missing %q:\n%s", evidence, packet)
		}
	}
}

func TestSanitizedRequestPacketIsBounded(t *testing.T) {
	request := httptest.NewRequest("POST", "http://example.test/upload", strings.NewReader(strings.Repeat("a", maxStoredRequestPacket*2)))
	request.Header.Set("Content-Type", "text/plain")
	rc, err := NewRequestContext(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	packet := rc.SanitizedRequestPacket()
	if len(packet) > maxStoredRequestPacket+len("\n...[TRUNCATED]") || !strings.Contains(packet, "[TRUNCATED]") {
		t.Fatalf("unexpected bounded packet length=%d", len(packet))
	}
}

func TestSanitizedRequestPacketRedactsMalformedBody(t *testing.T) {
	request := httptest.NewRequest("POST", "http://example.test/login", strings.NewReader(`{"password":"malformed-secret`))
	request.Header.Set("Content-Type", "application/json")
	rc, err := NewRequestContext(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	packet := rc.SanitizedRequestPacket()
	if strings.Contains(packet, "malformed-secret") || !strings.Contains(packet, redactedValue) {
		t.Fatalf("malformed body was not redacted:\n%s", packet)
	}
}
