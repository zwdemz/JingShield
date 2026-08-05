package iputil

import (
	"net/http/httptest"
	"testing"
)

func TestGetClientIPIgnoresHeadersFromUntrustedPeer(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.test/", nil)
	r.RemoteAddr = "203.0.113.10:4321"
	r.Header.Set("X-Forwarded-For", "198.51.100.20")

	if got := GetClientIP(r, nil); got != "203.0.113.10" {
		t.Fatalf("GetClientIP() = %q, want direct peer", got)
	}
}

func TestGetClientIPWalksTrustedProxyChainFromRight(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.test/", nil)
	r.RemoteAddr = "10.0.0.3:4321"
	r.Header.Set("X-Forwarded-For", "198.51.100.20, 10.0.0.2")

	if got := GetClientIP(r, []string{"10.0.0.0/8"}); got != "198.51.100.20" {
		t.Fatalf("GetClientIP() = %q, want original client", got)
	}
}

func TestMatchIPRule(t *testing.T) {
	tests := []struct {
		ip, rule string
		want     bool
	}{
		{"192.168.1.8", "192.168.1.8", true},
		{"192.168.1.8", "192.168.1.0/24", true},
		{"10.2.3.4", "10.*.*.*", true},
		{"10.2.3.4", "10.2.*.5", false},
		{"2001:db8::2", "2001:db8::/32", true},
		{"not-an-ip", "*.*.*.*", false},
	}
	for _, test := range tests {
		if got := MatchIPRule(test.ip, test.rule); got != test.want {
			t.Errorf("MatchIPRule(%q, %q) = %v, want %v", test.ip, test.rule, got, test.want)
		}
	}
}
