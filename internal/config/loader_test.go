package config

import "testing"

func TestTLSListenerRequiresCertificatePair(t *testing.T) {
	cfg := Config{Server: ServerConfig{Listen: "127.0.0.1:18080", TLSListen: "127.0.0.1:18443"}, Upstream: UpstreamConfig{Target: "http://127.0.0.1:9000"}}
	if err := cfg.validate(); err == nil {
		t.Fatal("TLS listener without certificate pair was accepted")
	}
	cfg.Server.TLSCertFile = "server.crt"
	cfg.Server.TLSKeyFile = "server.key"
	if err := cfg.validate(); err != nil {
		t.Fatalf("valid TLS listener rejected: %v", err)
	}
}

func TestTLSListenerCannotReuseHTTPAddress(t *testing.T) {
	cfg := Config{
		Server:   ServerConfig{Listen: "127.0.0.1:18080", TLSListen: "127.0.0.1:18080", TLSCertFile: "server.crt", TLSKeyFile: "server.key"},
		Upstream: UpstreamConfig{Target: "http://127.0.0.1:9000"},
	}
	if err := cfg.validate(); err == nil {
		t.Fatal("duplicate HTTP/TLS listen address was accepted")
	}
}

func TestProductionRequiresStableSessionSecret(t *testing.T) {
	cfg := Config{Environment: "prod", Upstream: UpstreamConfig{Target: "http://127.0.0.1:9000"}}
	if err := cfg.validate(); err == nil {
		t.Fatal("production accepted a missing session secret")
	}
	cfg.Session.Secret = "a-stable-random-secret-from-the-deployment-environment"
	cfg.Session.Secure = true
	if err := cfg.validate(); err != nil {
		t.Fatalf("production rejected a configured secret: %v", err)
	}
}

func TestMethodPolicyRequiresExplicitScope(t *testing.T) {
	cfg := Config{Upstream: UpstreamConfig{Target: "http://127.0.0.1:9000"}}
	cfg.Server.MethodPolicies = []MethodPolicy{{Host: "api.example.test", PathPrefix: "/v1", AllowedMethods: []string{"get", "options"}}}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.MethodPolicies[0].AllowedMethods[1] != "OPTIONS" {
		t.Fatal("method names were not normalized")
	}
	cfg.Server.MethodPolicies[0].PathPrefix = "v1"
	if err := cfg.validate(); err == nil {
		t.Fatal("relative method policy path was accepted")
	}
}
