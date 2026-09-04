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
