package config

import "testing"

func TestValidateRejectsEmptyDatabasePassword(t *testing.T) {
	cfg := Config{
		Upstream: UpstreamConfig{Target: "http://127.0.0.1:9000"},
		Database: DatabaseConfig{User: "jingshield"},
	}
	if err := cfg.validate(); err == nil {
		t.Fatal("empty database password was accepted")
	}
}
