package repository

import (
	"context"
	"strings"
	"testing"
)

func TestSchemaMigrationsAreNonDestructiveAndComplete(t *testing.T) {
	if len(schemaMigrations) != 13 {
		t.Fatalf("migration count = %d, want 12 tables plus defaults", len(schemaMigrations))
	}
	joined := ""
	for _, migration := range schemaMigrations {
		upper := strings.ToUpper(migration.sql)
		for _, forbidden := range []string{"DROP TABLE", "TRUNCATE", "DELETE FROM"} {
			if strings.Contains(upper, forbidden) {
				t.Fatalf("migration %s contains destructive statement %q", migration.name, forbidden)
			}
		}
		joined += "\n" + migration.sql
	}
	for _, table := range []string{
		"jyj_config", "jyj_ip_list", "jyj_attack_log", "jyj_access_log",
		"jyj_file_check", "jyj_users", "jyj_url_rules", "jyj_verify_fail", "jyj_login_log", "jyj_sites", "jyj_policy_rules", "jyj_device_events",
	} {
		if !strings.Contains(joined, "CREATE TABLE IF NOT EXISTS "+table) {
			t.Errorf("missing migration for %s", table)
		}
	}
	for _, key := range []string{"system_status", "cc_protection_status", "api_key", "alert_cpu_percent", "alert_request_rate"} {
		if !strings.Contains(joined, "'"+key+"'") {
			t.Errorf("missing default config %s", key)
		}
	}
}

func TestInitializeRejectsInvalidUsernameBeforeDatabaseAccess(t *testing.T) {
	if _, err := Initialize(context.Background(), nil, "a/b", ""); err == nil {
		t.Fatal("Initialize accepted an invalid username")
	}
}

func TestRandomPasswordCanBeVerified(t *testing.T) {
	password, err := randomPassword(20)
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != 20 {
		t.Fatalf("password length = %d", len(password))
	}
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(password, hash) {
		t.Fatal("generated password does not match its bcrypt hash")
	}
	if VerifyPassword(password+"x", hash) {
		t.Fatal("incorrect password matched bcrypt hash")
	}
}
