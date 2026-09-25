package repository_test

import (
	"context"
	"database/sql/driver"
	"jingshield/internal/repository"
	"jingshield/tests/testdb"
	"testing"
)

func TestOperationalMigrationRunsAfterCoreConfigTable(t *testing.T) {
	steps := []testdb.Step{{Kind: "exec", Contains: "CREATE TABLE IF NOT EXISTS jyj_ip_action_log"}}
	for _, table := range []string{"jyj_policy_rules", "jyj_device_events", "jyj_sites", "jyj_config", "jyj_ip_list", "jyj_attack_log", "jyj_attack_event_ref", "jyj_access_log", "jyj_file_check", "jyj_users", "jyj_url_rules", "jyj_verify_fail", "jyj_login_log"} {
		steps = append(steps, testdb.Step{Kind: "exec", Contains: "CREATE TABLE IF NOT EXISTS " + table})
	}
	steps = append(steps, testdb.Step{Kind: "exec", Contains: "INSERT INTO jyj_config"}, testdb.Step{Kind: "exec", Contains: "CREATE TABLE IF NOT EXISTS jyj_syslog_outbox"}, testdb.Step{Kind: "exec", Contains: "operations_outbox_lock"})
	steps = append(steps, testdb.Step{Kind: "exec", Contains: "CREATE TABLE IF NOT EXISTS jyj_synced_whitelist_state"}, testdb.Step{Kind: "exec", Contains: "CREATE TABLE IF NOT EXISTS jyj_synced_whitelist"})
	for index := 0; index < 10; index++ {
		steps = append(steps, testdb.Step{Kind: "query", Contains: "information_schema.COLUMNS", Columns: []string{"count"}, Values: [][]driver.Value{{int64(1)}}})
	}
	for index := 0; index < 4; index++ {
		steps = append(steps, testdb.Step{Kind: "query", Contains: "information_schema.STATISTICS", Columns: []string{"count"}, Values: [][]driver.Value{{int64(1)}}})
	}
	if err := repository.Migrate(context.Background(), testdb.Open(t, steps...)); err != nil {
		t.Fatal(err)
	}
}
