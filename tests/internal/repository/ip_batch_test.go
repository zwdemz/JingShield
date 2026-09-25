package repository_test

import (
	"context"
	"database/sql/driver"
	"errors"
	"jingshield/internal/repository"
	"jingshield/tests/testdb"
	"testing"
	"time"
)

func TestBatchWhitelistAndAuditAreAtomic(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[rollback], func(t *testing.T) {
			steps := []testdb.Step{
				{Kind: "begin"},
				{Kind: "query", Contains: "WHERE type = ? FOR UPDATE", Columns: []string{"ip"}, Values: [][]driver.Value{{"198.51.100.0/24"}}},
				{Kind: "query", Contains: "SELECT rule FROM jyj_synced_whitelist", Columns: []string{"rule"}},
				{Kind: "query", Contains: "SELECT type, expire_time", Columns: []string{"type", "expire_time"}, Values: [][]driver.Value{{int64(2), time.Now().Add(-time.Hour)}}},
				{Kind: "exec", Contains: "DELETE FROM jyj_ip_list"},
				{Kind: "exec", Contains: "INSERT INTO jyj_ip_list", Check: func(args []driver.NamedValue) error {
					if args[1].Value != int64(2) || args[3].Value != nil {
						return errors.New("permanent ban was shortened")
					}
					return nil
				}},
				{Kind: "exec", Contains: "INSERT INTO jyj_ip_action_log"},
				{Kind: "commit"},
			}
			if rollback {
				steps[6].Error = errors.New("audit storage unavailable")
				steps[7].Kind = "rollback"
			}
			repo := repository.NewIPListRepo(testdb.Open(t, steps...))
			result, err := repo.BlockBatch(context.Background(), []string{"198.51.100.8", "203.0.113.8", "203.0.113.8"}, "mock incident", 60, "admin:test")
			if rollback {
				if err == nil || result != nil {
					t.Fatal("partial batch result leaked after audit failure")
				}
				return
			}
			if err != nil || result.Requested != 3 || result.Unique != 2 || result.Blocked != 1 || result.SkippedWhitelist != 1 || result.SkippedIPs[0] != "198.51.100.8" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func TestInvalidBatchNeverTouchesDatabase(t *testing.T) {
	repo := repository.NewIPListRepo(testdb.Open(t))
	if _, err := repo.BlockBatch(context.Background(), []string{"192.0.2.0/24"}, "mock", 60, "test"); err == nil {
		t.Fatal("CIDR batch accepted")
	}
}
