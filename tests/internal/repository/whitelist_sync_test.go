package repository_test

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"jingshield/internal/repository"
	"jingshield/tests/testdb"
	"testing"
)

func TestWhitelistSnapshotVersionCannotRollbackOrConflict(t *testing.T) {
	digest := sha256.Sum256([]byte("192.0.2.0/24"))
	storedDigest := hex.EncodeToString(digest[:])
	for _, scenario := range []struct {
		name     string
		revision int64
		rules    []string
		want     error
		last     string
	}{
		{"stale", 41, []string{"192.0.2.0/24"}, repository.ErrStaleWhitelist, "rollback"},
		{"conflict", 42, []string{"198.51.100.0/24"}, repository.ErrWhitelistConflict, "rollback"},
		{"idempotent", 42, []string{"192.0.2.0/24"}, nil, "commit"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			steps := []testdb.Step{
				{Kind: "begin"},
				{Kind: "query", Contains: "FROM jyj_synced_whitelist_state WHERE source_id", Columns: []string{"revision", "digest"}, Values: [][]driver.Value{{int64(42), storedDigest}}},
				{Kind: scenario.last},
			}
			repo := repository.NewIPListRepo(testdb.Open(t, steps...))
			result, err := repo.SyncWhitelist(context.Background(), "nas_waf", scenario.revision, scenario.rules)
			if !errors.Is(err, scenario.want) {
				t.Fatalf("err=%v want=%v", err, scenario.want)
			}
			if scenario.want == nil && (result == nil || result.Digest != storedDigest) {
				t.Fatalf("idempotent acknowledgement=%+v", result)
			}
		})
	}
}
