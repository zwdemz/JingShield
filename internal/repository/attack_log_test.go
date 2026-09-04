package repository

import (
	"strings"
	"testing"
	"time"
)

func TestBuildAttackLogWhereIncludesLargeDatasetFilters(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	where, args := buildAttackLogWhere(AttackLogFilter{
		EventID: "JS-20260806T120000-A1B2C3D4E5F6", AttackType: "SQL注入", IP: "203.0.113.8", Severity: 5, StartAt: &start, EndAt: &end,
	})
	for _, clause := range []string{"jyj_attack_event_ref", "attack_type = ?", "ip = ?", "severity = ?", "created_at >= ?", "created_at < ?"} {
		if !strings.Contains(where, clause) {
			t.Errorf("where clause %q missing from %q", clause, where)
		}
	}
	if len(args) != 6 {
		t.Fatalf("argument count = %d, want 6", len(args))
	}
}
