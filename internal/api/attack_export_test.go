package api

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestSafeSpreadsheetCellPreventsFormulaExecution(t *testing.T) {
	for _, value := range []string{"=cmd()", "+1+1", " -2+3", "@SUM(A1:A2)"} {
		if got := safeSpreadsheetCell(value); got == value || got[0] != '\'' {
			t.Errorf("unsafe CSV cell was not escaped: %q -> %q", value, got)
		}
	}
	if got := safeSpreadsheetCell("/safe/path"); got != "/safe/path" {
		t.Fatalf("safe cell changed: %q", got)
	}
}

func TestAttackFilterParsesAllFields(t *testing.T) {
	request := httptest.NewRequest("GET", "/api/v1/attacks?event_id=JS-20260806T120000-A1B2C3D4E5F6&attack_type=SQL%E6%B3%A8%E5%85%A5&ip=203.0.113.8&severity=5&start_at=2026-08-01T00:00:00Z&end_at=2026-08-02T00:00:00Z", nil)
	filter, err := attackFilter(request)
	if err != nil {
		t.Fatalf("attackFilter returned error: %v", err)
	}
	if filter.EventID != "JS-20260806T120000-A1B2C3D4E5F6" || filter.AttackType != "SQL注入" || filter.IP != "203.0.113.8" || filter.Severity != 5 {
		t.Fatalf("unexpected filter: %+v", filter)
	}
	if filter.StartAt == nil || filter.EndAt == nil || filter.EndAt.Sub(*filter.StartAt) != 24*time.Hour {
		t.Fatalf("unexpected time range: %+v", filter)
	}
}

func TestAttackFilterRejectsInvalidRanges(t *testing.T) {
	for _, target := range []string{
		"/api/v1/attacks?severity=6",
		"/api/v1/attacks?event_id=not%20an%20event",
		"/api/v1/attacks?start_at=not-a-time",
		"/api/v1/attacks?start_at=2026-08-02T00:00:00Z&end_at=2026-08-01T00:00:00Z",
	} {
		if _, err := attackFilter(httptest.NewRequest("GET", target, nil)); err == nil {
			t.Errorf("attackFilter(%q) accepted invalid input", target)
		}
	}
}
