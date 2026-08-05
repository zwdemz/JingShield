package model

import "testing"

func TestAttackSeverityForCoversFiveLevels(t *testing.T) {
	tests := []struct {
		attackType string
		status     int
		want       int
	}{
		{AttackTypeSQL, 1, AttackSeverityCritical},
		{AttackTypeXSS, 1, AttackSeverityHigh},
		{AttackTypeCC, 1, AttackSeverityMedium},
		{AttackTypeVerifyFail, 1, AttackSeverityLow},
		{AttackTypePolicy, 2, AttackSeverityInfo},
	}
	for _, test := range tests {
		if got := AttackSeverityFor(test.attackType, test.status); got != test.want {
			t.Errorf("AttackSeverityFor(%q, %d) = %d, want %d", test.attackType, test.status, got, test.want)
		}
		if AttackSeverityLabel(test.want) == "" {
			t.Errorf("severity %d has no label", test.want)
		}
	}
}
