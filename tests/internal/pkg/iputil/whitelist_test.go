package iputil_test

import (
	"jingshield/internal/pkg/iputil"
	"strings"
	"testing"
)

func TestNormalizeWhitelistRules(t *testing.T) {
	rules, err := iputil.NormalizeWhitelistRules([]string{"198.51.100.*", "198.51.100.0/24", "2001:0DB8::1", "2001:db8::1", "192.0.2.1"})
	if err != nil || len(rules) != 3 || rules[0] != "192.0.2.1" || rules[1] != "198.51.100.0/24" || rules[2] != "2001:db8::1" {
		t.Fatalf("rules=%v err=%v", rules, err)
	}
	for _, input := range [][]string{{"*.*.*.*"}, {"192.*.2.*"}, {"192.0.2.0/0"}, {"192.0.2.1\n"}, {"2001:db8::1%eth0"}, {""}, {"192.0.2.1 "}} {
		if _, err := iputil.NormalizeWhitelistRules(input); err == nil {
			t.Fatalf("accepted unsafe rule %q", input)
		}
	}
	if rules, err := iputil.NormalizeWhitelistRules(nil); err != nil || len(rules) != 0 {
		t.Fatalf("empty replacement failed: %v %v", rules, err)
	}
	if _, err := iputil.NormalizeWhitelistRules(make([]string, 501)); err == nil {
		t.Fatal("501 submitted rules accepted")
	}
	if _, err := iputil.NormalizeWhitelistRules([]string{strings.Repeat("1", 65)}); err == nil {
		t.Fatal("oversized rule accepted")
	}
}
