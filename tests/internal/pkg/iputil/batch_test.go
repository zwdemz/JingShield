package iputil_test

import (
	"jingshield/internal/pkg/iputil"
	"testing"
)

func TestBatchNormalizesIPv6MappedIPv4AndDuplicates(t *testing.T) {
	result, err := iputil.NormalizeBlockIPs([]string{" 203.0.113.7 ", "::ffff:203.0.113.7", "2001:0db8:0:0:0:0:0:1", "2001:db8::1"})
	if err != nil || len(result) != 2 || result[1] != "2001:db8::1" {
		t.Fatalf("result=%v err=%v", result, err)
	}
}

func TestBatchLimitBeforeDedupeAndInvalidInputs(t *testing.T) {
	ips := make([]string, 500)
	for i := range ips {
		ips[i] = "203.0.113.7"
	}
	if _, err := iputil.NormalizeBlockIPs(ips); err != nil {
		t.Fatal(err)
	}
	for _, values := range [][]string{append(ips, "203.0.113.7"), nil, {"203.0.113.0/24"}, {"127.0.0.1"}, {"::"}, {"ff02::1"}, {"fe80::1%eth0"}, {"not-an-ip"}, {""}} {
		if _, err := iputil.NormalizeBlockIPs(values); err == nil {
			t.Errorf("accepted invalid batch of %d items", len(values))
		}
	}
	if iputil.ValidBlockReason("\nforged") || iputil.ValidBlockReason(" ") {
		t.Fatal("invalid reason accepted")
	}
}
