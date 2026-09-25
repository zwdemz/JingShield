package firewallbridge

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNFTWhitelistCleanupOnlyTouchesMatchingManagedMember(t *testing.T) {
	before := []any{"192.0.2.5", "203.0.113.5"}
	steps := nftReadSteps(before, nil)
	steps = append(steps,
		commandStep{executable: "/usr/sbin/nft", args: "-c -f -", inputContains: "delete element inet jingshield jingshield_blocked_v4 { 192.0.2.5 }"},
		commandStep{executable: "/usr/sbin/nft", args: "-f -", inputContains: "delete element inet jingshield jingshield_blocked_v4 { 192.0.2.5 }"},
	)
	steps = append(steps, nftReadSteps([]any{"203.0.113.5"}, nil)...)
	runner := runnerFor(t, steps...)
	removed, err := NewNFTDriver(runner).ClearMatching(context.Background(), []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
	if err != nil || removed != 1 || strings.Contains(runner.inputs[3], "203.0.113.5") {
		t.Fatalf("removed=%d err=%v input=%q", removed, err, runner.inputs[3])
	}
}

func TestIPSetWhitelistCleanupRequiresReadback(t *testing.T) {
	before := "add jingshield_blocked_v4 192.0.2.5 timeout 0\nadd jingshield_blocked_v4 203.0.113.5 timeout 0\n"
	steps := ipsetReadSteps(before, "")
	steps = append(steps, commandStep{executable: "/usr/sbin/ipset", args: "-exist restore", inputContains: "del jingshield_blocked_v4 192.0.2.5"})
	steps = append(steps, ipsetReadSteps(before, "")...)
	runner := runnerFor(t, steps...)
	removed, err := NewIPSetDriver(runner).ClearMatching(context.Background(), []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
	if err == nil || removed != 0 || strings.Contains(runner.inputs[2], "203.0.113.5") {
		t.Fatalf("unconfirmed clear treated as success: removed=%d err=%v", removed, err)
	}
}

func TestWhitelistStateDurableAndCorruptionSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.json")
	state := whitelistFile{Sources: map[string]whitelistSnapshot{"nas_waf": {Revision: 42, Rules: []string{"192.0.2.0/24"}, Digest: whitelistDigest([]string{"192.0.2.0/24"})}}}
	if err := writeWhitelistState(path, state); err != nil {
		t.Fatal(err)
	}
	restored, err := readWhitelistState(path)
	if err != nil || restored.Sources["nas_waf"].Revision != 42 {
		t.Fatalf("restored=%+v err=%v", restored, err)
	}
	if err := os.WriteFile(path, []byte(`{"sources":{"nas_waf":{"revision":42,"rules":["0.0.0.0/0"],"digest":"invalid"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readWhitelistState(path); err == nil {
		t.Fatal("corrupt state accepted")
	}
}

func TestWhitelistReceiverDryRunCannotClaimEnforcement(t *testing.T) {
	server, events := testServer(t)
	server.config.WhitelistStateFile = filepath.Join(t.TempDir(), "whitelist.json")
	capability := bridgeRequest(server, "GET", "/openapi/v1/capabilities", "")
	if !strings.Contains(capability.Body.String(), "preview-whitelist-sync") || strings.Contains(capability.Body.String(), `"whitelist-sync"`) {
		t.Fatal(capability.Body.String())
	}
	path := "/openapi/v1/ip/whitelist/sync"
	first := bridgeRequest(server, "POST", path, `{"source":"nas_waf","revision":42,"rules":["198.51.100.*"]}`)
	if first.Code != 200 || !strings.Contains(first.Body.String(), `"dry_run":true`) {
		t.Fatal(first.Body.String())
	}
	if _, err := os.Stat(server.config.WhitelistStateFile); !os.IsNotExist(err) {
		t.Fatal("dry-run persisted state")
	}
	stale := bridgeRequest(server, "POST", path, `{"source":"nas_waf","revision":41,"rules":[]}`)
	if stale.Code != 409 {
		t.Fatal(stale.Body.String())
	}
	invalid := bridgeRequest(server, "POST", path, `{"source":"nas_waf","revision":43,"rules":["*.*.*.*"]}`)
	if invalid.Code != 400 {
		t.Fatal(invalid.Body.String())
	}
	empty := bridgeRequest(server, "POST", path, `{"source":"nas_waf","revision":43,"rules":[]}`)
	if empty.Code != 200 || len(server.whitelist.Sources["nas_waf"].Rules) != 0 {
		t.Fatal(empty.Body.String())
	}
	if len(*events) != 4 {
		t.Fatalf("expected intent/outcome pairs only: %+v", *events)
	}
}

func TestMatchingManagedIPsOnly(t *testing.T) {
	current := snapshot{netip.MustParseAddr("192.0.2.3"): {}, netip.MustParseAddr("203.0.113.3"): {}}
	matched, err := matchingManagedIPs(current, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
	if err != nil || len(matched) != 1 || matched[0].String() != "192.0.2.3" {
		t.Fatalf("matched=%v err=%v", matched, err)
	}
}
