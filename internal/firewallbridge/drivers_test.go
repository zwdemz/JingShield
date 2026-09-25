package firewallbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type commandStep struct {
	executable    string
	args          string
	inputContains string
	output        string
	failure       error
}
type mockRunner struct {
	testing *testing.T
	steps   []commandStep
	index   int
	inputs  []string
}

func (r *mockRunner) Run(_ context.Context, executable string, args []string, input []byte) ([]byte, error) {
	r.testing.Helper()
	if r.index >= len(r.steps) {
		r.testing.Fatalf("unexpected command %s %v", executable, args)
	}
	step := r.steps[r.index]
	r.index++
	if executable != step.executable || strings.Join(args, " ") != step.args || !strings.Contains(string(input), step.inputContains) {
		r.testing.Fatalf("unexpected command %s %v %q, expected %#v", executable, args, input, step)
	}
	r.inputs = append(r.inputs, string(input))
	return []byte(step.output), step.failure
}
func runnerFor(t *testing.T, steps ...commandStep) *mockRunner {
	t.Helper()
	runner := &mockRunner{testing: t, steps: steps}
	t.Cleanup(func() {
		if runner.index != len(runner.steps) {
			t.Errorf("used %d/%d commands", runner.index, len(runner.steps))
		}
	})
	return runner
}
func nftJSON(name string, elements any) string {
	kind := "ipv4_addr"
	if name == ManagedIPv6Set {
		kind = "ipv6_addr"
	}
	raw, _ := json.Marshal(map[string]any{"nftables": []any{map[string]any{"set": map[string]any{"family": "inet", "table": ManagedTable, "name": name, "type": kind, "flags": []string{"timeout"}, "comment": ManagedMarker, "elem": elements}}}})
	return string(raw)
}
func nftReadSteps(v4, v6 any) []commandStep {
	return []commandStep{{executable: "/usr/sbin/nft", args: "-j list set inet jingshield " + ManagedIPv4Set, output: nftJSON(ManagedIPv4Set, v4)}, {executable: "/usr/sbin/nft", args: "-j list set inet jingshield " + ManagedIPv6Set, output: nftJSON(ManagedIPv6Set, v6)}}
}
func timed(ip string, seconds int) any {
	return map[string]any{"elem": map[string]any{"val": ip, "timeout": seconds, "expires": seconds}}
}
func ipsetReadSteps(v4, v6 string) []commandStep {
	return []commandStep{{executable: "/usr/sbin/ipset", args: "save " + ManagedIPv4Set, output: "create " + ManagedIPv4Set + " hash:ip family inet hashsize 1024 maxelem 20000 timeout 0\n" + v4}, {executable: "/usr/sbin/ipset", args: "save " + ManagedIPv6Set, output: "create " + ManagedIPv6Set + " hash:ip family inet6 hashsize 1024 maxelem 20000 timeout 0\n" + v6}}
}
func address(value string) netip.Addr { return netip.MustParseAddr(value) }

func TestNFTJSONElementUnitsAreSeconds(t *testing.T) {
	// nftables 1.1.3 src/json.c: set_elem_expr_json divides both internal
	// timeout and expiration by 1000 before writing JSON (official archive).
	fixture := `{"nftables":[{"metainfo":{"version":"1.1.3","json_schema_version":1}},{"set":{"family":"inet","table":"jingshield","name":"jingshield_blocked_v4","type":"ipv4_addr","flags":"timeout","comment":"jingshield-managed-v1","elem":[{"elem":{"val":"192.0.2.1","timeout":300,"expires":299}},"192.0.2.2"]}}]}`
	now := time.Unix(1000, 0)
	entries, err := parseNFTSet([]byte(fixture), ManagedIPv4Set, now)
	if err != nil {
		t.Fatal(err)
	}
	if entries[address("192.0.2.1")].Sub(now) != 300*time.Second || !entries[address("192.0.2.2")].IsZero() {
		t.Fatalf("JSON timeout unit/permanence mismatch: %#v", entries)
	}
}

func TestNFTApplyPreservesStrongerBlocksAndVerifiesIPv6(t *testing.T) {
	now := time.Unix(1000, 0)
	existing := []any{"192.0.2.1", timed("192.0.2.2", 600)}
	steps := nftReadSteps(existing, nil)
	steps = append(steps, commandStep{executable: "/usr/sbin/nft", args: "-c -f -", inputContains: "2001:db8::1 timeout 60s"}, commandStep{executable: "/usr/sbin/nft", args: "-f -", inputContains: "2001:db8::1 timeout 60s"})
	steps = append(steps, nftReadSteps(existing, []any{timed("2001:db8::1", 60)})...)
	runner := runnerFor(t, steps...)
	driver := NewNFTDriver(runner)
	driver.now = func() time.Time { return now }
	result, err := driver.Apply(context.Background(), []Block{{IP: address("192.0.2.1"), ExpiresAt: now.Add(time.Minute)}, {IP: address("192.0.2.2"), ExpiresAt: now.Add(time.Minute)}, {IP: address("2001:db8::1"), ExpiresAt: now.Add(time.Minute)}})
	if err != nil || result.Applied != 3 || result.Partial {
		t.Fatalf("bad result %#v %v", result, err)
	}
	for _, input := range runner.inputs {
		if strings.Contains(input, "192.0.2.") || strings.Contains(input, "flush") || strings.Contains(input, "delete table") {
			t.Fatalf("unrelated/stronger state touched: %s", input)
		}
	}
}

func TestNFTExtensionIsOneScopedTransaction(t *testing.T) {
	now := time.Unix(1000, 0)
	steps := nftReadSteps([]any{timed("192.0.2.1", 30)}, nil)
	steps = append(steps, commandStep{executable: "/usr/sbin/nft", args: "-c -f -", inputContains: "delete element inet jingshield jingshield_blocked_v4 { 192.0.2.1 }"}, commandStep{executable: "/usr/sbin/nft", args: "-f -", inputContains: "timeout 300s"})
	steps = append(steps, nftReadSteps([]any{timed("192.0.2.1", 300)}, nil)...)
	runner := runnerFor(t, steps...)
	driver := NewNFTDriver(runner)
	driver.now = func() time.Time { return now }
	if _, err := driver.Apply(context.Background(), []Block{{IP: address("192.0.2.1"), ExpiresAt: now.Add(300 * time.Second)}}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(runner.inputs[3], "\n") != 3 {
		t.Fatalf("non-atomic renewal script: %q", runner.inputs[3])
	}
}

func TestNFTCheckFailureDoesNotApply(t *testing.T) {
	steps := nftReadSteps(nil, nil)
	steps = append(steps, commandStep{executable: "/usr/sbin/nft", args: "-c -f -", failure: errors.New("unsupported set")})
	driver := NewNFTDriver(runnerFor(t, steps...))
	result, err := driver.Apply(context.Background(), []Block{{IP: address("192.0.2.1")}})
	if err == nil || result.Partial || result.Applied != 0 {
		t.Fatalf("bad failure outcome %#v %v", result, err)
	}
}

func TestNFTReadbackMismatchIsNotSuccess(t *testing.T) {
	steps := nftReadSteps(nil, nil)
	steps = append(steps, commandStep{executable: "/usr/sbin/nft", args: "-c -f -"}, commandStep{executable: "/usr/sbin/nft", args: "-f -"})
	steps = append(steps, nftReadSteps(nil, nil)...)
	driver := NewNFTDriver(runnerFor(t, steps...))
	result, err := driver.Apply(context.Background(), []Block{{IP: address("192.0.2.1")}})
	if err == nil || !result.Partial || result.Applied != 0 {
		t.Fatal("exec exit status was treated as enforcement")
	}
}

func TestIPSetZeroPermanentAndNearExpiryOne(t *testing.T) {
	now := time.Unix(1000, 0)
	raw := "create jingshield_blocked_v4 hash:ip family inet timeout 0\nadd jingshield_blocked_v4 192.0.2.1 timeout 0\nadd jingshield_blocked_v4 192.0.2.2 timeout 1\n"
	entries, err := parseIPSet([]byte(raw), ManagedIPv4Set, now)
	if err != nil {
		t.Fatal(err)
	}
	if !entries[address("192.0.2.1")].IsZero() || entries[address("192.0.2.2")].Sub(now) != 2*time.Second {
		t.Fatal("ipset permanent/near-expiry confusion")
	}
}

func TestIPSetAppliesBothFamiliesAndReadsBack(t *testing.T) {
	now := time.Unix(1000, 0)
	existing := "add jingshield_blocked_v4 192.0.2.1 timeout 0\n"
	steps := ipsetReadSteps(existing, "")
	steps = append(steps, commandStep{executable: "/usr/sbin/ipset", args: "-exist restore", inputContains: "add jingshield_blocked_v6 2001:db8::1 timeout 60"})
	steps = append(steps, ipsetReadSteps(existing, "add jingshield_blocked_v6 2001:db8::1 timeout 60\n")...)
	runner := runnerFor(t, steps...)
	driver := NewIPSetDriver(runner)
	driver.now = func() time.Time { return now }
	result, err := driver.Apply(context.Background(), []Block{{IP: address("192.0.2.1"), ExpiresAt: now.Add(time.Minute)}, {IP: address("2001:db8::1"), ExpiresAt: now.Add(time.Minute)}})
	if err != nil || result.Applied != 2 || strings.Contains(runner.inputs[2], "192.0.2.1") {
		t.Fatalf("bad apply %#v %v", result, err)
	}
}

func TestIPSetPartialFailureRollsBackTouchedEntries(t *testing.T) {
	for _, rollbackFails := range []bool{false, true} {
		t.Run(fmt.Sprint(rollbackFails), func(t *testing.T) {
			steps := ipsetReadSteps("", "")
			steps = append(steps, commandStep{executable: "/usr/sbin/ipset", args: "-exist restore", failure: errors.New("prefix applied")})
			steps = append(steps, ipsetReadSteps("add jingshield_blocked_v4 192.0.2.1 timeout 0\n", "")...)
			rollback := commandStep{executable: "/usr/sbin/ipset", args: "-exist restore", inputContains: "del jingshield_blocked_v4 192.0.2.1"}
			if rollbackFails {
				rollback.failure = errors.New("kernel unavailable")
			}
			steps = append(steps, rollback)
			v4 := ""
			if rollbackFails {
				v4 = "add jingshield_blocked_v4 192.0.2.1 timeout 0\n"
			}
			steps = append(steps, ipsetReadSteps(v4, "")...)
			driver := NewIPSetDriver(runnerFor(t, steps...))
			result, err := driver.Apply(context.Background(), []Block{{IP: address("192.0.2.1")}, {IP: address("2001:db8::1")}})
			if err == nil || result.Partial != rollbackFails {
				t.Fatalf("rollback mismatch %#v %v", result, err)
			}
		})
	}
}

func TestDriversRejectUnsafeInputsWithoutCommands(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, input := range [][]Block{{{IP: address("127.0.0.1")}}, {{IP: address("::ffff:192.0.2.1")}}, {{IP: address("192.0.2.1"), ExpiresAt: now.Add((MaxIPSetTTL + 1) * time.Second)}}, {{IP: address("192.0.2.1")}, {IP: address("192.0.2.1")}}} {
		driver := NewIPSetDriver(runnerFor(t))
		driver.now = func() time.Time { return now }
		if _, err := driver.Apply(context.Background(), input); err == nil {
			t.Fatalf("unsafe batch accepted %#v", input)
		}
	}
}

func TestSnapshotOwnershipAndUnexpectedSyntaxFailClosed(t *testing.T) {
	now := time.Now()
	valid := nftJSON(ManagedIPv4Set, []any{"192.0.2.1"})
	for _, value := range []string{"invalid", strings.Replace(valid, ManagedMarker, "foreign", 1), strings.Replace(valid, "ipv4_addr", "ipv6_addr", 1), strings.Replace(valid, "timeout", "interval", 1), nftJSON(ManagedIPv4Set, []any{map[string]any{"prefix": map[string]any{"addr": "192.0.2.1", "len": 24}}})} {
		if _, err := parseNFTSet([]byte(value), ManagedIPv4Set, now); err == nil {
			t.Fatalf("unsafe nft set accepted %s", value)
		}
	}
	for _, value := range []string{"", "create foreign hash:ip family inet timeout 0", "create jingshield_blocked_v4 hash:ip family inet timeout 0 forceadd", "create jingshield_blocked_v4 hash:net family inet timeout 0", "create jingshield_blocked_v4 hash:ip family inet timeout 0\nadd jingshield_blocked_v4 192.0.2.1;flush", "create jingshield_blocked_v4 hash:ip family inet timeout 60"} {
		if _, err := parseIPSet([]byte(value), ManagedIPv4Set, now); err == nil {
			t.Fatalf("unsafe ipset accepted %s", value)
		}
	}
	for _, option := range []string{"netmask 24", "bitmask 255.255.255.0"} {
		if _, err := parseIPSet([]byte("create jingshield_blocked_v4 hash:ip family inet timeout 0 "+option), ManagedIPv4Set, now); err == nil {
			t.Fatalf("address masking option accepted: %s", option)
		}
	}
}

func TestDryRunIdempotenceAndExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	driver := NewDryRunDriver()
	driver.now = func() time.Time { return now }
	ip := address("192.0.2.1")
	for _, deadline := range []time.Time{now.Add(time.Hour), now.Add(time.Minute), {}, now.Add(time.Minute)} {
		if _, err := driver.Apply(context.Background(), []Block{{IP: ip, ExpiresAt: deadline}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(driver.entries) != 1 || !driver.entries[ip].IsZero() {
		t.Fatal("permanent block shortened or duplicate created")
	}
	other := address("2001:db8::1")
	if _, err := driver.Apply(context.Background(), []Block{{IP: other, ExpiresAt: now.Add(time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := driver.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, found := driver.entries[other]; found {
		t.Fatal("temporary simulation did not expire")
	}
}
