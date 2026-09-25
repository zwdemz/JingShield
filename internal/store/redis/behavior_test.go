package redis

import (
	"context"
	"testing"
	"time"

	"jingshield/internal/store"

	"github.com/alicebob/miniredis/v2"
)

func TestBehaviorSharedWindowAndFixedPenalty(t *testing.T) {
	server := miniredis.RunT(t)
	now := time.Unix(1800000000, 0)
	server.SetTime(now)
	ctx := context.Background()
	first, err := New(ctx, "redis://"+server.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := New(ctx, "redis://"+server.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	policy := store.BehaviorPolicy{WindowSeconds: 30, Threshold: 2, BlockSeconds: 10}
	if snapshot, err := first.ObserveBehavior(ctx, "scope", "secrets", false, policy, true); err != nil || snapshot.Blocked {
		t.Fatalf("first probe: %+v %v", snapshot, err)
	}
	now = now.Add(30 * time.Second)
	server.SetTime(now)
	if snapshot, err := second.ObserveBehavior(ctx, "scope", "repository", false, policy, true); err != nil || snapshot.Hits != 1 || snapshot.Blocked {
		t.Fatalf("expired window: %+v %v", snapshot, err)
	}
	if snapshot, err := first.ObserveBehavior(ctx, "scope", "secrets", false, policy, true); err != nil || !snapshot.Blocked || snapshot.BlockRemainingSeconds != 10 {
		t.Fatalf("shared threshold: %+v %v", snapshot, err)
	}
	server.FastForward(9 * time.Second)
	if snapshot, err := second.ObserveBehavior(ctx, "scope", "", false, policy, true); err != nil || !snapshot.Blocked || snapshot.BlockRemainingSeconds != 1 {
		t.Fatalf("shared fixed penalty: %+v %v", snapshot, err)
	}
	if snapshot, err := second.ObserveBehavior(ctx, "scope", "", false, policy, false); err != nil || snapshot.Blocked {
		t.Fatalf("observe mode enforced a penalty: %+v %v", snapshot, err)
	}
	server.FastForward(time.Second)
	if snapshot, err := second.ObserveBehavior(ctx, "scope", "secrets", false, policy, true); err != nil || snapshot.Blocked || snapshot.Hits != 1 {
		t.Fatalf("penalty renewed or reused old probes: %+v %v", snapshot, err)
	}
}

func TestBehaviorObservationBoundedAndErrorsVisible(t *testing.T) {
	server := miniredis.RunT(t)
	ctx := context.Background()
	state, err := New(ctx, "redis://"+server.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	policy := store.BehaviorPolicy{WindowSeconds: 30, Threshold: 2, BlockSeconds: 10}
	for count := 0; count < 20; count++ {
		snapshot, err := state.ObserveBehavior(ctx, "scope", "secrets", true, policy, false)
		if err != nil || snapshot.Blocked || snapshot.Hits > 4 {
			t.Fatalf("observe state became blocking/unbounded: %+v %v", snapshot, err)
		}
	}
	if snapshot, err := state.ObserveBehavior(ctx, "scope", "", false, policy, true); err != nil || snapshot.Blocked {
		t.Fatalf("observe traffic created a persistent block: %+v %v", snapshot, err)
	}
	for _, stateKey := range server.Keys() {
		if server.TTL(stateKey) <= 0 {
			t.Fatalf("behavior state must expire: %s", stateKey)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if snapshot, err := state.ObserveBehavior(cancelled, "scope", "secrets", true, policy, true); err == nil || snapshot.Blocked {
		t.Fatalf("state failure must be explicit without a block: %+v %v", snapshot, err)
	}
}
