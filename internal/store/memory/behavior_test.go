package memory

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"jingshield/internal/store"
)

func TestBehaviorWindowAndFixedBlockExpiry(t *testing.T) {
	state := New()
	now := time.Unix(1800000000, 0)
	state.behavior.now = func() time.Time { return now }
	policy := store.BehaviorPolicy{WindowSeconds: 30, Threshold: 2, BlockSeconds: 10}
	ctx := context.Background()
	first, err := state.ObserveBehavior(ctx, "scope", "secrets", false, policy, true)
	if err != nil || first.Matched {
		t.Fatalf("first probe: %+v %v", first, err)
	}
	now = now.Add(30 * time.Second)
	second, err := state.ObserveBehavior(ctx, "scope", "repository", false, policy, true)
	if err != nil || second.Hits != 1 || second.Matched {
		t.Fatalf("window boundary retained old probe: %+v %v", second, err)
	}
	blocked, err := state.ObserveBehavior(ctx, "scope", "secrets", false, policy, true)
	if err != nil || !blocked.Blocked || blocked.BlockRemainingSeconds != 10 {
		t.Fatalf("threshold did not create fixed penalty: %+v %v", blocked, err)
	}
	now = now.Add(9 * time.Second)
	blocked, _ = state.ObserveBehavior(ctx, "scope", "", false, policy, true)
	if !blocked.Blocked || blocked.BlockRemainingSeconds != 1 {
		t.Fatalf("unexpected remaining penalty: %+v", blocked)
	}
	observed, _ := state.ObserveBehavior(ctx, "scope", "", false, policy, false)
	if observed.Blocked {
		t.Fatal("observation mode enforced a previous penalty")
	}
	now = now.Add(time.Second)
	fresh, err := state.ObserveBehavior(ctx, "scope", "secrets", false, policy, true)
	if err != nil || fresh.Hits != 1 || fresh.Blocked {
		t.Fatalf("expired penalty reused old evidence or was extended: %+v %v", fresh, err)
	}
}

func TestBehaviorMemoryBoundsAndClear(t *testing.T) {
	state := New()
	policy := store.BehaviorPolicy{WindowSeconds: 30, Threshold: 2, BlockSeconds: 10}
	for count := 0; count < 100; count++ {
		if _, err := state.ObserveBehavior(context.Background(), "scope", "secrets", false, policy, false); err != nil {
			t.Fatal(err)
		}
	}
	if state.behavior.events != 4 || len(state.behavior.entries["scope"].events) != 4 {
		t.Fatal("observation mode exceeded the bounded event budget")
	}
	state.ClearAll(context.Background())
	if len(state.behavior.entries) != 0 || state.behavior.events != 0 {
		t.Fatal("administrative state clear omitted behavior state")
	}
	state.behavior.entries = make(map[string]*behaviorEntry)
	for index := 0; index < maxBehaviorScopes; index++ {
		state.behavior.entries[fmt.Sprint(index)] = &behaviorEntry{expiresAt: time.Now().Add(time.Hour)}
	}
	if _, err := state.ObserveBehavior(context.Background(), "overflow", "secrets", false, policy, false); !errors.Is(err, store.ErrBehaviorCapacity) {
		t.Fatalf("capacity must fail visibly: %v", err)
	}
}

func TestBehaviorAtomicConcurrentThreshold(t *testing.T) {
	state := New()
	policy := store.BehaviorPolicy{WindowSeconds: 30, Threshold: 8, BlockSeconds: 10}
	var workers sync.WaitGroup
	for index := 0; index < 8; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			category := "secrets"
			if index%2 == 0 {
				category = "repository"
			}
			if _, err := state.ObserveBehavior(context.Background(), "scope", category, false, policy, true); err != nil {
				t.Error(err)
			}
		}(index)
	}
	workers.Wait()
	snapshot, err := state.ObserveBehavior(context.Background(), "scope", "", false, policy, true)
	if err != nil || !snapshot.Blocked {
		t.Fatalf("concurrent probes did not atomically reach threshold: %+v %v", snapshot, err)
	}
}
