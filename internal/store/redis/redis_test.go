package redis

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestSharedCountersAndOneTimeChallenges(t *testing.T) {
	server := miniredis.RunT(t)
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

	if count, err := first.HitAndCount(ctx, "198.51.100.20", 60); err != nil || count != 1 {
		t.Fatalf("first hit: count=%d err=%v", count, err)
	}
	if count, err := second.HitAndCount(ctx, "198.51.100.20", 60); err != nil || count != 2 {
		t.Fatalf("shared hit: count=%d err=%v", count, err)
	}
	var hits sync.WaitGroup
	for index := 0; index < 20; index++ {
		hits.Add(1)
		go func(index int) {
			defer hits.Done()
			instance := first
			if index%2 == 0 {
				instance = second
			}
			if _, err := instance.HitAndCount(ctx, "198.51.100.20", 60); err != nil {
				t.Errorf("concurrent hit: %v", err)
			}
		}(index)
	}
	hits.Wait()
	if count, err := first.HitAndCount(ctx, "198.51.100.20", 60); err != nil || count != 23 {
		t.Fatalf("atomic hit count: count=%d err=%v", count, err)
	}
	if count, err := first.HitAndCount(ctx, "198.51.100.20|/login", 60); err != nil || count != 1 {
		t.Fatalf("URL hit: count=%d err=%v", count, err)
	}
	if previous, err := first.LastRequestAt(ctx, "198.51.100.20"); err != nil || !previous.IsZero() {
		t.Fatalf("first interval: previous=%v err=%v", previous, err)
	}
	if previous, err := second.LastRequestAt(ctx, "198.51.100.20"); err != nil || previous.IsZero() {
		t.Fatalf("shared interval: previous=%v err=%v", previous, err)
	}
	if intervals, err := first.RecentIntervals(ctx, "198.51.100.20", 10); err != nil || len(intervals) != 1 {
		t.Fatalf("recent intervals: values=%v err=%v", intervals, err)
	}
	if ports, err := first.RecordPort(ctx, "198.51.100.20", 80, 60); err != nil || ports != 1 {
		t.Fatalf("first port: count=%d err=%v", ports, err)
	}
	if ports, err := second.RecordPort(ctx, "198.51.100.20", 443, 60); err != nil || ports != 2 {
		t.Fatalf("shared ports: count=%d err=%v", ports, err)
	}
	if err := second.ResetIP(ctx, "198.51.100.20"); err != nil {
		t.Fatal(err)
	}
	if count, err := first.HitAndCount(ctx, "198.51.100.20|/login", 60); err != nil || count != 1 {
		t.Fatalf("reset URL hit: count=%d err=%v", count, err)
	}

	if err := first.PutChallenge(ctx, "nonce", []byte("claims"), 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	if value, err := second.ConsumeChallenge(ctx, "nonce"); err != nil || string(value) != "claims" {
		t.Fatalf("challenge consume: value=%q err=%v", value, err)
	}
	if value, err := first.ConsumeChallenge(ctx, "nonce"); err != nil || value != nil {
		t.Fatalf("challenge replay: value=%q err=%v", value, err)
	}
}

func TestClearAllPreservesOtherApplications(t *testing.T) {
	server := miniredis.RunT(t)
	server.Set("unrelated:key", "keep")
	state, err := New(context.Background(), "redis://"+server.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if _, err := state.HitAndCount(context.Background(), "198.51.100.20", 60); err != nil {
		t.Fatal(err)
	}
	if err := state.ClearAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if value, err := server.Get("unrelated:key"); err != nil || value != "keep" {
		t.Fatalf("other application key changed: value=%q err=%v", value, err)
	}
}
