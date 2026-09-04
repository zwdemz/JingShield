package api

import (
	"testing"
	"time"
)

func TestLoginLimiterBlocksBurstAndExpires(t *testing.T) {
	l := newLoginLimiter()
	now := time.Unix(1000, 0)
	for i := 0; i < loginMaxAttempts; i++ {
		if !l.allow("198.51.100.10", now) {
			t.Fatalf("attempt %d was unexpectedly blocked", i)
		}
	}
	if l.allow("198.51.100.10", now) {
		t.Fatal("burst limit was not enforced")
	}
	if !l.allow("198.51.100.10", now.Add(loginWindow+time.Second)) {
		t.Fatal("expired attempts were not discarded")
	}
}

func TestLoginLimiterCapsUnknownKeys(t *testing.T) {
	l := newLoginLimiter()
	now := time.Unix(2000, 0)
	for i := 0; i < loginMaxKeys; i++ {
		if !l.allow("user:"+string(rune(i+1)), now) {
			t.Fatalf("key %d was unexpectedly blocked", i)
		}
	}
	if l.allow("new-key", now) {
		t.Fatal("new key was accepted after limiter capacity was exhausted")
	}
}
