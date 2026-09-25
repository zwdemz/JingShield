package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"jingshield/internal/config"
)

type sharedChallengeMemory struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (s *sharedChallengeMemory) PutChallenge(_ context.Context, nonce string, payload []byte, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[nonce] = payload
	return nil
}

func (s *sharedChallengeMemory) ConsumeChallenge(_ context.Context, nonce string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value := s.values[nonce]
	delete(s.values, nonce)
	return value, nil
}

func TestSharedChallengeIsSingleUseAcrossInstances(t *testing.T) {
	shared := &sharedChallengeMemory{values: make(map[string][]byte)}
	first := &Service{session: config.SessionConfig{Secret: "same-secret"}, shared: shared}
	second := &Service{session: config.SessionConfig{Secret: "same-secret"}, shared: shared}
	claims := challengeClaims{IP: "198.51.100.20", Action: "verify_slide", Nonce: "one-time", Difficulty: 8, IssuedAt: time.Now().Unix() - 2, ExpiresAt: time.Now().Unix() + 120}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := shared.PutChallenge(context.Background(), claims.Nonce, payload, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	token := encoded + "." + first.sign(encoded)
	proof := solveProof(token, claims.Difficulty)
	if err := second.validateChallenge(claims.IP, claims.Action, token, proof); err != nil {
		t.Fatal(err)
	}
	if err := first.validateChallenge(claims.IP, claims.Action, token, proof); err == nil {
		t.Fatal("challenge replay was accepted")
	}
}

func TestChallengeIsIPBoundAndSingleUse(t *testing.T) {
	s := &Service{
		session:    config.SessionConfig{Secret: "test-secret"},
		challenges: make(map[string]challengeClaims),
	}
	token, action, _, difficulty, err := s.NewChallenge("198.51.100.20", ModeSlide)
	if err != nil {
		t.Fatal(err)
	}

	// Move the signed issue time backwards so the test does not sleep.
	parts := strings.SplitN(token, ".", 2)
	payload, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var claims challengeClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims.IssuedAt -= 2
	payload, _ = json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	token = encoded + "." + s.sign(encoded)
	s.challenges[claims.Nonce] = claims

	proof := solveProof(token, difficulty)
	if err := s.validateChallenge("203.0.113.5", action, token, proof); err == nil {
		t.Fatal("challenge accepted from a different IP")
	}
	if err := s.validateChallenge("198.51.100.20", action, token, proof); err != nil {
		t.Fatalf("valid challenge rejected: %v", err)
	}
	if err := s.validateChallenge("198.51.100.20", action, token, proof); err == nil {
		t.Fatal("single-use challenge was accepted twice")
	}
}

func solveProof(token string, difficulty int) string {
	for i := 0; ; i++ {
		proof := strconv.Itoa(i)
		if validProof(token, proof, difficulty) {
			return proof
		}
	}
}
