package verify

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"jingshield/internal/config"
)

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
