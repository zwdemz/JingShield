package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"jingshield/internal/config"
	"jingshield/internal/model"
)

type session struct {
	UserID             int64
	Username           string
	MustChangePassword bool
	CSRFToken          string
	ExpiresAt          time.Time
}

type sessionManager struct {
	mu       sync.RWMutex
	sessions map[[32]byte]session
	cfg      config.SessionConfig
}

func newSessionManager(cfg config.SessionConfig) *sessionManager {
	if cfg.Name == "" {
		cfg.Name = "jingshield_session"
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 7200
	}
	return &sessionManager{sessions: make(map[[32]byte]session), cfg: cfg}
}

func (m *sessionManager) create(w http.ResponseWriter, u *model.User) (session, error) {
	raw, err := randomToken(32)
	if err != nil {
		return session{}, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return session{}, err
	}
	s := session{
		UserID: u.ID, Username: u.Username, MustChangePassword: u.MustChangePassword,
		CSRFToken: csrf, ExpiresAt: time.Now().Add(time.Duration(m.cfg.MaxAge) * time.Second),
	}
	m.mu.Lock()
	if len(m.sessions) >= 10000 {
		m.removeExpiredLocked(time.Now())
	}
	if len(m.sessions) >= 10000 {
		m.mu.Unlock()
		return session{}, errSessionCapacity
	}
	m.sessions[sha256.Sum256([]byte(raw))] = s
	m.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: m.cfg.Name, Value: raw, Path: "/api/v1", Domain: m.cfg.Domain,
		MaxAge: m.cfg.MaxAge, HttpOnly: true, Secure: m.cfg.Secure,
		SameSite: http.SameSiteStrictMode,
	})
	return s, nil
}

func (m *sessionManager) get(r *http.Request) (session, bool) {
	cookie, err := r.Cookie(m.cfg.Name)
	if err != nil || cookie.Value == "" {
		return session{}, false
	}
	key := sha256.Sum256([]byte(cookie.Value))
	m.mu.RLock()
	s, ok := m.sessions[key]
	m.mu.RUnlock()
	if !ok || time.Now().After(s.ExpiresAt) {
		if ok {
			m.mu.Lock()
			delete(m.sessions, key)
			m.mu.Unlock()
		}
		return session{}, false
	}
	return s, true
}

func (m *sessionManager) delete(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(m.cfg.Name); err == nil {
		m.mu.Lock()
		delete(m.sessions, sha256.Sum256([]byte(cookie.Value)))
		m.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: m.cfg.Name, Value: "", Path: "/api/v1", Domain: m.cfg.Domain,
		MaxAge: -1, HttpOnly: true, Secure: m.cfg.Secure, SameSite: http.SameSiteStrictMode,
	})
}

// deleteUser 使指定用户的所有现存管理会话立即失效。
func (m *sessionManager) deleteUser(userID int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, key)
		}
	}
}

func (m *sessionManager) removeExpiredLocked(now time.Time) {
	for key, s := range m.sessions {
		if now.After(s.ExpiresAt) {
			delete(m.sessions, key)
		}
	}
}

func randomToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type sessionCapacityError struct{}

func (sessionCapacityError) Error() string { return "会话容量已满" }

var errSessionCapacity = sessionCapacityError{}
