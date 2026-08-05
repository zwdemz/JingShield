package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"jingshield/internal/config"
	"jingshield/internal/model"
)

func TestSessionLifecycle(t *testing.T) {
	m := newSessionManager(config.SessionConfig{Name: "test_session", MaxAge: 60})
	recorder := httptest.NewRecorder()
	created, err := m.create(recorder, &model.User{ID: 7, Username: "admin", MustChangePassword: true})
	if err != nil {
		t.Fatal(err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected session cookie: %#v", cookies)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.test/api/v1/auth/me", nil)
	req.AddCookie(cookies[0])
	got, ok := m.get(req)
	if !ok || got.UserID != 7 || got.CSRFToken != created.CSRFToken {
		t.Fatalf("session lookup failed: %#v, ok=%v", got, ok)
	}
	m.delete(httptest.NewRecorder(), req)
	if _, ok := m.get(req); ok {
		t.Fatal("deleted session remained valid")
	}
}

func TestProtectedRequiresCSRFAndEnforcesPasswordChange(t *testing.T) {
	a := &API{
		sessions: newSessionManager(config.SessionConfig{Name: "test_session", MaxAge: 60}),
		adminIPs: []string{"127.0.0.1"},
	}
	cookieRecorder := httptest.NewRecorder()
	s, err := a.sessions.create(cookieRecorder, &model.User{ID: 1, Username: "admin", MustChangePassword: true})
	if err != nil {
		t.Fatal(err)
	}
	cookie := cookieRecorder.Result().Cookies()[0]

	called := false
	handler := a.protected(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), true, true)
	req := httptest.NewRequest(http.MethodPut, "http://example.test/api/v1/users/password", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusForbidden || called {
		t.Fatalf("missing CSRF returned %d, called=%v", response.Code, called)
	}

	req = httptest.NewRequest(http.MethodPut, "http://example.test/api/v1/users/password", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", s.CSRFToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK || !called {
		t.Fatalf("valid CSRF returned %d, called=%v", response.Code, called)
	}

	called = false
	handler = a.protected(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), false, false)
	req = httptest.NewRequest(http.MethodGet, "http://example.test/api/v1/dashboard/stats", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusForbidden || called {
		t.Fatalf("forced password change returned %d, called=%v", response.Code, called)
	}
}
