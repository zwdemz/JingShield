package api_test

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"jingshield/internal/api"
	"jingshield/internal/config"
	"jingshield/internal/pkg/logx"
	"jingshield/internal/policy"
	"jingshield/internal/repository"
	"jingshield/internal/store/memory"
	"jingshield/tests/testdb"
)

const mockAPIKey = "test-only-openapi-key-not-production"
const mockPassword = "TestOnly-NotARealPassword"

var apiTestLogger sync.Once

type apiFixture struct {
	handler http.Handler
	cookie  *http.Cookie
	csrf    string
	dynamic *config.DynamicConfig
}

func newFixture(t *testing.T, login bool, steps ...testdb.Step) *apiFixture {
	t.Helper()
	apiTestLogger.Do(func() {
		// The application's process-wide logger owns open files for its lifetime.
		// A process-scoped temp path avoids Windows deleting live logger handles.
		directory := filepath.Join(os.TempDir(), fmt.Sprintf("jingshield-api-handler-tests-%d", os.Getpid()))
		if err := logx.Init(logx.Config{Level: "error", Dir: directory}); err != nil {
			t.Fatal(err)
		}
	})
	prefix := []testdb.Step{
		{Kind: "query", Contains: "SHOW TABLES", Columns: []string{"table"}, Values: [][]driver.Value{{"jyj_config"}}},
		{Kind: "query", Contains: "SELECT config_key, config_value", Columns: []string{"config_key", "config_value"}, Values: [][]driver.Value{{"api_key", mockAPIKey}}},
	}
	if login {
		hash, err := bcrypt.GenerateFromPassword([]byte(mockPassword), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		prefix = append(prefix,
			testdb.Step{Kind: "query", Contains: "FROM jyj_users WHERE username", Columns: []string{"id", "username", "password", "email", "status", "must_change_password", "last_login_at", "created_at"}, Values: [][]driver.Value{{int64(7), "test-admin", string(hash), "", int64(1), false, nil, time.Now()}}, Check: checkArguments("test-admin")},
			testdb.Step{Kind: "exec", Contains: "UPDATE jyj_users SET last_login_at"},
			testdb.Step{Kind: "exec", Contains: "INSERT INTO jyj_login_log"},
		)
	}
	db := testdb.Open(t, append(prefix, steps...)...)
	dynamic := config.NewDynamicConfig(db)
	if err := dynamic.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	handler, err := api.New(api.Dependencies{
		DB: db, DynamicConfig: dynamic, State: memory.New(), StaticConfig: &config.Config{AdminIPs: []string{"127.0.0.1"}},
		Sites: repository.NewSiteRepo(db), Policies: policy.New(repository.NewPolicyRepo(db), dynamic), FallbackHandler: http.NotFoundHandler(),
		StateBackend: "redis", WAFMetrics: func() map[string]any {
			return map[string]any{"evaluated_total": uint64(42), "access_queue_capacity": 2048, "behavior": map[string]any{"state_errors_total": uint64(3)}}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &apiFixture{handler: handler, dynamic: dynamic}
	if login {
		response := fixture.request(t, "POST", "/api/v1/auth/login", map[string]string{"username": "test-admin", "password": mockPassword}, "none")
		data := requireResponse(t, response, http.StatusOK)
		fixture.csrf, _ = data["csrf_token"].(string)
		cookies := response.Result().Cookies()
		if len(cookies) != 1 || fixture.csrf == "" {
			t.Fatal("real login handler did not produce session and CSRF token")
		}
		fixture.cookie = cookies[0]
	}
	return fixture
}

func (fixture *apiFixture) request(t *testing.T, method, target string, body any, authentication string) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, "https://waf.test"+target, bytes.NewReader(encoded))
	request.RemoteAddr = "127.0.0.1:43210"
	request.Header.Set("Content-Type", "application/json")
	if authentication == "session" || authentication == "csrf" {
		request.AddCookie(fixture.cookie)
	}
	if authentication == "csrf" {
		request.Header.Set("X-CSRF-Token", fixture.csrf)
	}
	if authentication == "api" {
		request.Header.Set("X-API-Key", mockAPIKey)
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func requireResponse(t *testing.T, response *httptest.ResponseRecorder, status int) map[string]any {
	t.Helper()
	if response.Code != status {
		t.Fatalf("HTTP status=%d, expected=%d; body=%s", response.Code, status, response.Body.String())
	}
	var envelope struct {
		Code int            `json:"code"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if (status == http.StatusOK) != (envelope.Code == 0) {
		t.Fatalf("HTTP status and envelope disagree: %s", response.Body.String())
	}
	return envelope.Data
}

func checkArguments(expected ...any) func([]driver.NamedValue) error {
	return func(arguments []driver.NamedValue) error {
		if len(arguments) != len(expected) {
			return fmt.Errorf("argument count got %d expected %d", len(arguments), len(expected))
		}
		for index, argument := range arguments {
			if fmt.Sprint(argument.Value) != fmt.Sprint(expected[index]) {
				return fmt.Errorf("argument %d got %v expected %v", index, argument.Value, expected[index])
			}
		}
		return nil
	}
}
