package cc

import (
	"net/http/httptest"
	"testing"

	"jingshield/internal/config"
	"jingshield/internal/protection/reqctx"
)

func TestMethodPolicyAppliesOnlyToSelectedHostAndPath(t *testing.T) {
	detector := &CCDetector{methodPolicies: []config.MethodPolicy{{Host: "api.example.test", PathPrefix: "/v1", AllowedMethods: []string{"GET", "POST", "OPTIONS"}}}}
	cases := []struct {
		method, url string
		denied      bool
	}{
		{"OPTIONS", "http://api.example.test/v1/items", false},
		{"PATCH", "http://api.example.test/v1/items", true},
		{"PATCH", "http://api.example.test/v12/items", false},
		{"PATCH", "http://other.example.test/v1/items", false},
	}
	for _, item := range cases {
		request := httptest.NewRequest(item.method, item.url, nil)
		context, err := reqctx.NewRequestContext(request, nil)
		if err != nil {
			t.Fatal(err)
		}
		if actual := detector.methodDenied(context); actual != item.denied {
			t.Errorf("%s %s: denied = %v, want %v", item.method, item.url, actual, item.denied)
		}
	}
}

func TestCORSPreflightBypassesBehavioralChallenge(t *testing.T) {
	detector := &CCDetector{}
	request := httptest.NewRequest("OPTIONS", "http://api.example.test/v1/items", nil)
	request.Header.Set("Origin", "https://app.example.test")
	request.Header.Set("Access-Control-Request-Method", "PATCH")
	context, err := reqctx.NewRequestContext(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result := detector.Check(request.Context(), context); result.Action != ActionAllow {
		t.Fatalf("preflight action = %v, want allow", result.Action)
	}
}
