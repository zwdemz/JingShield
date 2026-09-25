package cc_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"jingshield/internal/config"
	"jingshield/internal/protection/cc"
	"jingshield/internal/protection/reqctx"
	"jingshield/internal/store/memory"
)

type busyNASHistory struct{}

func (busyNASHistory) CountByIPSince(context.Context, string, string) (int64, error) {
	return 40, nil
}

func (busyNASHistory) CountDistinctURIByIPSince(context.Context, string, string) (int64, error) {
	return 40, nil
}

func newDetector(t *testing.T) *cc.CCDetector {
	t.Helper()
	dynamic := config.NewDynamicConfig(nil)
	if err := dynamic.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return cc.NewCCDetector(memory.New(), busyNASHistory{}, nil, nil, nil, dynamic, config.SessionConfig{})
}

func TestNASResourceDiversityDoesNotBlockOrdinaryNavigation(t *testing.T) {
	detector := newDetector(t)
	for index := 0; index < 25; index++ {
		request := httptest.NewRequest("GET", fmt.Sprintf("https://nas.example.test/v/assets/module-%d.js", index), nil)
		requestContext, err := reqctx.NewRequestContext(request, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result := detector.Check(request.Context(), requestContext); result.Action != cc.ActionAllow {
			t.Fatalf("ordinary resource challenged or blocked after diverse NAS requests: %+v", result)
		}
	}
}

func TestNASCompatibilityRetainsVariantAndScannerBlocking(t *testing.T) {
	for _, scenario := range []struct{ name, query, userAgent string }{
		{"suspicious parameters with churn", "?abcdefghijklmnopqrstuvw=value", "Mozilla/5.0"},
		{"scanner signature", "", "sqlmap"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "https://nas.example.test/"+scenario.query, nil)
			request.Header.Set("User-Agent", scenario.userAgent)
			requestContext, err := reqctx.NewRequestContext(request, nil)
			if err != nil {
				t.Fatal(err)
			}
			if result := newDetector(t).Check(request.Context(), requestContext); result.Action != cc.ActionBlock {
				t.Fatalf("expected variant CC block, got %v", result.Action)
			}
		})
	}
}
