package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesEntryAndSPAFallback(t *testing.T) {
	h := Handler()
	for _, target := range []string{"/", "/attacks"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s: status = %d", target, rr.Code)
		}
		if !strings.Contains(rr.Body.String(), `<div id="app"></div>`) {
			t.Fatalf("GET %s did not return the Vue entry point", target)
		}
	}
}

func TestHandlerDoesNotFallbackForMissingAsset(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/assets/missing.js", nil)
	rr := httptest.NewRecorder()
	Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}
