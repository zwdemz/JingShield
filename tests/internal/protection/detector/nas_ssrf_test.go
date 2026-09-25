package detector_test

import (
	"net/http/httptest"
	"testing"

	"jingshield/internal/protection/detector"
	"jingshield/internal/protection/reqctx"
)

func TestNASOriginMetadataDoesNotDisableSSRFParameterInspection(t *testing.T) {
	for _, scenario := range []struct {
		name, header, value, query string
		blocked                    bool
	}{
		{"same-origin referer", "Referer", "https://192.168.1.92:18443/", "", false},
		{"same-origin origin", "Origin", "https://192.168.1.92:18443", "", false},
		{"foreign private referer", "Referer", "http://127.0.0.1/", "", true},
		{"private fetch parameter", "Referer", "https://192.168.1.92:18443/", "?url=http%3A%2F%2F127.0.0.1%2F", true},
		{"private target in referer query", "Referer", "https://192.168.1.92:18443/?url=http%3A%2F%2F127.0.0.1%2F", "", true},
		{"custom URL header", "X-Target", "http://127.0.0.1/", "", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "https://192.168.1.92:18443/"+scenario.query, nil)
			request.RequestURI = request.URL.RequestURI()
			request.Header.Set(scenario.header, scenario.value)
			requestContext, err := reqctx.NewRequestContext(request, nil)
			if err != nil {
				t.Fatal(err)
			}
			result := detector.NewSSRFDetector().Check(request.Context(), requestContext)
			if blocked := result != nil && result.Detected; blocked != scenario.blocked {
				t.Fatalf("blocked = %v, want %v: %+v", blocked, scenario.blocked, result)
			}
			if request.Header.Get(scenario.header) != scenario.value {
				t.Fatal("SSRF inspection modified the forwarded request headers")
			}
		})
	}
}
