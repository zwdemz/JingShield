package proxy

import (
	"errors"
	"net/http"
	"testing"
)

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("origin down")
}

func TestCircuitBreakerOpensAfterRepeatedFailures(t *testing.T) {
	breaker := &circuitBreakerTransport{base: failingTransport{}}
	req, err := http.NewRequest(http.MethodGet, "http://origin.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < upstreamFailureThreshold; i++ {
		_, _ = breaker.RoundTrip(req)
	}
	if _, err := breaker.RoundTrip(req); err == nil || err.Error() != "源站熔断中" {
		t.Fatalf("circuit did not open after repeated failures: %v", err)
	}
}
