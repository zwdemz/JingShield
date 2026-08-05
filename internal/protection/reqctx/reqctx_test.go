package reqctx

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewRequestContextPreservesFormBody(t *testing.T) {
	body := "name=alice&comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	r := httptest.NewRequest("POST", "http://example.test/submit", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rc, err := NewRequestContext(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := rc.Post.Get("name"); got != "alice" {
		t.Fatalf("form name = %q", got)
	}
	forwarded, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(forwarded) != body {
		t.Fatalf("forwarded body = %q, want %q", forwarded, body)
	}
}

func TestNewRequestContextExtractsJSONValuesAndPreservesBody(t *testing.T) {
	body := `{"profile":{"display_name":"<script>alert(1)</script>"}}`
	r := httptest.NewRequest("POST", "http://example.test/api", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")

	rc, err := NewRequestContext(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, value := range rc.AllParamValues() {
		if value == "<script>alert(1)</script>" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("nested JSON string was not exposed to detectors")
	}
	forwarded, _ := io.ReadAll(r.Body)
	if string(forwarded) != body {
		t.Fatalf("forwarded body = %q, want %q", forwarded, body)
	}
}
