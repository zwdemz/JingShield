package repository

import (
	"testing"

	"jingshield/internal/model"
)

func TestMatchSiteExactAndLongestWildcard(t *testing.T) {
	routes := map[string]*model.Site{
		"www.example.com":   {Host: "www.example.com", Name: "exact"},
		"*.example.com":     {Host: "*.example.com", Name: "wildcard"},
		"*.api.example.com": {Host: "*.api.example.com", Name: "specific"},
	}
	for host, want := range map[string]string{
		"www.example.com": "exact", "img.example.com": "wildcard", "v1.api.example.com": "specific",
	} {
		got := matchSite(routes, host)
		if got == nil || got.Name != want {
			t.Fatalf("host %s resolved to %#v, want %s", host, got, want)
		}
	}
	if got := matchSite(routes, "example.com"); got != nil {
		t.Fatalf("wildcard unexpectedly matched apex: %#v", got)
	}
}

func TestCanonicalRequestHost(t *testing.T) {
	for input, want := range map[string]string{
		"WWW.Example.COM:8080": "www.example.com",
		"example.com.":         "example.com",
		"[2001:db8::1]:443":    "2001:db8::1",
	} {
		if got := canonicalRequestHost(input); got != want {
			t.Fatalf("canonicalRequestHost(%q) = %q, want %q", input, got, want)
		}
	}
}
