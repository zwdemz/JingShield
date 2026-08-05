package api

import "testing"

func TestValidatedSiteNormalizesInput(t *testing.T) {
	site, message := validatedSite(siteInput{
		Name: " 官网 ", Host: "*.Example.COM.", Upstream: "https://127.0.0.1:9443/", Enabled: true, PassHost: true,
	})
	if message != "" {
		t.Fatal(message)
	}
	if site.Name != "官网" || site.Host != "*.example.com" || site.Upstream != "https://127.0.0.1:9443" {
		t.Fatalf("unexpected normalized site: %#v", site)
	}
}

func TestValidatedSiteRejectsUnsafeValues(t *testing.T) {
	tests := []siteInput{
		{Name: "x", Host: "https://example.com", Upstream: "http://127.0.0.1"},
		{Name: "x", Host: "*example.com", Upstream: "http://127.0.0.1"},
		{Name: "x", Host: "example.com", Upstream: "file:///etc/passwd"},
		{Name: "x", Host: "example.com", Upstream: "http://user:pass@127.0.0.1"},
		{Name: "x", Host: "example.com", Upstream: "http://127.0.0.1?admin=1"},
		{Name: "x", Host: "example.com", Upstream: "http://127.0.0.1", TLSSkipVerify: true},
	}
	for _, input := range tests {
		if _, message := validatedSite(input); message == "" {
			t.Fatalf("accepted invalid input: %#v", input)
		}
	}
}
