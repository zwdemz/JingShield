package proxy

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"testing"

	"jingshield/internal/model"
)

type fixedSiteResolver struct {
	site     *model.Site
	hasSites bool
	err      error
}

func (r fixedSiteResolver) ResolveSite(context.Context, string) (*model.Site, bool, error) {
	return r.site, r.hasSites, r.err
}

func TestReverseForRejectsUnknownHostWhenSitesExist(t *testing.T) {
	p := &Proxy{sites: fixedSiteResolver{hasSites: true}, reverses: map[string]*httputil.ReverseProxy{}}
	req := &http.Request{Host: "unknown.example.com", URL: &url.URL{Path: "/"}}
	rp, err := p.reverseFor(req)
	if err != nil || rp != nil {
		t.Fatalf("reverseFor = (%v, %v), want (nil, nil)", rp, err)
	}
}

func TestReverseForSelectsSiteAndAppliesHostPolicy(t *testing.T) {
	for _, passHost := range []bool{true, false} {
		site := &model.Site{Upstream: "http://127.0.0.1:19000/base", PassHost: passHost}
		p := &Proxy{sites: fixedSiteResolver{site: site, hasSites: true}, reverses: map[string]*httputil.ReverseProxy{}}
		req := &http.Request{Host: "www.example.com", URL: &url.URL{Path: "/hello"}, Header: make(http.Header)}
		rp, err := p.reverseFor(req)
		if err != nil {
			t.Fatal(err)
		}
		rp.Director(req)
		if req.URL.Host != "127.0.0.1:19000" || req.URL.Path != "/base/hello" {
			t.Fatalf("unexpected target: %s", req.URL.String())
		}
		wantHost := "www.example.com"
		if !passHost {
			wantHost = "127.0.0.1:19000"
		}
		if req.Host != wantHost {
			t.Fatalf("passHost=%t: Host = %q, want %q", passHost, req.Host, wantHost)
		}
		if req.Header.Get("X-Forwarded-Host") != "www.example.com" || req.Header.Get("X-Forwarded-Proto") != "http" {
			t.Fatalf("forwarded headers not normalized: %#v", req.Header)
		}
	}
}

func TestReverseForAllowsExplicitSelfSignedTLSOrigin(t *testing.T) {
	for _, skipVerify := range []bool{false, true} {
		site := &model.Site{Upstream: "https://127.0.0.1:8080", TLSSkipVerify: skipVerify}
		p := &Proxy{sites: fixedSiteResolver{site: site, hasSites: true}, reverses: map[string]*httputil.ReverseProxy{}}
		req := &http.Request{Host: "cyberstrike.example", URL: &url.URL{Path: "/"}, Header: make(http.Header)}
		rp, err := p.reverseFor(req)
		if err != nil {
			t.Fatal(err)
		}
		breaker, ok := rp.Transport.(*circuitBreakerTransport)
		if !ok {
			t.Fatalf("expected circuit breaker, got %T", rp.Transport)
		}
		transport, ok := breaker.base.(*http.Transport)
		if !ok || transport.TLSClientConfig == nil {
			t.Fatalf("missing TLS configuration on circuit breaker transport: %T", breaker.base)
		}
		if transport.TLSClientConfig.InsecureSkipVerify != skipVerify || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
			t.Fatalf("skipVerify=%v: unexpected TLS configuration: %+v", skipVerify, transport.TLSClientConfig)
		}
	}
}

func TestReverseProxyRewritesOnlyPublicSameOriginForPrivateUpstream(t *testing.T) {
	for _, test := range []struct {
		name       string
		origin     string
		wantOrigin string
	}{
		{name: "same origin", origin: "https://waf.example:18443", wantOrigin: "https://127.0.0.1:8080"},
		{name: "foreign origin", origin: "https://attacker.example", wantOrigin: "https://attacker.example"},
		{name: "null origin", origin: "null", wantOrigin: "null"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rp, err := newReverseProxy("https://127.0.0.1:8080", false, true, 10, nil)
			if err != nil {
				t.Fatal(err)
			}
			req := &http.Request{
				Host:   "waf.example:18443",
				URL:    &url.URL{Path: "/login"},
				Header: http.Header{"Origin": {test.origin}},
				TLS:    &tls.ConnectionState{},
			}
			rp.Director(req)
			if got := req.Header.Get("Origin"); got != test.wantOrigin {
				t.Fatalf("Origin = %q, want %q", got, test.wantOrigin)
			}
			if req.Host != "127.0.0.1:8080" {
				t.Fatalf("Host = %q", req.Host)
			}
		})
	}
}
