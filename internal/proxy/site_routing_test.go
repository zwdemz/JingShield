package proxy

import (
	"context"
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
	site := &model.Site{Upstream: "https://127.0.0.1:8080", TLSSkipVerify: true}
	p := &Proxy{sites: fixedSiteResolver{site: site, hasSites: true}, reverses: map[string]*httputil.ReverseProxy{}}
	req := &http.Request{Host: "cyberstrike.example", URL: &url.URL{Path: "/"}, Header: make(http.Header)}
	rp, err := p.reverseFor(req)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := rp.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("explicit self-signed TLS option was not applied")
	}
}
