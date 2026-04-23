package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"testing"
)

func TestHandleProxyForwardedHeaders_SetsCommonForwardedHeaders(t *testing.T) {
	req := &http.Request{
		Header:     make(http.Header),
		Host:       "frontend.example.test:8443",
		RemoteAddr: "203.0.113.9:50123",
		TLS:        &tls.ConnectionState{},
	}

	handleProxyForwardedHeaders(req, "/apps/demo")

	if got := req.Header.Get("X-Real-IP"); got != "203.0.113.9" {
		t.Fatalf("X-Real-IP = %q, want %q", got, "203.0.113.9")
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "frontend.example.test:8443" {
		t.Fatalf("X-Forwarded-Host = %q, want %q", got, "frontend.example.test:8443")
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("X-Forwarded-Proto = %q, want %q", got, "https")
	}
	if got := req.Header.Get("X-Forwarded-Port"); got != "8443" {
		t.Fatalf("X-Forwarded-Port = %q, want %q", got, "8443")
	}
	if got := req.Header.Get("X-Forwarded-Prefix"); got != "/apps/demo" {
		t.Fatalf("X-Forwarded-Prefix = %q, want %q", got, "/apps/demo")
	}
	if got := req.Header.Get("Forwarded"); got != `for="203.0.113.9";host="frontend.example.test:8443";proto=https` {
		t.Fatalf("Forwarded = %q, want expected RFC7239 value", got)
	}
}

func TestHandleProxyForwardedHeaders_OmitsPrefixForRootRoute(t *testing.T) {
	req := &http.Request{
		Header:     make(http.Header),
		Host:       "frontend.example.test",
		RemoteAddr: "203.0.113.9:50123",
	}

	handleProxyForwardedHeaders(req, "")

	if got := req.Header.Get("X-Forwarded-Prefix"); got != "" {
		t.Fatalf("X-Forwarded-Prefix = %q, want empty for root route", got)
	}
}

func TestHandleProxyForwardedHeaders_AppendsForwardedHeader(t *testing.T) {
	req := &http.Request{
		Header:     make(http.Header),
		Host:       "frontend.example.test",
		RemoteAddr: "203.0.113.9:50123",
	}
	req.Header.Set("Forwarded", `for=198.51.100.20;proto=http`)

	handleProxyForwardedHeaders(req, "/apps/demo")

	if got := req.Header.Get("Forwarded"); got != `for=198.51.100.20;proto=http, for="203.0.113.9";host="frontend.example.test";proto=http` {
		t.Fatalf("Forwarded = %q, want appended value", got)
	}
}

func TestConfigureRouteProxyDirector_SetsForwardedPrefix(t *testing.T) {
	proxy := &httputil.ReverseProxy{}
	target := &url.URL{Scheme: "http", Host: "backend.internal:8080", Path: "/base"}
	configureRouteProxyDirector(proxy, target, "/apps/demo")

	req := &http.Request{
		Header:     make(http.Header),
		Host:       "frontend.example.test",
		RemoteAddr: "203.0.113.9:50123",
		URL: &url.URL{
			Path:    "/apps/demo/api/v1/items",
			RawPath: "/apps/demo/api/v1/items",
		},
	}

	proxy.Director(req)

	if got := req.URL.Scheme; got != "http" {
		t.Fatalf("req.URL.Scheme = %q, want %q", got, "http")
	}
	if got := req.URL.Host; got != "backend.internal:8080" {
		t.Fatalf("req.URL.Host = %q, want %q", got, "backend.internal:8080")
	}
	if got := req.URL.Path; got != "/base/api/v1/items" {
		t.Fatalf("req.URL.Path = %q, want %q", got, "/base/api/v1/items")
	}
	if got := req.Header.Get("X-Forwarded-Prefix"); got != "/apps/demo" {
		t.Fatalf("X-Forwarded-Prefix = %q, want %q", got, "/apps/demo")
	}
}