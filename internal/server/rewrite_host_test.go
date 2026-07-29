package server

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
)

func TestConfigureRouteProxyDirectorRewritesHostHeader(t *testing.T) {
	targetURL := &url.URL{Scheme: "http", Host: "backend.internal:8080"}
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	configureRouteProxyDirector(proxy, targetURL, "/", "backend.example.test")

	req := httptest.NewRequest(http.MethodGet, "http://frontend.example.test/app", nil)
	proxy.Director(req)

	if req.Host != "backend.example.test" {
		t.Fatalf("expected rewritten host %q, got %q", "backend.example.test", req.Host)
	}
	if req.URL.Host != "backend.internal:8080" {
		t.Fatalf("expected backend URL host %q, got %q", "backend.internal:8080", req.URL.Host)
	}
}
