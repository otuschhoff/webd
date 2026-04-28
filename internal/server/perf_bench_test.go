package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"testing"
)

func BenchmarkRouteTrieMatch(b *testing.B) {
	routes := make([]routeProxy, 0, 200)
	for i := 0; i < 200; i++ {
		routes = append(routes, routeProxy{prefix: fmt.Sprintf("/api/v1/service/%d", i)})
	}
	matcher := buildRouteTrie(routes)
	path := "/api/v1/service/137/resource/abc"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := matcher.match(path); got == nil {
			b.Fatal("expected route match")
		}
	}
}

func BenchmarkIsClientIPv4Allowed(b *testing.B) {
	ranges := make([]IPv4Range, 0, 2048)
	for i := 0; i < 2048; i++ {
		start := uint32(i * 128)
		ranges = append(ranges, IPv4Range{Start: start, End: start + 31})
	}
	normalized := normalizeIPv4Ranges(ranges)
	ip := "0.0.15.10"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = isClientIPv4Allowed(ip, normalized)
	}
}

func BenchmarkNormalizeIPv4Ranges(b *testing.B) {
	input := make([]IPv4Range, 0, 4096)
	for i := 4095; i >= 0; i-- {
		start := uint32(i * 8)
		input = append(input, IPv4Range{Start: start, End: start + 4})
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = normalizeIPv4Ranges(input)
	}
}

func BenchmarkHandleProxyForwardedHeaders(b *testing.B) {
	b.Run("no_existing_forwarded", func(b *testing.B) {
		req := &http.Request{
			Header:     make(http.Header),
			Host:       "frontend.example.test:8443",
			RemoteAddr: "203.0.113.9:50123",
			TLS:        &tls.ConnectionState{},
		}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req.Header.Del("Forwarded")
			handleProxyForwardedHeaders(req, "/apps/demo")
		}
	})

	b.Run("with_existing_forwarded", func(b *testing.B) {
		req := &http.Request{
			Header:     make(http.Header),
			Host:       "frontend.example.test",
			RemoteAddr: "203.0.113.9:50123",
		}
		req.Header.Set("Forwarded", `for=198.51.100.20;proto=http`)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req.Header.Set("Forwarded", `for=198.51.100.20;proto=http`)
			handleProxyForwardedHeaders(req, "/apps/demo")
		}
	})
}

func BenchmarkConfigureRouteProxyDirector(b *testing.B) {
	proxy := &httputil.ReverseProxy{}
	target := &url.URL{
		Scheme:   "http",
		Host:     "backend.internal:8080",
		Path:     "/base",
		RawPath:  "/base",
		RawQuery: "target=1",
	}
	configureRouteProxyDirector(proxy, target, "/apps/demo")

	b.Run("no_existing_forwarded", func(b *testing.B) {
		req := &http.Request{
			Header:     make(http.Header),
			Host:       "frontend.example.test:8443",
			RemoteAddr: "203.0.113.9:50123",
			TLS:        &tls.ConnectionState{},
			URL: &url.URL{
				Path:     "/apps/demo/api/v1/items",
				RawPath:  "/apps/demo/api/v1/items",
				RawQuery: "request=1",
			},
		}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req.URL.Path = "/apps/demo/api/v1/items"
			req.URL.RawPath = "/apps/demo/api/v1/items"
			req.URL.RawQuery = "request=1"
			req.Header.Del("Forwarded")
			proxy.Director(req)
		}
	})

	b.Run("with_existing_forwarded", func(b *testing.B) {
		req := &http.Request{
			Header:     make(http.Header),
			Host:       "frontend.example.test",
			RemoteAddr: "203.0.113.9:50123",
			URL: &url.URL{
				Path:     "/apps/demo/api/v1/items",
				RawPath:  "/apps/demo/api/v1/items",
				RawQuery: "request=1",
			},
		}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req.URL.Path = "/apps/demo/api/v1/items"
			req.URL.RawPath = "/apps/demo/api/v1/items"
			req.URL.RawQuery = "request=1"
			req.Header.Set("Forwarded", `for=198.51.100.20;proto=http`)
			proxy.Director(req)
		}
	})

	b.Run("empty_rawpath", func(b *testing.B) {
		req := &http.Request{
			Header:     make(http.Header),
			Host:       "frontend.example.test",
			RemoteAddr: "203.0.113.9:50123",
			URL: &url.URL{
				Path:     "/apps/demo/api/v1/items",
				RawPath:  "",
				RawQuery: "request=1",
			},
		}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req.URL.Path = "/apps/demo/api/v1/items"
			req.URL.RawPath = ""
			req.URL.RawQuery = "request=1"
			req.Header.Del("Forwarded")
			proxy.Director(req)
		}
	})
}

func BenchmarkClientIP(b *testing.B) {
	b.Run("xff_single", func(b *testing.B) {
		req := &http.Request{Header: make(http.Header), RemoteAddr: "203.0.113.9:50123"}
		req.Header.Set("X-Forwarded-For", "198.51.100.7")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = clientIP(req)
		}
	})

	b.Run("xff_multi", func(b *testing.B) {
		req := &http.Request{Header: make(http.Header), RemoteAddr: "203.0.113.9:50123"}
		req.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.9")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = clientIP(req)
		}
	})

	b.Run("remote_addr", func(b *testing.B) {
		req := &http.Request{Header: make(http.Header), RemoteAddr: "203.0.113.9:50123"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = clientIP(req)
		}
	})
}
