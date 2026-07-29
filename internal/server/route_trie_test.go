package server

import (
	"net/http/httputil"
	"testing"
)

func TestRouteTrieMatch_LongestPrefixWins(t *testing.T) {
	routes := []routeProxy{
		{prefix: "/"},
		{prefix: "/api"},
		{prefix: "/api/v1"},
		{prefix: "/api/v1/private"},
		{prefix: "/app"},
	}
	trie := buildRouteTrie(routes)

	cases := []struct {
		path string
		want string
	}{
		{path: "/", want: "/"},
		{path: "/unknown", want: "/"},
		{path: "/api", want: "/api"},
		{path: "/api/foo", want: "/api"},
		{path: "/api/v1", want: "/api/v1"},
		{path: "/api/v1/x", want: "/api/v1"},
		{path: "/api/v1/private", want: "/api/v1/private"},
		{path: "/api/v1/private/x", want: "/api/v1/private"},
		{path: "/app/x", want: "/app"},
	}

	for _, tc := range cases {
		r := trie.match(tc.path)
		if r == nil {
			t.Fatalf("match(%q) returned nil, want prefix %q", tc.path, tc.want)
		}
		if r.prefix != tc.want {
			t.Fatalf("match(%q) = %q, want %q", tc.path, r.prefix, tc.want)
		}
	}
}

func TestRouteTrieMatch_NoRootRouteReturnsNil(t *testing.T) {
	routes := []routeProxy{
		{prefix: "/api"},
		{prefix: "/app"},
	}
	trie := buildRouteTrie(routes)

	if got := trie.match("/no-match"); got != nil {
		t.Fatalf("match(/no-match) = %q, want nil", got.prefix)
	}
}

func TestRouteTrieMatch_RedirectAndFallbackRoutesCoexist(t *testing.T) {
	routes := []routeProxy{
		{prefix: "/", redirectTarget: "/polarion"},
		{prefix: "/", proxy: &httputil.ReverseProxy{}},
	}
	trie := buildRouteTrie(routes)

	rootRoute := trie.match("/")
	if rootRoute == nil || rootRoute.redirectTarget != "/polarion" {
		t.Fatalf("match(/) = %#v, want redirect route for /", rootRoute)
	}

	fallbackRoute := trie.match("/foo")
	if fallbackRoute == nil || fallbackRoute.proxy == nil {
		t.Fatalf("match(/foo) = %#v, want fallback proxy route", fallbackRoute)
	}
}

func TestBuildRouteProxies_RedirectAndHandlerCoexistForSamePrefix(t *testing.T) {
	cfg := &Config{Routes: []Route{{
		Path:     "/",
		Redirect: "/polarion",
		Handler:  &Handler{Protocol: "http", Hostname: "example.com", Port: 80},
	}}}

	routes, err := buildRouteProxies(cfg, nil)
	if err != nil {
		t.Fatalf("buildRouteProxies() error = %v", err)
	}

	matcher := newRouteSet(routes).matcher
	rootRoute := matcher.match("/")
	if rootRoute == nil || rootRoute.redirectTarget != "/polarion" {
		t.Fatalf("match(/) = %#v, want redirect route for /", rootRoute)
	}

	fallbackRoute := matcher.match("/foo")
	if fallbackRoute == nil || fallbackRoute.proxy == nil {
		t.Fatalf("match(/foo) = %#v, want fallback proxy route", fallbackRoute)
	}
}

func TestTransportCacheKey_DiffersByTLSAndTarget(t *testing.T) {
	a := Handler{Protocol: "https", Hostname: "api.local", Port: 443, IPv4Addresses: []string{"127.0.0.1"}}
	b := Handler{Protocol: "https", Hostname: "api.local", Port: 443, IPv4Addresses: []string{"127.0.0.2"}}
	c := Handler{Protocol: "http", Hostname: "api.local", Port: 443, IPv4Addresses: []string{"127.0.0.1"}}

	if transportCacheKey(a, true) == transportCacheKey(b, true) {
		t.Fatal("cache key should differ for different backend IP sets")
	}
	if transportCacheKey(a, true) == transportCacheKey(c, true) {
		t.Fatal("cache key should differ for different protocols")
	}
	if transportCacheKey(a, true) == transportCacheKey(a, false) {
		t.Fatal("cache key should differ by HTTP/2 setting")
	}
	d := a
	d.AbortiveClose = true
	if transportCacheKey(a, true) == transportCacheKey(d, true) {
		t.Fatal("cache key should differ by abortive_close setting")
	}
}

func TestBuildRouteProxies_NormalizesTrailingSlashForMatching(t *testing.T) {
	cfg := &Config{Routes: []Route{{Path: "/foo/", Redirect: "https://example.com/foo"}}}
	routes, err := buildRouteProxies(cfg, nil)
	if err != nil {
		t.Fatalf("buildRouteProxies() error = %v", err)
	}

	m := newRouteSet(routes).matcher
	for _, path := range []string{"/foo", "/foo/", "/foo/bar"} {
		r := m.match(path)
		if r == nil {
			t.Fatalf("match(%q) returned nil", path)
		}
		if r.prefix != "/foo" {
			t.Fatalf("match(%q) = %q, want %q", path, r.prefix, "/foo")
		}
	}
}
