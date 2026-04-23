package server

import "testing"

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

func TestTransportCacheKey_DiffersByTLSAndTarget(t *testing.T) {
	a := Handler{Protocol: "https", Hostname: "api.local", Port: 443, IPv4Addresses: []string{"127.0.0.1"}}
	b := Handler{Protocol: "https", Hostname: "api.local", Port: 443, IPv4Addresses: []string{"127.0.0.2"}}
	c := Handler{Protocol: "http", Hostname: "api.local", Port: 443, IPv4Addresses: []string{"127.0.0.1"}}

	if transportCacheKey(a) == transportCacheKey(b) {
		t.Fatal("cache key should differ for different backend IP sets")
	}
	if transportCacheKey(a) == transportCacheKey(c) {
		t.Fatal("cache key should differ for different protocols")
	}
}
