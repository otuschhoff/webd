package server

import (
	"fmt"
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
