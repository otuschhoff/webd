package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRewriteLocationToRequestHTTPS_RewritesBackendAbsoluteRedirectToRelative(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://frontend.example.com/polarion", nil)

	got := rewriteLocationToRequestHTTPS("https://backend.example.com/polarion/", req, "backend.example.com")
	if got != "/polarion/" {
		t.Fatalf("rewriteLocationToRequestHTTPS() = %q, want %q", got, "/polarion/")
	}
}

func TestRewriteLocationToRequestHTTPS_PreservesQueryAndFragment(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://frontend.example.com/polarion", nil)

	got := rewriteLocationToRequestHTTPS("https://backend.example.com/polarion/?a=1#frag", req, "backend.example.com")
	if got != "/polarion/?a=1#frag" {
		t.Fatalf("rewriteLocationToRequestHTTPS() = %q, want %q", got, "/polarion/?a=1#frag")
	}
}

func TestRewriteLocationToRequestHTTPS_WithoutRequestContextSanitizesAbsoluteRedirect(t *testing.T) {
	got := rewriteLocationToRequestHTTPS("https://backend.example.com/polarion/", nil, "backend.example.com")
	if got != "/polarion/" {
		t.Fatalf("rewriteLocationToRequestHTTPS() = %q, want %q", got, "/polarion/")
	}
}
