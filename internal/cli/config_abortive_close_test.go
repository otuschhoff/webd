package cli

import "testing"

func TestValidate_AbortiveCloseWithRedirectRejected(t *testing.T) {
	cfg := &Config{Routes: []Route{{
		Path:          "/",
		Redirect:      "https://example.com/",
		AbortiveClose: true,
	}}}
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate() expected error, got nil")
	}
}

func TestValidate_AbortiveCloseWithFileHandlerRejected(t *testing.T) {
	cfg := &Config{Routes: []Route{{
		Path:          "/static/",
		Handler:       "file:///var/www/static",
		AbortiveClose: true,
	}}}
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate() expected error, got nil")
	}
}

func TestValidate_AbortiveCloseWithHTTPHandlerAllowed(t *testing.T) {
	cfg := &Config{Routes: []Route{{
		Path:          "/api/",
		Handler:       "http://127.0.0.1:8080/",
		AbortiveClose: true,
	}}}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}
