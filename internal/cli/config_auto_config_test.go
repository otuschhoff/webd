package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAutoConfiguresFallbackRedirectRoute(t *testing.T) {
	oldLocalFQDNResolver := localFQDNResolver
	localFQDNResolver = func() (string, error) {
		return "host.eu.socionext.com", nil
	}
	defer func() {
		localFQDNResolver = oldLocalFQDNResolver
	}()

	tests := []struct {
		name     string
		contents string
	}{
		{name: "missing-file"},
		{name: "empty-file", contents: ""},
		{name: "no-routes", contents: "templates:\n  handler:\n    foo: http://example.com\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.name+".yaml")
			if tt.contents != "" {
				if err := os.WriteFile(path, []byte(tt.contents), 0o600); err != nil {
					t.Fatalf("write config: %v", err)
				}
			}

			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if len(cfg.Routes) != 1 {
				t.Fatalf("expected one route, got %d", len(cfg.Routes))
			}
			if cfg.Routes[0].Path != "/" {
				t.Fatalf("expected fallback path '/', got %q", cfg.Routes[0].Path)
			}
			if cfg.Routes[0].Redirect != "https://eu.socionext.com" {
				t.Fatalf("expected fallback redirect to https://eu.socionext.com, got %q", cfg.Routes[0].Redirect)
			}
		})
	}
}
