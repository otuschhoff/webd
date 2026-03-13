package server

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Route maps a URL path prefix to an upstream base URL for runtime usage.
type Route struct {
	PathPrefix string `json:"path_prefix"`
	Upstream   string `json:"upstream"`
}

// Config is the runtime JSON configuration consumed by the httpsd daemon.
type Config struct {
	Routes []Route `json:"routes"`
}

// LoadJSON reads, parses, and validates a runtime JSON configuration file.
func LoadJSON(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read runtime config %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse runtime config %s as json: %w", path, err)
	}

	if err := Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks that the runtime config contains valid route definitions.
func Validate(cfg *Config) error {
	if len(cfg.Routes) == 0 {
		return fmt.Errorf("config must contain at least one route")
	}

	for _, r := range cfg.Routes {
		prefix := strings.TrimSpace(r.PathPrefix)
		if prefix == "" {
			prefix = "/"
		}
		if !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("path_prefix must begin with '/': %q", prefix)
		}

		u, err := url.Parse(r.Upstream)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("invalid upstream for prefix %q: %q", prefix, r.Upstream)
		}
	}
	return nil
}
