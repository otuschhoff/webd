package server

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

type IPv4Range struct {
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}

type TrustedCA struct {
	Name string `json:"name"`
	File string `json:"file"`
}

type Upstream struct {
	Protocol      string     `json:"protocol"`
	Hostname      string     `json:"hostname"`
	Port          int        `json:"port"`
	Path          string     `json:"path,omitempty"`
	RawQuery      string     `json:"raw_query,omitempty"`
	IPv4Addresses []string   `json:"ipv4_addresses"`
	TrustedCA     *TrustedCA `json:"trusted_ca,omitempty"`
}

// Route maps a URL path prefix to a decomposed upstream definition for runtime usage.
type Route struct {
	PathPrefix        string      `json:"path_prefix"`
	AllowedIPv4Ranges []IPv4Range `json:"allowed_ipv4_ranges,omitempty"`
	Upstream          Upstream    `json:"upstream"`
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

		protocol := strings.ToLower(strings.TrimSpace(r.Upstream.Protocol))
		if protocol != "http" && protocol != "https" && protocol != "ws" && protocol != "wss" {
			return fmt.Errorf("invalid upstream protocol for prefix %q: %q", prefix, r.Upstream.Protocol)
		}
		if strings.TrimSpace(r.Upstream.Hostname) == "" {
			return fmt.Errorf("upstream hostname is required for prefix %q", prefix)
		}
		if r.Upstream.Port < 1 || r.Upstream.Port > 65535 {
			return fmt.Errorf("upstream port must be between 1 and 65535 for prefix %q: %d", prefix, r.Upstream.Port)
		}
		if path := strings.TrimSpace(r.Upstream.Path); path != "" && !strings.HasPrefix(path, "/") {
			return fmt.Errorf("upstream path must begin with '/' for prefix %q: %q", prefix, r.Upstream.Path)
		}
		if len(r.Upstream.IPv4Addresses) == 0 {
			return fmt.Errorf("upstream ipv4_addresses must contain at least one address for prefix %q", prefix)
		}
		for _, rawIP := range r.Upstream.IPv4Addresses {
			ip := net.ParseIP(strings.TrimSpace(rawIP))
			if ip == nil || ip.To4() == nil {
				return fmt.Errorf("invalid upstream IPv4 address for prefix %q: %q", prefix, rawIP)
			}
		}
		for _, entry := range r.AllowedIPv4Ranges {
			if entry.Start > entry.End {
				return fmt.Errorf("invalid allowed_ipv4_ranges entry for prefix %q: start %d is greater than end %d", prefix, entry.Start, entry.End)
			}
		}
		if r.Upstream.TrustedCA != nil {
			if protocol != "https" && protocol != "wss" {
				return fmt.Errorf("trusted_ca is supported only for https and wss upstreams for prefix %q", prefix)
			}
			if strings.TrimSpace(r.Upstream.TrustedCA.Name) == "" || strings.TrimSpace(r.Upstream.TrustedCA.File) == "" {
				return fmt.Errorf("trusted_ca name and file are required for prefix %q", prefix)
			}
		}
	}
	return nil
}
