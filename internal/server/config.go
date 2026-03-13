package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"httpsd/internal/schema"
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
	Redirect          string      `json:"redirect,omitempty"`
	Upstream          *Upstream   `json:"upstream,omitempty"`
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

	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse runtime config %s as json: %w", path, err)
	}
	if err := schema.ValidateRuntimeConfig(raw); err != nil {
		return nil, fmt.Errorf("validate runtime config %s against json schema: %w", path, err)
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

		redirect := strings.TrimSpace(r.Redirect)
		hasRedirect := redirect != ""
		hasUpstream := r.Upstream != nil
		if hasRedirect == hasUpstream {
			return fmt.Errorf("exactly one of upstream or redirect must be set for prefix %q", prefix)
		}
		if hasRedirect {
			u, err := url.Parse(redirect)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return fmt.Errorf("invalid redirect for prefix %q: %q", prefix, r.Redirect)
			}
		}

		for _, entry := range r.AllowedIPv4Ranges {
			if entry.Start > entry.End {
				return fmt.Errorf("invalid allowed_ipv4_ranges entry for prefix %q: start %d is greater than end %d", prefix, entry.Start, entry.End)
			}
		}

		if hasRedirect {
			continue
		}

		upstream := r.Upstream
		protocol := strings.ToLower(strings.TrimSpace(upstream.Protocol))
		if protocol != "http" && protocol != "https" && protocol != "ws" && protocol != "wss" {
			return fmt.Errorf("invalid upstream protocol for prefix %q: %q", prefix, upstream.Protocol)
		}
		if strings.TrimSpace(upstream.Hostname) == "" {
			return fmt.Errorf("upstream hostname is required for prefix %q", prefix)
		}
		if upstream.Port < 1 || upstream.Port > 65535 {
			return fmt.Errorf("upstream port must be between 1 and 65535 for prefix %q: %d", prefix, upstream.Port)
		}
		if path := strings.TrimSpace(upstream.Path); path != "" && !strings.HasPrefix(path, "/") {
			return fmt.Errorf("upstream path must begin with '/' for prefix %q: %q", prefix, upstream.Path)
		}
		if len(upstream.IPv4Addresses) == 0 {
			return fmt.Errorf("upstream ipv4_addresses must contain at least one address for prefix %q", prefix)
		}
		for _, rawIP := range upstream.IPv4Addresses {
			ip := net.ParseIP(strings.TrimSpace(rawIP))
			if ip == nil || ip.To4() == nil {
				return fmt.Errorf("invalid upstream IPv4 address for prefix %q: %q", prefix, rawIP)
			}
		}
		if upstream.TrustedCA != nil {
			if protocol != "https" && protocol != "wss" {
				return fmt.Errorf("trusted_ca is supported only for https and wss upstreams for prefix %q", prefix)
			}
			if strings.TrimSpace(upstream.TrustedCA.Name) == "" || strings.TrimSpace(upstream.TrustedCA.File) == "" {
				return fmt.Errorf("trusted_ca name and file are required for prefix %q", prefix)
			}
		}
	}
	return nil
}
