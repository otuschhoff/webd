package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"webd/internal/app"
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

// Route maps a URL path prefix to a decomposed handler definition for runtime usage.
type Route struct {
	Path              string      `json:"path"`
	AllowedIPv4Ranges []IPv4Range `json:"allowed_ipv4_ranges,omitempty"`
	Redirect          string      `json:"redirect,omitempty"`
	Handler           *Upstream   `json:"handler,omitempty"`
}

// Config is the runtime JSON configuration consumed by the webd daemon.
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
	if err := app.ValidateRuntimeConfig(raw); err != nil {
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
		prefix := strings.TrimSpace(r.Path)
		if prefix == "" {
			prefix = "/"
		}
		if !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("path must begin with '/': %q", prefix)
		}

		redirect := strings.TrimSpace(r.Redirect)
		hasRedirect := redirect != ""
		hasHandler := r.Handler != nil
		if hasRedirect == hasHandler {
			return fmt.Errorf("exactly one of handler or redirect must be set for path %q", prefix)
		}
		if hasRedirect {
			u, err := url.Parse(redirect)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return fmt.Errorf("invalid redirect for path %q: %q", prefix, r.Redirect)
			}
		}

		for _, entry := range r.AllowedIPv4Ranges {
			if entry.Start > entry.End {
				return fmt.Errorf("invalid allowed_ipv4_ranges entry for path %q: start %d is greater than end %d", prefix, entry.Start, entry.End)
			}
		}

		if hasRedirect {
			continue
		}

		handler := r.Handler
		protocol := strings.ToLower(strings.TrimSpace(handler.Protocol))
		if protocol != "http" && protocol != "https" && protocol != "ws" && protocol != "wss" {
			return fmt.Errorf("invalid handler protocol for path %q: %q", prefix, handler.Protocol)
		}
		if strings.TrimSpace(handler.Hostname) == "" {
			return fmt.Errorf("handler hostname is required for path %q", prefix)
		}
		if handler.Port < 1 || handler.Port > 65535 {
			return fmt.Errorf("handler port must be between 1 and 65535 for path %q: %d", prefix, handler.Port)
		}
		if path := strings.TrimSpace(handler.Path); path != "" && !strings.HasPrefix(path, "/") {
			return fmt.Errorf("handler path must begin with '/' for path %q: %q", prefix, handler.Path)
		}
		if len(handler.IPv4Addresses) == 0 {
			return fmt.Errorf("handler ipv4_addresses must contain at least one address for path %q", prefix)
		}
		for _, rawIP := range handler.IPv4Addresses {
			ip := net.ParseIP(strings.TrimSpace(rawIP))
			if ip == nil || ip.To4() == nil {
				return fmt.Errorf("invalid handler IPv4 address for path %q: %q", prefix, rawIP)
			}
		}
		if handler.TrustedCA != nil {
			if protocol != "https" && protocol != "wss" {
				return fmt.Errorf("trusted_ca is supported only for https and wss handlers for path %q", prefix)
			}
			if strings.TrimSpace(handler.TrustedCA.Name) == "" || strings.TrimSpace(handler.TrustedCA.File) == "" {
				return fmt.Errorf("trusted_ca name and file are required for path %q", prefix)
			}
		}
	}
	return nil
}
