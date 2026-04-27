package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"webd/internal/app"
)

type IPv4Range struct {
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}

type TrustedCA struct {
	Name    string `json:"name"`
	File    string `json:"file"`
	PinCert bool   `json:"pin_cert,omitempty"`
}

type RewriteLocation struct {
	Match   string `json:"match"`
	Replace string `json:"replace"`
}

type Handler struct {
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
	Path              string           `json:"path"`
	AllowedIPv4Ranges []IPv4Range      `json:"allowed_ipv4_ranges,omitempty"`
	Browse            bool             `json:"browse,omitempty"`
	Redirect          string           `json:"redirect,omitempty"`
	Handler           *Handler         `json:"handler,omitempty"`
	WebsocketHandler  *Handler         `json:"websocket_handler,omitempty"`
	RewriteLocation   *RewriteLocation `json:"rewrite_location,omitempty"`
	RewriteBaseHref   *bool            `json:"rewrite_base_href,omitempty"`
}

// Config is the runtime JSON configuration consumed by the webd daemon.
type Config struct {
	Routes []Route `json:"routes"`
}

// LoadJSON reads, parses, and validates a runtime JSON configuration file.
// If the file does not exist, it returns an empty config (for ACME-only mode).
func LoadJSON(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Allow missing config for ACME-only mode (no routes needed)
			return &Config{Routes: []Route{}}, nil
		}
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
// If config is empty (ACME-only mode), validation passes.
func Validate(cfg *Config) error {
	if len(cfg.Routes) == 0 {
		// Allow zero routes for ACME-only mode (serving challenges only)
		return nil
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
			if r.Browse {
				return fmt.Errorf("browse cannot be used with redirect for path %q", prefix)
			}
			if r.RewriteLocation != nil {
				return fmt.Errorf("rewrite_location cannot be used with redirect for path %q", prefix)
			}
			if r.RewriteBaseHref != nil {
				return fmt.Errorf("rewrite_base_href cannot be used with redirect for path %q", prefix)
			}
			continue
		}

		handler := r.Handler
		protocol := strings.ToLower(strings.TrimSpace(handler.Protocol))
		if protocol != "http" && protocol != "https" && protocol != "ws" && protocol != "wss" && protocol != "file" {
			return fmt.Errorf("invalid handler protocol for path %q: %q", prefix, handler.Protocol)
		}

		if protocol == "file" {
			if strings.TrimSpace(handler.Path) == "" || !filepath.IsAbs(handler.Path) {
				return fmt.Errorf("file handler path must be absolute for path %q: %q", prefix, handler.Path)
			}
			if strings.TrimSpace(handler.Hostname) != "" {
				return fmt.Errorf("file handler hostname must be empty for path %q", prefix)
			}
			if handler.Port != 0 {
				return fmt.Errorf("file handler port must be 0 for path %q", prefix)
			}
			if len(handler.IPv4Addresses) != 0 {
				return fmt.Errorf("file handler ipv4_addresses must be empty for path %q", prefix)
			}
			if handler.TrustedCA != nil {
				return fmt.Errorf("trusted_ca is not supported for file handlers for path %q", prefix)
			}
			if r.RewriteLocation != nil {
				return fmt.Errorf("rewrite_location is not supported for file handlers for path %q", prefix)
			}
			if r.RewriteBaseHref != nil {
				return fmt.Errorf("rewrite_base_href is not supported for file handlers for path %q", prefix)
			}
			continue
		}

		if r.Browse {
			return fmt.Errorf("browse is supported only for file handlers for path %q", prefix)
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

		if r.RewriteLocation != nil {
			match := strings.TrimSpace(r.RewriteLocation.Match)
			if match == "" {
				return fmt.Errorf("rewrite_location.match is required for path %q", prefix)
			}
			if _, err := regexp.Compile(normalizeRegexPattern(match)); err != nil {
				return fmt.Errorf("invalid rewrite_location.match regex for path %q: %w", prefix, err)
			}
		}

		if r.WebsocketHandler != nil {
			wsh := r.WebsocketHandler
			wsProtocol := strings.ToLower(strings.TrimSpace(wsh.Protocol))
			if wsProtocol != "http" && wsProtocol != "https" && wsProtocol != "ws" && wsProtocol != "wss" {
				return fmt.Errorf("invalid websocket_handler protocol for path %q: %q", prefix, wsh.Protocol)
			}
			if strings.TrimSpace(wsh.Hostname) == "" {
				return fmt.Errorf("websocket_handler hostname is required for path %q", prefix)
			}
			if wsh.Port < 1 || wsh.Port > 65535 {
				return fmt.Errorf("websocket_handler port must be between 1 and 65535 for path %q: %d", prefix, wsh.Port)
			}
			if len(wsh.IPv4Addresses) == 0 {
				return fmt.Errorf("websocket_handler ipv4_addresses must contain at least one address for path %q", prefix)
			}
			for _, rawIP := range wsh.IPv4Addresses {
				ip := net.ParseIP(strings.TrimSpace(rawIP))
				if ip == nil || ip.To4() == nil {
					return fmt.Errorf("invalid websocket_handler IPv4 address for path %q: %q", prefix, rawIP)
				}
			}
			if wsh.TrustedCA != nil {
				if wsProtocol != "https" && wsProtocol != "wss" {
					return fmt.Errorf("websocket_handler trusted_ca is supported only for https and wss for path %q", prefix)
				}
				if strings.TrimSpace(wsh.TrustedCA.Name) == "" || strings.TrimSpace(wsh.TrustedCA.File) == "" {
					return fmt.Errorf("websocket_handler trusted_ca name and file are required for path %q", prefix)
				}
			}
		}
	}
	return nil
}

func normalizeRegexPattern(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) >= 2 && strings.HasPrefix(trimmed, "/") && strings.HasSuffix(trimmed, "/") {
		return trimmed[1 : len(trimmed)-1]
	}
	return trimmed
}
