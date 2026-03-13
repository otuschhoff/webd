package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

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
	PathPrefix  string   `json:"path_prefix"`
	AllowedIPv4 []string `json:"allowed_ipv4,omitempty"`
	Upstream    Upstream `json:"upstream"`
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
		if protocol != "http" && protocol != "https" {
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
		for _, raw := range r.AllowedIPv4 {
			if err := validateAllowedIPv4Entry(raw); err != nil {
				return fmt.Errorf("invalid allowed_ipv4 for prefix %q: %w", prefix, err)
			}
		}
		if r.Upstream.TrustedCA != nil {
			if protocol != "https" {
				return fmt.Errorf("trusted_ca is supported only for https upstreams for prefix %q", prefix)
			}
			if strings.TrimSpace(r.Upstream.TrustedCA.Name) == "" || strings.TrimSpace(r.Upstream.TrustedCA.File) == "" {
				return fmt.Errorf("trusted_ca name and file are required for prefix %q", prefix)
			}
		}
	}
	return nil
}

func validateAllowedIPv4Entry(raw string) error {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fmt.Errorf("entry must not be empty")
	}

	if strings.Contains(value, "-") {
		parts := strings.SplitN(value, "-", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid range %q", value)
		}
		start, err := parseIPv4Address(parts[0])
		if err != nil {
			return fmt.Errorf("invalid range start in %q: %w", value, err)
		}
		end, err := parseIPv4Address(parts[1])
		if err != nil {
			return fmt.Errorf("invalid range end in %q: %w", value, err)
		}
		if ipv4ToUint32(start) > ipv4ToUint32(end) {
			return fmt.Errorf("range start is greater than range end in %q", value)
		}
		return nil
	}

	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q", value)
		}
		if !prefix.Addr().Is4() {
			return fmt.Errorf("CIDR must be IPv4: %q", value)
		}
		return nil
	}

	if _, err := parseIPv4Address(value); err != nil {
		return fmt.Errorf("invalid IPv4 address %q", value)
	}
	return nil
}

func parseIPv4Address(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, err
	}
	if !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("must be IPv4")
	}
	return addr, nil
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
