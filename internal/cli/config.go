package cli

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"

	"webd/internal/app"
	"webd/internal/server"

	"gopkg.in/yaml.v3"
)

type TrustedCA struct {
	Name     string `yaml:"name" json:"name"`
	CertPath string `yaml:"cert_path" json:"cert_path"`
}

// Route maps a URL path prefix to an upstream base URL.
type Route struct {
	// PathPrefix is matched against the incoming request path.
	PathPrefix string `yaml:"path_prefix" json:"path_prefix"`
	// Upstream is the absolute HTTP/HTTPS/WS/WSS upstream base URL.
	Upstream string `yaml:"upstream,omitempty" json:"upstream,omitempty"`
	// Redirect is an absolute URL for HTTP 301 redirects when this route matches.
	// Exactly one of Upstream or Redirect must be set.
	Redirect string `yaml:"redirect,omitempty" json:"redirect,omitempty"`
	// AllowedIPv4 optionally restricts this route to specific IPv4 addresses, ranges, and/or CIDRs.
	AllowedIPv4 []string `yaml:"allowed_ipv4,omitempty" json:"allowed_ipv4,omitempty"`
	// TrustedCA identifies a PEM CA bundle that should verify this upstream TLS server.
	TrustedCA *TrustedCA `yaml:"trusted_ca,omitempty" json:"trusted_ca,omitempty"`
}

// Config is the root YAML configuration for reverse-proxy routes.
type Config struct {
	Routes []Route `yaml:"routes" json:"routes"`
}

// Load reads, parses, and validates a YAML configuration file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var sourceRaw any
	if err := yaml.Unmarshal(b, &sourceRaw); err != nil {
		return nil, fmt.Errorf("parse config %s as yaml: %w", path, err)
	}
	if err := app.ValidateSourceConfig(normalizeYAMLValue(sourceRaw)); err != nil {
		return nil, fmt.Errorf("validate config %s against json schema: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s as yaml: %w", path, err)
	}

	if err := Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// normalizeYAMLValue converts YAML-decoded maps into JSON-compatible map[string]any values.
func normalizeYAMLValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = normalizeYAMLValue(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[fmt.Sprint(k)] = normalizeYAMLValue(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = normalizeYAMLValue(item)
		}
		return out
	default:
		return v
	}
}

// Validate checks that the configuration contains valid route definitions.
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

		upstreamRaw := strings.TrimSpace(r.Upstream)
		redirectRaw := strings.TrimSpace(r.Redirect)
		hasUpstream := upstreamRaw != ""
		hasRedirect := redirectRaw != ""
		if hasUpstream == hasRedirect {
			return fmt.Errorf("exactly one of upstream or redirect must be set for prefix %q", prefix)
		}

		scheme := ""
		if hasUpstream {
			u, err := url.Parse(upstreamRaw)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return fmt.Errorf("invalid upstream for prefix %q: %q", prefix, r.Upstream)
			}
			scheme = strings.ToLower(strings.TrimSpace(u.Scheme))
			if scheme != "http" && scheme != "https" && scheme != "ws" && scheme != "wss" {
				return fmt.Errorf("invalid upstream scheme for prefix %q: %q", prefix, r.Upstream)
			}
		}
		if hasRedirect {
			u, err := url.Parse(redirectRaw)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return fmt.Errorf("invalid redirect for prefix %q: %q", prefix, r.Redirect)
			}
		}

		for _, raw := range r.AllowedIPv4 {
			if err := validateAllowedIPv4Entry(raw); err != nil {
				return fmt.Errorf("invalid allowed_ipv4 for prefix %q: %w", prefix, err)
			}
		}

		if r.TrustedCA != nil {
			if hasRedirect {
				return fmt.Errorf("trusted_ca cannot be used with redirect for prefix %q", prefix)
			}
			caName := strings.TrimSpace(r.TrustedCA.Name)
			if caName == "" {
				return fmt.Errorf("trusted_ca.name is required for prefix %q", prefix)
			}
			if !isTrustedCAName(caName) {
				return fmt.Errorf("trusted_ca.name must contain only letters, digits, dot, dash, or underscore for prefix %q: %q", prefix, caName)
			}
			if strings.TrimSpace(r.TrustedCA.CertPath) == "" {
				return fmt.Errorf("trusted_ca.cert_path is required for prefix %q", prefix)
			}
			if scheme != "https" && scheme != "wss" {
				return fmt.Errorf("trusted_ca is supported only for https and wss upstreams for prefix %q", prefix)
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

func translateAllowedIPv4(entries []string) ([]server.IPv4Range, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	ranges := make([]server.IPv4Range, 0, len(entries))
	for _, raw := range entries {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, fmt.Errorf("entry must not be empty")
		}

		if strings.Contains(value, "-") {
			parts := strings.SplitN(value, "-", 2)
			start, err := parseIPv4Address(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid range start in %q: %w", value, err)
			}
			end, err := parseIPv4Address(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid range end in %q: %w", value, err)
			}
			ranges = append(ranges, server.IPv4Range{Start: ipv4ToUint32(start), End: ipv4ToUint32(end)})
			continue
		}

		if strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q", value)
			}
			if !prefix.Addr().Is4() {
				return nil, fmt.Errorf("CIDR must be IPv4: %q", value)
			}
			masked := prefix.Masked()
			start := ipv4ToUint32(masked.Addr())
			bits := masked.Bits()
			hostMask := uint32(0)
			if bits < 32 {
				hostMask = (1 << uint32(32-bits)) - 1
			}
			ranges = append(ranges, server.IPv4Range{Start: start, End: start | hostMask})
			continue
		}

		addr, err := parseIPv4Address(value)
		if err != nil {
			return nil, fmt.Errorf("invalid IPv4 address %q", value)
		}
		value32 := ipv4ToUint32(addr)
		ranges = append(ranges, server.IPv4Range{Start: value32, End: value32})
	}

	return ranges, nil
}

func isTrustedCAName(name string) bool {
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_' {
			continue
		}
		return false
	}
	return true
}

// PrettyYAML renders the configuration back to normalized YAML.
func PrettyYAML(cfg *Config) (string, error) {
	pretty, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshal yaml config: %w", err)
	}
	return string(pretty), nil
}

// ColorizeYAML applies ANSI color to YAML output when enabled.
func ColorizeYAML(in string, useColor bool) string {
	if !useColor {
		return in
	}

	const (
		colorReset   = "\033[0m"
		colorCyan    = "\033[36m"
		colorYellow  = "\033[33m"
		colorGreen   = "\033[32m"
		colorMagenta = "\033[35m"
	)

	keyRe := regexp.MustCompile(`^(\s*)([a-zA-Z0-9_\-]+):(\s*)(.*)$`)
	numBoolNullRe := regexp.MustCompile(`^(-?[0-9][0-9eE+\.-]*|true|false|null)$`)

	lines := strings.Split(in, "\n")
	for i, line := range lines {
		line = strings.ReplaceAll(line, "- ", colorCyan+"- "+colorReset)
		if m := keyRe.FindStringSubmatch(line); len(m) == 5 {
			val := strings.TrimSpace(m[4])
			coloredVal := m[4]
			switch {
			case strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\""):
				coloredVal = m[3] + colorGreen + strings.TrimPrefix(m[4], m[3]) + colorReset
			case numBoolNullRe.MatchString(val):
				coloredVal = m[3] + colorMagenta + strings.TrimPrefix(m[4], m[3]) + colorReset
			case val != "":
				coloredVal = m[3] + colorGreen + strings.TrimPrefix(m[4], m[3]) + colorReset
			}
			line = m[1] + colorYellow + m[2] + colorReset + ":" + coloredVal
		}
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}
