package cli

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"webd/internal/app"
	"webd/internal/server"

	"gopkg.in/yaml.v3"
)

type TrustedCA struct {
	Name     string `yaml:"name" json:"name"`
	CertPath string `yaml:"cert_path" json:"cert_path"`
}

type Templates struct {
	IPv4    map[string][]string `yaml:"ipv4,omitempty" json:"ipv4,omitempty"`
	Handler map[string]string   `yaml:"handler,omitempty" json:"handler,omitempty"`
}

// Route maps a URL path prefix to a handler base URL.
type Route struct {
	// Path is matched against the incoming request path.
	Path string `yaml:"path" json:"path"`
	// Handler is the absolute HTTP/HTTPS/WS/WSS/file handler URL.
	Handler string `yaml:"handler,omitempty" json:"handler,omitempty"`
	// Redirect is an absolute URL for HTTP 301 redirects when this route matches.
	// Exactly one of Handler or Redirect must be set.
	Redirect string `yaml:"redirect,omitempty" json:"redirect,omitempty"`
	// AllowedIPv4 optionally restricts this route to specific IPv4 addresses, ranges, and/or CIDRs.
	AllowedIPv4 []string `yaml:"allowed_ipv4,omitempty" json:"allowed_ipv4,omitempty"`
	// Browse enables directory listing when a file:// handler maps to a directory path.
	Browse bool `yaml:"browse,omitempty" json:"browse,omitempty"`
	// Insecure enables endpoint certificate pinning for https/wss handlers.
	Insecure bool `yaml:"insecure,omitempty" json:"insecure,omitempty"`
	// TrustedCA identifies a PEM CA bundle that should verify this handler TLS server.
	TrustedCA *TrustedCA `yaml:"trusted_ca,omitempty" json:"trusted_ca,omitempty"`
}

// Config is the root YAML configuration for reverse-proxy routes.
type Config struct {
	Templates *Templates `yaml:"templates,omitempty" json:"templates,omitempty"`
	Routes    []Route    `yaml:"routes" json:"routes"`
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

	if err := resolveTemplates(&cfg); err != nil {
		return nil, err
	}

	if err := Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

var handlerTemplateRefRe = regexp.MustCompile(`\$\{\s*([A-Za-z0-9_.-]+)\s*\}`)
var ipv4TemplateRefRe = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}`)

func resolveTemplates(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	ipv4Templates := map[string][]string{}
	handlerTemplates := map[string]string{}
	if cfg.Templates != nil {
		ipv4Templates = cfg.Templates.IPv4
		handlerTemplates = cfg.Templates.Handler
	}

	if err := validateTemplateNames(ipv4Templates, "templates.ipv4"); err != nil {
		return err
	}
	if err := validateTemplateNames(handlerTemplates, "templates.handler"); err != nil {
		return err
	}
	if _, reserved := handlerTemplates["path"]; reserved {
		return fmt.Errorf("templates.handler template name %q is reserved", "path")
	}

	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		routePathTemplate := routePathTemplateValue(r.Path)

		resolvedHandler, err := resolveHandlerTemplateRefs(r.Handler, handlerTemplates, routePathTemplate)
		if err != nil {
			return fmt.Errorf("route path=%q handler template expansion failed: %w", strings.TrimSpace(r.Path), err)
		}
		r.Handler = resolvedHandler

		resolvedIPv4, err := resolveIPv4TemplateRefs(r.AllowedIPv4, ipv4Templates)
		if err != nil {
			return fmt.Errorf("route path=%q allowed_ipv4 template expansion failed: %w", strings.TrimSpace(r.Path), err)
		}
		r.AllowedIPv4 = resolvedIPv4
	}

	return nil
}

func routePathTemplateValue(routePath string) string {
	trimmed := strings.TrimSpace(routePath)
	if trimmed == "" || trimmed == "/" {
		return ""
	}
	return strings.TrimPrefix(trimmed, "/")
}

func validateTemplateNames[T any](m map[string]T, section string) error {
	for name := range m {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%s template name must not be empty", section)
		}
		if !templateRefNameOK(name) {
			return fmt.Errorf("%s template name %q contains unsupported characters", section, name)
		}
	}
	return nil
}

func templateRefNameOK(name string) bool {
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

func resolveHandlerTemplateRefs(handler string, templates map[string]string, routePathValue string) (string, error) {
	raw := strings.TrimSpace(handler)
	if raw == "" {
		return handler, nil
	}

	// Shorthand: if handler exactly matches a template name, expand it as
	// <template>/<path> where <path> omits the leading '/'.
	if base, ok := templates[raw]; ok {
		return appendPathSuffix(base, routePathValue), nil
	}

	missing := make([]string, 0)
	resolved := handlerTemplateRefRe.ReplaceAllStringFunc(raw, func(match string) string {
		parts := handlerTemplateRefRe.FindStringSubmatch(match)
		if len(parts) != 2 {
			return match
		}
		name := parts[1]
		if name == "path" {
			return routePathValue
		}
		value, ok := templates[name]
		if !ok {
			missing = append(missing, name)
			return match
		}
		return value
	})

	if len(missing) > 0 {
		sort.Strings(missing)
		return "", fmt.Errorf("unknown handler template(s): %s", strings.Join(uniqueStrings(missing), ", "))
	}

	return resolved, nil
}

func appendPathSuffix(base, pathSuffix string) string {
	base = strings.TrimSpace(base)
	if pathSuffix == "" {
		return base
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(pathSuffix, "/")
}

func resolveIPv4TemplateRefs(entries []string, templates map[string][]string) ([]string, error) {
	if len(entries) == 0 {
		return entries, nil
	}

	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		name, ok := parseTemplateRef(entry)
		if !ok {
			bare := strings.TrimSpace(entry)
			if _, exists := templates[bare]; exists {
				name = bare
				ok = true
			}
		}
		if !ok {
			out = append(out, entry)
			continue
		}
		values, exists := templates[name]
		if !exists {
			return nil, fmt.Errorf("unknown ipv4 template %q", name)
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("ipv4 template %q is empty", name)
		}
		out = append(out, values...)
	}
	return out, nil
}

func parseTemplateRef(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	m := ipv4TemplateRefRe.FindStringSubmatch(trimmed)
	if len(m) != 2 {
		return "", false
	}
	if m[0] != trimmed {
		return "", false
	}
	return m[1], true
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	last := ""
	for i, s := range in {
		if i == 0 || s != last {
			out = append(out, s)
		}
		last = s
	}
	return out
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
		prefix := strings.TrimSpace(r.Path)
		if prefix == "" {
			prefix = "/"
		}
		if !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("path must begin with '/': %q", prefix)
		}

		handlerRaw := strings.TrimSpace(r.Handler)
		redirectRaw := strings.TrimSpace(r.Redirect)
		hasHandler := handlerRaw != ""
		hasRedirect := redirectRaw != ""
		if hasHandler == hasRedirect {
			return fmt.Errorf("exactly one of handler or redirect must be set for path %q", prefix)
		}

		scheme := ""
		if hasHandler {
			u, err := url.Parse(handlerRaw)
			if err != nil || u.Scheme == "" {
				return fmt.Errorf("invalid handler for path %q: %q", prefix, r.Handler)
			}
			scheme = strings.ToLower(strings.TrimSpace(u.Scheme))
			if scheme != "http" && scheme != "https" && scheme != "ws" && scheme != "wss" && scheme != "file" {
				return fmt.Errorf("invalid handler scheme for path %q: %q", prefix, r.Handler)
			}
			if scheme == "file" {
				host := strings.TrimSpace(u.Host)
				if host != "" && host != "localhost" {
					return fmt.Errorf("file handler host must be empty or localhost for path %q: %q", prefix, r.Handler)
				}
				if strings.TrimSpace(u.Path) == "" || !filepath.IsAbs(u.Path) {
					return fmt.Errorf("file handler path must be absolute for path %q: %q", prefix, r.Handler)
				}
			} else if strings.TrimSpace(u.Host) == "" {
				return fmt.Errorf("invalid handler for path %q: %q", prefix, r.Handler)
			}
		}
		if hasRedirect {
			u, err := url.Parse(redirectRaw)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return fmt.Errorf("invalid redirect for path %q: %q", prefix, r.Redirect)
			}
		}

		for _, raw := range r.AllowedIPv4 {
			if err := validateAllowedIPv4Entry(raw); err != nil {
				return fmt.Errorf("invalid allowed_ipv4 for path %q: %w", prefix, err)
			}
		}

		if r.TrustedCA != nil {
			if hasRedirect {
				return fmt.Errorf("trusted_ca cannot be used with redirect for path %q", prefix)
			}
			caName := strings.TrimSpace(r.TrustedCA.Name)
			if caName == "" {
				return fmt.Errorf("trusted_ca.name is required for path %q", prefix)
			}
			if !isTrustedCAName(caName) {
				return fmt.Errorf("trusted_ca.name must contain only letters, digits, dot, dash, or underscore for path %q: %q", prefix, caName)
			}
			if strings.TrimSpace(r.TrustedCA.CertPath) == "" {
				return fmt.Errorf("trusted_ca.cert_path is required for path %q", prefix)
			}
			if scheme != "https" && scheme != "wss" {
				return fmt.Errorf("trusted_ca is supported only for https and wss handlers for path %q", prefix)
			}
		}

		if r.Insecure {
			if hasRedirect {
				return fmt.Errorf("insecure cannot be used with redirect for path %q", prefix)
			}
			if scheme != "https" && scheme != "wss" {
				return fmt.Errorf("insecure is supported only for https and wss handlers for path %q", prefix)
			}
			if r.TrustedCA != nil {
				return fmt.Errorf("insecure cannot be combined with trusted_ca for path %q", prefix)
			}
		}

		if r.Browse && scheme != "file" {
			return fmt.Errorf("browse is supported only for file handlers for path %q", prefix)
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
