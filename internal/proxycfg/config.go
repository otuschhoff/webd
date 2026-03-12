package proxycfg

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Route struct {
	PathPrefix string `yaml:"path_prefix"`
	Upstream   string `yaml:"upstream"`
}

type Config struct {
	Routes []Route `yaml:"routes"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if err := Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

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

func PrettyYAML(cfg *Config) (string, error) {
	pretty, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshal yaml config: %w", err)
	}
	return string(pretty), nil
}

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
