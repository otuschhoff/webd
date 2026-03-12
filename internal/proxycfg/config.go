package proxycfg

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type Route struct {
	PathPrefix string `json:"path_prefix"`
	Upstream   string `json:"upstream"`
}

type Config struct {
	Routes []Route `json:"routes"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
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

func PrettyJSON(cfg *Config) (string, error) {
	pretty, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal pretty config: %w", err)
	}
	return string(pretty), nil
}

func ColorizeJSON(in string, useColor bool) string {
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

	keyRe := regexp.MustCompile(`^(\s*)"([^"]+)"(\s*:)`)
	strValRe := regexp.MustCompile(`(:\s*)"([^"]*)"`)
	numBoolNullRe := regexp.MustCompile(`(:\s*)(-?[0-9][0-9eE+\.-]*|true|false|null)`)

	lines := strings.Split(in, "\n")
	for i, line := range lines {
		line = strings.ReplaceAll(line, "{", colorCyan+"{"+colorReset)
		line = strings.ReplaceAll(line, "}", colorCyan+"}"+colorReset)
		line = strings.ReplaceAll(line, "[", colorCyan+"["+colorReset)
		line = strings.ReplaceAll(line, "]", colorCyan+"]"+colorReset)
		line = keyRe.ReplaceAllString(line, `$1`+colorYellow+`"$2"`+colorReset+`$3`)
		line = strValRe.ReplaceAllString(line, `$1`+colorGreen+`"$2"`+colorReset)
		line = numBoolNullRe.ReplaceAllString(line, `$1`+colorMagenta+`$2`+colorReset)
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}
