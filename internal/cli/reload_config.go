package cli

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type proxyRoute struct {
	PathPrefix string `yaml:"path_prefix" json:"path_prefix"`
	Upstream   string `yaml:"upstream" json:"upstream"`
}

type proxyConfig struct {
	Routes []proxyRoute `yaml:"routes" json:"routes"`
}

func loadConfig(path string) (*proxyConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg proxyConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s as yaml: %w", path, err)
	}

	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validateConfig(cfg *proxyConfig) error {
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
