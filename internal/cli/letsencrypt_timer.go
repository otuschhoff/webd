package cli

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	letsEncryptTimerServiceName        = "webd-letsencrypt-renew.service"
	letsEncryptTimerUnitName           = "webd-letsencrypt-renew.timer"
	letsEncryptTimerServicePath        = "/etc/systemd/system/" + letsEncryptTimerServiceName
	letsEncryptTimerUnitPath           = "/etc/systemd/system/" + letsEncryptTimerUnitName
	letsEncryptTimerConfigPath         = "/etc/webd/letsencrypt-timer.json"
	defaultLetsEncryptTimerInterval    = "1d"
	defaultLetsEncryptTimerRenewBefore = "10d"
)

// LetsEncryptTimerOptions controls setup of the periodic certificate renewal check.
type LetsEncryptTimerOptions struct {
	Interval    string
	RenewBefore string
	ConfigFile  string
	LetsEncrypt LetsEncryptOptions
}

type letsEncryptTimerConfig struct {
	Interval    string            `json:"interval"`
	RenewBefore string            `json:"renew_before"`
	LetsEncrypt LetsEncryptConfig `json:"letsencrypt"`
}

type LetsEncryptConfig struct {
	Host         string  `json:"host"`
	Email        string  `json:"email"`
	DirectoryURL string  `json:"directory_url"`
	ChallengeDir string  `json:"challenge_dir"`
	CertPath     string  `json:"cert_path"`
	KeyPath      string  `json:"key_path"`
	Deploy       bool    `json:"deploy"`
	Reload       Options `json:"reload"`
}

func defaultLetsEncryptTimerOptions() LetsEncryptTimerOptions {
	return LetsEncryptTimerOptions{
		Interval:    defaultLetsEncryptTimerInterval,
		RenewBefore: defaultLetsEncryptTimerRenewBefore,
		ConfigFile:  letsEncryptTimerConfigPath,
		LetsEncrypt: defaultLetsEncryptOptions(),
	}
}

func runLetsEncryptTimerAdd(opts LetsEncryptTimerOptions) error {
	if err := ensureLetsEncryptTimerRoot("add"); err != nil {
		return err
	}

	intervalDuration, err := parseLetsEncryptTimerDuration(opts.Interval)
	if err != nil {
		return fmt.Errorf("parse interval %q: %w", opts.Interval, err)
	}
	if _, err := parseLetsEncryptTimerDuration(opts.RenewBefore); err != nil {
		return fmt.Errorf("parse renew-before %q: %w", opts.RenewBefore, err)
	}

	if fileExists(letsEncryptTimerUnitPath) || fileExists(letsEncryptTimerServicePath) || fileExists(opts.ConfigFile) {
		return fmt.Errorf("letsencrypt-timer is already installed; run `webctl letsencrypt-timer modify` or `webctl letsencrypt-timer list`")
	}

	serviceContent := buildLetsEncryptTimerServiceUnit(opts.ConfigFile)
	timerContent := buildLetsEncryptTimerUnit(int64(intervalDuration / time.Second))

	if _, err := ensureUnitFileIfAbsent(letsEncryptTimerServicePath, serviceContent); err != nil {
		return err
	}
	if _, err := ensureUnitFileIfAbsent(letsEncryptTimerUnitPath, timerContent); err != nil {
		return err
	}

	cfg := letsEncryptTimerConfigFromOptions(opts)
	if _, err := writeLetsEncryptTimerConfig(opts.ConfigFile, cfg, false); err != nil {
		return err
	}

	if err := daemonReload(); err != nil {
		return err
	}
	fmt.Println("systemd daemon-reload completed")

	if _, err := runSystemctl("enable", "--now", letsEncryptTimerUnitName); err != nil {
		return err
	}
	fmt.Printf("enabled and started %s\n", letsEncryptTimerUnitName)

	return runLetsEncryptTimerList()
}

func runLetsEncryptTimerModify(opts LetsEncryptTimerOptions) error {
	if err := ensureLetsEncryptTimerRoot("modify"); err != nil {
		return err
	}

	intervalDuration, err := parseLetsEncryptTimerDuration(opts.Interval)
	if err != nil {
		return fmt.Errorf("parse interval %q: %w", opts.Interval, err)
	}
	if _, err := parseLetsEncryptTimerDuration(opts.RenewBefore); err != nil {
		return fmt.Errorf("parse renew-before %q: %w", opts.RenewBefore, err)
	}

	if !fileExists(letsEncryptTimerUnitPath) {
		return fmt.Errorf("timer %s is not installed; run `webctl letsencrypt-timer add` first", letsEncryptTimerUnitName)
	}

	serviceChanged, err := writeUnitFileIfChanged(letsEncryptTimerServicePath, buildLetsEncryptTimerServiceUnit(opts.ConfigFile))
	if err != nil {
		return err
	}
	timerChanged, err := writeUnitFileIfChanged(letsEncryptTimerUnitPath, buildLetsEncryptTimerUnit(int64(intervalDuration/time.Second)))
	if err != nil {
		return err
	}

	cfg := letsEncryptTimerConfigFromOptions(opts)
	configChanged, err := writeLetsEncryptTimerConfig(opts.ConfigFile, cfg, true)
	if err != nil {
		return err
	}

	if serviceChanged || timerChanged || configChanged {
		if err := daemonReload(); err != nil {
			return err
		}
		fmt.Println("systemd daemon-reload completed")
	}

	if _, err := runSystemctl("enable", "--now", letsEncryptTimerUnitName); err != nil {
		return err
	}
	if _, err := runSystemctl("restart", letsEncryptTimerUnitName); err != nil {
		return err
	}

	if serviceChanged || timerChanged || configChanged {
		fmt.Printf("updated %s configuration and restarted timer\n", letsEncryptTimerUnitName)
	} else {
		fmt.Printf("timer %s already matches requested settings\n", letsEncryptTimerUnitName)
	}

	return runLetsEncryptTimerList()
}

func runLetsEncryptTimerDelete() error {
	if err := ensureLetsEncryptTimerRoot("delete"); err != nil {
		return err
	}

	if _, err := runSystemctl("disable", "--now", letsEncryptTimerUnitName); err != nil && !isUnitNotFoundError(err) {
		return err
	}

	removedAny := false
	for _, path := range []string{letsEncryptTimerUnitPath, letsEncryptTimerServicePath, letsEncryptTimerConfigPath} {
		if err := os.Remove(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("remove %s: %w", path, err)
		}
		removedAny = true
		fmt.Printf("removed %s\n", path)
	}

	if removedAny {
		if err := daemonReload(); err != nil {
			return err
		}
		fmt.Println("systemd daemon-reload completed")
	} else {
		fmt.Println("letsencrypt-timer files were already absent")
	}

	return nil
}

func runLetsEncryptTimerList() error {
	fmt.Printf("timer unit: %s\n", letsEncryptTimerUnitPath)
	fmt.Printf("service unit: %s\n", letsEncryptTimerServicePath)
	fmt.Printf("config file: %s\n", letsEncryptTimerConfigPath)

	timerExists := fileExists(letsEncryptTimerUnitPath)
	serviceExists := fileExists(letsEncryptTimerServicePath)
	configExists := fileExists(letsEncryptTimerConfigPath)
	fmt.Printf("timer file exists: %t\n", timerExists)
	fmt.Printf("service file exists: %t\n", serviceExists)
	fmt.Printf("config file exists: %t\n", configExists)

	if timerExists {
		interval, err := configuredReloadTimerInterval(letsEncryptTimerUnitPath)
		if err != nil {
			return err
		}
		fmt.Printf("configured interval: %s\n", interval)
	}

	if configExists {
		cfg, err := loadLetsEncryptTimerConfig(letsEncryptTimerConfigPath)
		if err != nil {
			return err
		}
		fmt.Printf("renew-before threshold: %s\n", cfg.RenewBefore)
		fmt.Printf("letsencrypt host: %s\n", displayValue(cfg.LetsEncrypt.Host, "(auto local FQDN)"))
		fmt.Printf("letsencrypt email: %s\n", displayValue(cfg.LetsEncrypt.Email, "(auto it@<domain>)"))
		fmt.Printf("letsencrypt directory-url: %s\n", cfg.LetsEncrypt.DirectoryURL)
		fmt.Printf("letsencrypt challenge-dir: %s\n", cfg.LetsEncrypt.ChallengeDir)
		fmt.Printf("letsencrypt cert-path: %s\n", cfg.LetsEncrypt.CertPath)
		fmt.Printf("letsencrypt key-path: %s\n", cfg.LetsEncrypt.KeyPath)
		fmt.Printf("letsencrypt deploy: %t\n", cfg.LetsEncrypt.Deploy)
		fmt.Printf("reload config source: %s\n", cfg.LetsEncrypt.Reload.ConfigSource)
		fmt.Printf("reload http-addr: %s\n", cfg.LetsEncrypt.Reload.HTTPAddr)
		fmt.Printf("reload https-addr: %s\n", cfg.LetsEncrypt.Reload.HTTPSAddr)
		fmt.Printf("reload tls-cert dest: %s\n", cfg.LetsEncrypt.Reload.TLSCertDest)
		fmt.Printf("reload tls-key dest: %s\n", cfg.LetsEncrypt.Reload.TLSKeyDest)
		fmt.Printf("reload run-user: %s\n", cfg.LetsEncrypt.Reload.RunUser)
	}

	out, err := runSystemctl(
		"show",
		letsEncryptTimerUnitName,
		"--property=LoadState",
		"--property=UnitFileState",
		"--property=ActiveState",
		"--property=SubState",
		"--property=NextElapseUSecRealtime",
		"--property=LastTriggerUSec",
	)
	if err != nil {
		if isUnitNotFoundError(err) {
			fmt.Printf("systemd status: unit %s not loaded\n", letsEncryptTimerUnitName)
			return nil
		}
		return err
	}

	fmt.Println("systemd state:")
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		fmt.Printf("  %s\n", trimmed)
	}

	return nil
}

func runLetsEncryptTimerRun(configPath string) error {
	if err := ensureLetsEncryptTimerRoot("run"); err != nil {
		return err
	}

	cfg, err := loadLetsEncryptTimerConfig(configPath)
	if err != nil {
		return err
	}

	threshold, err := parseLetsEncryptTimerDuration(cfg.RenewBefore)
	if err != nil {
		return fmt.Errorf("parse renew-before %q: %w", cfg.RenewBefore, err)
	}

	host := strings.TrimSpace(cfg.LetsEncrypt.Host)
	if host == "" {
		host, err = localFQDN()
		if err != nil {
			return fmt.Errorf("resolve local fqdn: %w", err)
		}
	}
	checkCertPath := strings.TrimSpace(cfg.LetsEncrypt.CertPath)
	if checkCertPath == "" {
		checkCertPath = defaultLetsEncryptActiveCertPath(host)
	}

	notAfter, err := readLeafCertificateNotAfter(checkCertPath)
	if err == nil {
		remaining := time.Until(notAfter)
		if remaining > threshold {
			fmt.Printf("certificate at %s is valid until %s (%s remaining); threshold %s not reached\n", checkCertPath, notAfter.UTC().Format(time.RFC3339), remaining.Round(time.Second), threshold.Round(time.Second))
			return nil
		}
		fmt.Printf("certificate at %s expires at %s (%s remaining), threshold is %s; requesting renewal\n", checkCertPath, notAfter.UTC().Format(time.RFC3339), remaining.Round(time.Second), threshold.Round(time.Second))
	} else {
		fmt.Printf("could not read existing certificate at %s (%v); requesting renewal\n", checkCertPath, err)
	}

	opts := LetsEncryptOptions{
		Host:         cfg.LetsEncrypt.Host,
		Email:        cfg.LetsEncrypt.Email,
		DirectoryURL: cfg.LetsEncrypt.DirectoryURL,
		ChallengeDir: cfg.LetsEncrypt.ChallengeDir,
		CertPath:     cfg.LetsEncrypt.CertPath,
		KeyPath:      cfg.LetsEncrypt.KeyPath,
		Deploy:       cfg.LetsEncrypt.Deploy,
		Reload:       cfg.LetsEncrypt.Reload,
	}
	return RunLetsEncrypt(opts)
}

func ensureLetsEncryptTimerRoot(action string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("letsencrypt-timer %s must be run as root because it manages systemd system units and TLS paths", action)
	}
	return nil
}

func letsEncryptTimerConfigFromOptions(opts LetsEncryptTimerOptions) letsEncryptTimerConfig {
	return letsEncryptTimerConfig{
		Interval:    strings.TrimSpace(opts.Interval),
		RenewBefore: strings.TrimSpace(opts.RenewBefore),
		LetsEncrypt: LetsEncryptConfig{
			Host:         strings.TrimSpace(opts.LetsEncrypt.Host),
			Email:        strings.TrimSpace(opts.LetsEncrypt.Email),
			DirectoryURL: strings.TrimSpace(opts.LetsEncrypt.DirectoryURL),
			ChallengeDir: strings.TrimSpace(opts.LetsEncrypt.ChallengeDir),
			CertPath:     strings.TrimSpace(opts.LetsEncrypt.CertPath),
			KeyPath:      strings.TrimSpace(opts.LetsEncrypt.KeyPath),
			Deploy:       opts.LetsEncrypt.Deploy,
			Reload:       opts.LetsEncrypt.Reload,
		},
	}
}

func writeLetsEncryptTimerConfig(path string, cfg letsEncryptTimerConfig, allowReplace bool) (bool, error) {
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal letsencrypt timer config: %w", err)
	}
	body = append(body, '\n')

	if !allowReplace {
		if _, err := os.Stat(path); err == nil {
			return false, fmt.Errorf("config %s already exists", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("stat %s: %w", path, err)
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, fmt.Errorf("create config directory for %s: %w", path, err)
	}
	changed, err := writeFileAtomic(path, body, 0o640)
	if err != nil {
		return false, fmt.Errorf("write letsencrypt timer config %s: %w", path, err)
	}
	return changed, nil
}

func loadLetsEncryptTimerConfig(path string) (letsEncryptTimerConfig, error) {
	var cfg letsEncryptTimerConfig

	content, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(content, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}

	if strings.TrimSpace(cfg.RenewBefore) == "" {
		cfg.RenewBefore = defaultLetsEncryptTimerRenewBefore
	}
	if strings.TrimSpace(cfg.Interval) == "" {
		cfg.Interval = defaultLetsEncryptTimerInterval
	}
	if strings.TrimSpace(cfg.LetsEncrypt.DirectoryURL) == "" {
		cfg.LetsEncrypt.DirectoryURL = defaultLetsEncryptOptions().DirectoryURL
	}
	if strings.TrimSpace(cfg.LetsEncrypt.ChallengeDir) == "" {
		cfg.LetsEncrypt.ChallengeDir = defaultLetsEncryptOptions().ChallengeDir
	}
	if strings.TrimSpace(cfg.LetsEncrypt.Reload.ConfigSource) == "" {
		cfg.LetsEncrypt.Reload = defaultLetsEncryptOptions().Reload
	}

	return cfg, nil
}

func buildLetsEncryptTimerServiceUnit(configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Renew Let's Encrypt certificate for webd when the configured expiry threshold is reached
Documentation=man:systemd.timer(5)

[Service]
Type=oneshot
User=root
Group=root
ExecStart=%s letsencrypt-timer run --config-file %s
`, DefaultWebctlPath, configPath)
}

func buildLetsEncryptTimerUnit(intervalSeconds int64) string {
	return fmt.Sprintf(`[Unit]
Description=Periodic Let's Encrypt renewal threshold check for webd
Documentation=man:systemd.timer(5)

[Timer]
OnBootSec=10m
OnUnitActiveSec=%ds
Persistent=true
Unit=%s

[Install]
WantedBy=timers.target
`, intervalSeconds, letsEncryptTimerServiceName)
}

func parseLetsEncryptTimerDuration(input string) (time.Duration, error) {
	value := strings.TrimSpace(strings.ToLower(input))
	if value == "" {
		return 0, fmt.Errorf("duration must not be empty")
	}

	tokenRe := regexp.MustCompile(`([0-9]+)(min|m|w|d|h|s)`)
	matches := tokenRe.FindAllStringSubmatchIndex(value, -1)
	if len(matches) == 0 {
		return 0, fmt.Errorf("invalid duration; use values like 10d, 1w, 2m, 12h, 30min")
	}

	consumed := 0
	var total time.Duration
	for _, m := range matches {
		if m[0] != consumed {
			return 0, fmt.Errorf("invalid duration format")
		}
		amountStr := value[m[2]:m[3]]
		unit := value[m[4]:m[5]]
		consumed = m[1]

		amount, err := strconv.ParseInt(amountStr, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse duration amount %q: %w", amountStr, err)
		}
		if amount <= 0 {
			return 0, fmt.Errorf("duration components must be > 0")
		}

		var mul time.Duration
		switch unit {
		case "m":
			mul = 30 * 24 * time.Hour
		case "w":
			mul = 7 * 24 * time.Hour
		case "d":
			mul = 24 * time.Hour
		case "h":
			mul = time.Hour
		case "min":
			mul = time.Minute
		case "s":
			mul = time.Second
		default:
			return 0, fmt.Errorf("unsupported unit %q", unit)
		}

		if amount > int64((1<<63-1)/int64(mul)) {
			return 0, fmt.Errorf("duration is too large")
		}
		total += time.Duration(amount) * mul
	}

	if consumed != len(value) {
		return 0, fmt.Errorf("invalid duration format")
	}
	if total <= 0 {
		return 0, fmt.Errorf("duration must be > 0")
	}
	return total, nil
}

func readLeafCertificateNotAfter(certPath string) (time.Time, error) {
	content, err := os.ReadFile(certPath)
	if err != nil {
		return time.Time{}, err
	}

	for len(content) > 0 {
		var block *pem.Block
		block, content = pem.Decode(content)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse cert: %w", err)
		}
		return cert.NotAfter, nil
	}

	return time.Time{}, fmt.Errorf("no PEM certificate found")
}

func displayValue(value, fallback string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return fallback
	}
	return v
}

func defaultLetsEncryptActiveCertPath(host string) string {
	fqdn := strings.TrimSuffix(strings.TrimSpace(host), ".")
	if fqdn == "" {
		return "/etc/pki/tls/certs/self.crt"
	}
	return filepath.Join("/etc/pki/tls/certs", fqdn+".crt")
}
