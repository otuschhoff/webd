package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	reloadTimerServiceName   = "webd-local-tls-update.service"
	reloadTimerUnitName      = "webd-local-tls-update.timer"
	reloadTimerServicePath   = "/etc/systemd/system/" + reloadTimerServiceName
	reloadTimerUnitPath      = "/etc/systemd/system/" + reloadTimerUnitName
	defaultReloadTimerPeriod = "1d"
)

func runReloadTimerAdd(interval string) error {
	if err := ensureReloadTimerRoot("add"); err != nil {
		return err
	}

	seconds, err := parseHumanInterval(interval)
	if err != nil {
		return fmt.Errorf("parse interval %q: %w", interval, err)
	}

	serviceContent := buildReloadTimerServiceUnit()
	timerContent := buildReloadTimerUnit(seconds)

	serviceChanged, err := ensureUnitFileIfAbsent(reloadTimerServicePath, serviceContent)
	if err != nil {
		return err
	}
	timerChanged, err := ensureUnitFileIfAbsent(reloadTimerUnitPath, timerContent)
	if err != nil {
		return err
	}

	if serviceChanged || timerChanged {
		if err := daemonReload(); err != nil {
			return err
		}
		fmt.Println("systemd daemon-reload completed")
	} else {
		fmt.Println("reload-timer unit files already exist; leaving definitions unchanged")
	}

	if _, err := runSystemctl("enable", "--now", reloadTimerUnitName); err != nil {
		return err
	}
	fmt.Printf("enabled and started %s\n", reloadTimerUnitName)

	return runReloadTimerShow()
}

func runReloadTimerModify(interval string) error {
	if err := ensureReloadTimerRoot("modify"); err != nil {
		return err
	}

	seconds, err := parseHumanInterval(interval)
	if err != nil {
		return fmt.Errorf("parse interval %q: %w", interval, err)
	}

	if _, err := os.Stat(reloadTimerUnitPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("timer %s is not installed; run `webctl reload-timer add` first", reloadTimerUnitName)
		}
		return fmt.Errorf("stat %s: %w", reloadTimerUnitPath, err)
	}

	serviceChanged, err := writeUnitFileIfChanged(reloadTimerServicePath, buildReloadTimerServiceUnit())
	if err != nil {
		return err
	}
	timerChanged, err := writeUnitFileIfChanged(reloadTimerUnitPath, buildReloadTimerUnit(seconds))
	if err != nil {
		return err
	}

	if serviceChanged || timerChanged {
		if err := daemonReload(); err != nil {
			return err
		}
		fmt.Println("systemd daemon-reload completed")
	}

	if _, err := runSystemctl("enable", "--now", reloadTimerUnitName); err != nil {
		return err
	}
	if _, err := runSystemctl("restart", reloadTimerUnitName); err != nil {
		return err
	}

	if serviceChanged || timerChanged {
		fmt.Printf("updated %s interval and restarted timer\n", reloadTimerUnitName)
	} else {
		fmt.Printf("timer %s already matches requested interval\n", reloadTimerUnitName)
	}

	return runReloadTimerShow()
}

func runReloadTimerDelete() error {
	if err := ensureReloadTimerRoot("delete"); err != nil {
		return err
	}

	if _, err := runSystemctl("disable", "--now", reloadTimerUnitName); err != nil && !isUnitNotFoundError(err) {
		return err
	}

	removedAny := false
	for _, path := range []string{reloadTimerUnitPath, reloadTimerServicePath} {
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
	}

	if !removedAny {
		fmt.Println("reload-timer files were already absent")
	}
	return nil
}

func runReloadTimerShow() error {
	fmt.Printf("timer unit: %s\n", reloadTimerUnitPath)
	fmt.Printf("service unit: %s\n", reloadTimerServicePath)

	timerExists := fileExists(reloadTimerUnitPath)
	serviceExists := fileExists(reloadTimerServicePath)
	fmt.Printf("timer file exists: %t\n", timerExists)
	fmt.Printf("service file exists: %t\n", serviceExists)

	if timerExists {
		interval, err := configuredReloadTimerInterval(reloadTimerUnitPath)
		if err != nil {
			return err
		}
		fmt.Printf("configured interval: %s\n", interval)
	}

	out, err := runSystemctl(
		"show",
		reloadTimerUnitName,
		"--property=LoadState",
		"--property=UnitFileState",
		"--property=ActiveState",
		"--property=SubState",
		"--property=NextElapseUSecRealtime",
		"--property=LastTriggerUSec",
	)
	if err != nil {
		if isUnitNotFoundError(err) {
			fmt.Printf("systemd status: unit %s not loaded\n", reloadTimerUnitName)
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

func ensureReloadTimerRoot(action string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("reload-timer %s must be run as root because it manages systemd system units", action)
	}
	return nil
}

func ensureUnitFileIfAbsent(path, content string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, fmt.Errorf("create systemd directory for %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return false, fmt.Errorf("write unit file %s: %w", path, err)
	}
	return true, nil
}

func writeUnitFileIfChanged(path, content string) (bool, error) {
	existing, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return false, fmt.Errorf("create systemd directory for %s: %w", path, err)
			}
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				return false, fmt.Errorf("write unit file %s: %w", path, err)
			}
			return true, nil
		}
		return false, fmt.Errorf("read unit file %s: %w", path, err)
	}

	if string(existing) == content {
		return false, nil
	}

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return false, fmt.Errorf("write unit file %s: %w", path, err)
	}
	return true, nil
}

func configuredReloadTimerInterval(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "OnUnitActiveSec=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "OnUnitActiveSec=")), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan %s: %w", path, err)
	}

	return "", fmt.Errorf("timer file %s has no OnUnitActiveSec", path)
}

func buildReloadTimerServiceUnit() string {
	return fmt.Sprintf(`[Unit]
Description=Refresh staged local TLS materials for webd and trigger reload when certificates changed
Documentation=man:systemd.timer(5)

[Service]
Type=oneshot
User=root
Group=root
ExecStart=%s reload --only-local-tls
`, DefaultWebctlPath)
}

func buildReloadTimerUnit(intervalSeconds int64) string {
	return fmt.Sprintf(`[Unit]
Description=Periodic local TLS certificate/key update check for webd runtime staging and reload
Documentation=man:systemd.timer(5)

[Timer]
OnBootSec=5m
OnUnitActiveSec=%ds
Persistent=true
Unit=%s

[Install]
WantedBy=timers.target
`, intervalSeconds, reloadTimerServiceName)
}

func parseHumanInterval(input string) (int64, error) {
	value := strings.TrimSpace(strings.ToLower(input))
	if value == "" {
		return 0, fmt.Errorf("interval must not be empty")
	}

	tokenRe := regexp.MustCompile(`([0-9]+)([dhms])`)
	matches := tokenRe.FindAllStringSubmatchIndex(value, -1)
	if len(matches) > 0 {
		consumed := 0
		var total int64
		for _, m := range matches {
			if m[0] != consumed {
				return 0, fmt.Errorf("invalid interval format")
			}
			amountStr := value[m[2]:m[3]]
			unit := value[m[4]:m[5]]
			consumed = m[1]

			amount, err := strconv.ParseInt(amountStr, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("parse interval amount %q: %w", amountStr, err)
			}
			if amount <= 0 {
				return 0, fmt.Errorf("interval components must be > 0")
			}

			var mul int64
			switch unit {
			case "d":
				mul = 24 * 60 * 60
			case "h":
				mul = 60 * 60
			case "m":
				mul = 60
			case "s":
				mul = 1
			default:
				return 0, fmt.Errorf("unsupported interval unit %q", unit)
			}

			if amount > (1<<63-1)/mul {
				return 0, fmt.Errorf("interval is too large")
			}
			total += amount * mul
		}

		if consumed != len(value) {
			return 0, fmt.Errorf("invalid interval format")
		}
		if total <= 0 {
			return 0, fmt.Errorf("interval must be > 0")
		}
		return total, nil
	}

	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid interval; use values like 10m, 1h, 12h, 1d")
	}
	if d <= 0 {
		return 0, fmt.Errorf("interval must be > 0")
	}
	return int64(d / time.Second), nil
}

func runSystemctl(args ...string) (string, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "", fmt.Errorf("systemctl not found in PATH")
	}

	cmd := exec.Command("systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed == "" {
			trimmed = err.Error()
		}
		return "", fmt.Errorf("systemctl %s failed: %s", strings.Join(args, " "), trimmed)
	}

	return string(out), nil
}

func isUnitNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "no such file") || strings.Contains(msg, "not loaded")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
