package cli

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"httpsd/internal/app"
	"httpsd/internal/proxycfg"
)

type portProcessInfo struct {
	PID            int
	ExePath        string
	SystemdService string
	StartedAt      string
}

func runCheck(opts app.RunOptions) error {
	cfg, err := proxycfg.Load(opts.ConfigPath)
	if err != nil {
		return err
	}

	pretty, err := proxycfg.PrettyYAML(cfg)
	if err != nil {
		return err
	}
	fmt.Println(proxycfg.ColorizeYAML(pretty, os.Getenv("NO_COLOR") == ""))

	checkErrs := make([]string, 0)

	fmt.Println("-- port availability --")
	if err := checkBindPort("http", opts.HTTPAddr); err != nil {
		checkErrs = append(checkErrs, err.Error())
	}
	if err := checkBindPort("https", opts.HTTPSAddr); err != nil {
		checkErrs = append(checkErrs, err.Error())
	}

	fmt.Println("-- upstream reachability --")
	if err := checkUpstreams(cfg); err != nil {
		checkErrs = append(checkErrs, err.Error())
	}

	if len(checkErrs) > 0 {
		return fmt.Errorf("check failed:\n- %s", strings.Join(checkErrs, "\n- "))
	}
	fmt.Println("check OK")
	return nil
}

func checkBindPort(label, addr string) error {
	// Check existing listeners via /proc rather than bind attempts, so low ports can
	// be checked by non-root users without permission-denied false positives.
	_, portStr, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		portStr = strings.TrimPrefix(addr, ":")
	}
	port, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		return fmt.Errorf("%s %s: port parse failed: %v", label, addr, convErr)
	}

	infos, lookupErr := findPortOwners(port)
	if lookupErr != nil {
		return fmt.Errorf("%s %s: owner lookup failed: %v", label, addr, lookupErr)
	}
	if len(infos) == 0 {
		fmt.Printf("%s %s: free\n", label, addr)
		return nil
	}

	fmt.Printf("%s %s: in use\n", label, addr)
	for _, info := range infos {
		fmt.Printf("  pid=%d exe=%s systemd=%s started=%s\n", info.PID, info.ExePath, info.SystemdService, info.StartedAt)
	}
	return fmt.Errorf("%s %s is already bound", label, addr)
}

func checkUpstreams(cfg *proxycfg.Config) error {
	seen := make(map[string]struct{})
	failed := make([]string, 0)

	for _, route := range cfg.Routes {
		raw := strings.TrimSpace(route.Upstream)
		if raw == "" {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}

		u, err := url.Parse(raw)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s parse error: %v", raw, err))
			continue
		}

		hostPort := u.Host
		if u.Port() == "" {
			switch strings.ToLower(u.Scheme) {
			case "http":
				hostPort = net.JoinHostPort(u.Hostname(), "80")
			case "https":
				hostPort = net.JoinHostPort(u.Hostname(), "443")
			default:
				failed = append(failed, fmt.Sprintf("%s unsupported scheme %q", raw, u.Scheme))
				continue
			}
		}

		switch strings.ToLower(u.Scheme) {
		case "http":
			conn, err := net.DialTimeout("tcp", hostPort, 3*time.Second)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s TCP handshake failed: %v", raw, err))
				continue
			}
			_ = conn.Close()
			fmt.Printf("upstream %s: TCP handshake OK\n", raw)
		case "https":
			dialer := &net.Dialer{Timeout: 4 * time.Second}
			conn, err := tls.DialWithDialer(dialer, "tcp", hostPort, &tls.Config{InsecureSkipVerify: true})
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s TLS handshake failed: %v", raw, err))
				continue
			}
			_ = conn.Close()
			fmt.Printf("upstream %s: TLS handshake OK\n", raw)
		default:
			failed = append(failed, fmt.Sprintf("%s unsupported scheme %q", raw, u.Scheme))
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("upstream checks failed:\n  - %s", strings.Join(failed, "\n  - "))
	}
	return nil
}

func findPortOwners(port int) ([]portProcessInfo, error) {
	inodes, err := listeningInodesForPort(port)
	if err != nil {
		return nil, err
	}
	if len(inodes) == 0 {
		return nil, nil
	}

	pids, err := pidsForSocketInodes(inodes)
	if err != nil {
		return nil, err
	}
	infos := make([]portProcessInfo, 0, len(pids))
	for _, pid := range pids {
		infos = append(infos, portProcessInfo{
			PID:            pid,
			ExePath:        readProcessExe(pid),
			SystemdService: readProcessSystemdService(pid),
			StartedAt:      readProcessStartTime(pid),
		})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].PID < infos[j].PID })
	return infos, nil
}

func listeningInodesForPort(port int) (map[string]struct{}, error) {
	inodes := make(map[string]struct{})
	files := []string{"/proc/net/tcp", "/proc/net/tcp6"}
	portHex := strings.ToUpper(fmt.Sprintf("%04X", port))

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", file, err)
		}
		scanner := bufio.NewScanner(f)
		first := true
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if first {
				first = false
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			localAddr := fields[1]
			state := fields[3]
			inode := fields[9]
			parts := strings.Split(localAddr, ":")
			if len(parts) != 2 {
				continue
			}
			if strings.ToUpper(parts[1]) != portHex {
				continue
			}
			if state != "0A" {
				continue
			}
			inodes[inode] = struct{}{}
		}
		if err := scanner.Err(); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("scan %s: %w", file, err)
		}
		_ = f.Close()
	}

	return inodes, nil
}

func pidsForSocketInodes(inodes map[string]struct{}) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	seen := make(map[int]struct{})
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			linkPath := filepath.Join(fdDir, fd.Name())
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}
			if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if _, ok := inodes[inode]; ok {
				seen[pid] = struct{}{}
				break
			}
		}
	}

	pids := make([]int, 0, len(seen))
	for pid := range seen {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	return pids, nil
}

func readProcessExe(pid int) string {
	exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return "unknown"
	}
	return exe
}

func readProcessSystemdService(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "-"
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, ".service") {
			parts := strings.Split(line, "/")
			for i := len(parts) - 1; i >= 0; i-- {
				if strings.HasSuffix(parts[i], ".service") {
					return parts[i]
				}
			}
		}
	}
	return "-"
}

func readProcessStartTime(pid int) string {
	statPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	b, err := os.ReadFile(statPath)
	if err != nil {
		return "unknown"
	}
	line := string(b)
	idx := strings.LastIndex(line, ")")
	if idx == -1 || idx+2 >= len(line) {
		return "unknown"
	}
	fields := strings.Fields(line[idx+2:])
	if len(fields) < 20 {
		return "unknown"
	}
	startTicks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return "unknown"
	}
	clkTck := int64(100)
	if out, err := execCommand("getconf", "CLK_TCK"); err == nil {
		if v, convErr := strconv.ParseInt(strings.TrimSpace(out), 10, 64); convErr == nil && v > 0 {
			clkTck = v
		}
	}
	bootTime, err := readBootTimeUnix()
	if err != nil {
		return "unknown"
	}
	started := time.Unix(bootTime+startTicks/clkTck, 0).UTC()
	return started.Format(time.RFC3339)
}

func readBootTimeUnix() (int64, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "btime ") {
			parts := strings.Fields(line)
			if len(parts) != 2 {
				break
			}
			v, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				break
			}
			return v, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("btime not found in /proc/stat")
}

func execCommand(name string, args ...string) (string, error) {
	b, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", err
	}
	return string(b), nil
}
