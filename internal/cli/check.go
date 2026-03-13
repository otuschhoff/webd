package cli

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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
)

type portProcessInfo struct {
	PID            int
	ExePath        string
	SystemdService string
	StartedAt      string
}

type checkResult struct {
	okLines   []string
	failLines []string
}

func runCheck(opts app.RunOptions) error {
	cfg, err := Load(opts.ConfigPath)
	if err != nil {
		return err
	}

	pretty, err := PrettyYAML(cfg)
	if err != nil {
		return err
	}
	fmt.Println(ColorizeYAML(pretty, os.Getenv("NO_COLOR") == ""))

	checkErrs := make([]string, 0)

	fmt.Println("-- port availability --")
	for _, result := range []checkResult{
		checkBindPort("http", opts.HTTPAddr),
		checkBindPort("https", opts.HTTPSAddr),
	} {
		for _, line := range result.okLines {
			fmt.Println(line)
		}
		checkErrs = append(checkErrs, result.failLines...)
	}

	fmt.Println("-- upstream reachability --")
	upstreamResults := checkUpstreams(cfg)
	for _, line := range upstreamResults.okLines {
		fmt.Println(line)
	}
	checkErrs = append(checkErrs, upstreamResults.failLines...)

	fmt.Println("-- tls validation --")
	tlsResults := checkTLSMaterials(opts.TLSCertPath, opts.TLSKeyPath)
	for _, line := range tlsResults.okLines {
		fmt.Println(line)
	}
	checkErrs = append(checkErrs, tlsResults.failLines...)

	if len(checkErrs) > 0 {
		return fmt.Errorf("check failed:\n- %s", strings.Join(checkErrs, "\n- "))
	}
	fmt.Println("check OK")
	return nil
}

func checkBindPort(label, addr string) checkResult {
	// Check existing listeners via /proc rather than bind attempts, so low ports can
	// be checked by non-root users without permission-denied false positives.
	_, portStr, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		portStr = strings.TrimPrefix(addr, ":")
	}
	port, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		return checkResult{failLines: []string{fmt.Sprintf("%s %s: port parse failed: %v", label, addr, convErr)}}
	}

	infos, lookupErr := findPortOwners(port)
	if lookupErr != nil {
		return checkResult{failLines: []string{fmt.Sprintf("%s %s: owner lookup failed: %v", label, addr, lookupErr)}}
	}
	if len(infos) == 0 {
		return checkResult{okLines: []string{fmt.Sprintf("%s %s: free", label, addr)}}
	}

	failLines := []string{fmt.Sprintf("%s %s is already bound", label, addr)}
	for _, info := range infos {
		failLines = append(failLines, fmt.Sprintf("%s %s owner: pid=%d exe=%s systemd=%s started=%s", label, addr, info.PID, info.ExePath, info.SystemdService, info.StartedAt))
	}
	return checkResult{failLines: failLines}
}

func checkUpstreams(cfg *Config) checkResult {
	seen := make(map[string]struct{})
	result := checkResult{}

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
			result.failLines = append(result.failLines, fmt.Sprintf("%s parse error: %v", raw, err))
			continue
		}

		hostPort := u.Host
		if u.Port() == "" {
			switch strings.ToLower(u.Scheme) {
			case "http":
			case "ws":
				hostPort = net.JoinHostPort(u.Hostname(), "80")
			case "https":
			case "wss":
				hostPort = net.JoinHostPort(u.Hostname(), "443")
			default:
				result.failLines = append(result.failLines, fmt.Sprintf("%s unsupported scheme %q", raw, u.Scheme))
				continue
			}
		}

		switch strings.ToLower(u.Scheme) {
		case "http", "ws":
			conn, err := net.DialTimeout("tcp", hostPort, 3*time.Second)
			if err != nil {
				result.failLines = append(result.failLines, fmt.Sprintf("%s TCP handshake failed: %v", raw, err))
				continue
			}
			_ = conn.Close()
			result.okLines = append(result.okLines, fmt.Sprintf("upstream %s: TCP handshake OK", raw))
		case "https", "wss":
			dialer := &net.Dialer{Timeout: 4 * time.Second}
			tlsConfig := &tls.Config{InsecureSkipVerify: true}
			if route.TrustedCA != nil {
				pool, poolErr := loadTrustedCAPool(route.TrustedCA.CertPath)
				if poolErr != nil {
					result.failLines = append(result.failLines, fmt.Sprintf("%s trusted_ca load failed: %v", raw, poolErr))
					continue
				}
				tlsConfig = &tls.Config{ServerName: u.Hostname(), RootCAs: pool}
			}
			conn, err := tls.DialWithDialer(dialer, "tcp", hostPort, tlsConfig)
			if err != nil {
				result.failLines = append(result.failLines, fmt.Sprintf("%s TLS handshake failed: %v", raw, err))
				continue
			}
			_ = conn.Close()
			result.okLines = append(result.okLines, fmt.Sprintf("upstream %s: TLS handshake OK", raw))
		default:
			result.failLines = append(result.failLines, fmt.Sprintf("%s unsupported scheme %q", raw, u.Scheme))
		}
	}

	return result
}

func loadTrustedCAPool(certPath string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", certPath, err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
		return nil, fmt.Errorf("no PEM certificates found in %s", certPath)
	}
	return pool, nil
}

func checkTLSMaterials(certPath, keyPath string) checkResult {
	result := checkResult{}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		result.failLines = append(result.failLines, fmt.Sprintf("tls cert read failed (%s): %v", certPath, err))
		return result
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		result.failLines = append(result.failLines, fmt.Sprintf("tls key read failed (%s): %v", keyPath, err))
		return result
	}

	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		result.failLines = append(result.failLines, fmt.Sprintf("tls cert/key mismatch or parse failure: %v", err))
	}

	certs, parseErr := parseCertificatesFromPEM(certPEM)
	if parseErr != nil {
		result.failLines = append(result.failLines, parseErr.Error())
		return result
	}

	leaf := certs[0]
	if len(certs) < 2 {
		result.failLines = append(result.failLines, "tls cert chain check failed: bundle must contain leaf cert followed by issuing sub-CA/intermediate cert")
	} else {
		if err := leaf.CheckSignatureFrom(certs[1]); err != nil {
			result.failLines = append(result.failLines, fmt.Sprintf("tls chain check failed: leaf cert is not signed by next cert in bundle: %v", err))
		}
	}

	for i := 0; i < len(certs)-1; i++ {
		child := certs[i]
		parent := certs[i+1]
		if !bytes.Equal(child.RawIssuer, parent.RawSubject) {
			result.failLines = append(result.failLines, fmt.Sprintf("tls chain ordering issue at position %d: issuer of cert[%d] does not match subject of cert[%d]", i, i, i+1))
			continue
		}
		if err := child.CheckSignatureFrom(parent); err != nil {
			result.failLines = append(result.failLines, fmt.Sprintf("tls chain signature check failed between cert[%d] and cert[%d]: %v", i, i+1, err))
		}
	}

	hostname, err := os.Hostname()
	if err != nil {
		result.failLines = append(result.failLines, fmt.Sprintf("tls SAN check failed: resolve local hostname: %v", err))
	} else {
		candidates := hostCandidates(hostname)
		matched := ""
		for _, candidate := range candidates {
			if verifyErr := leaf.VerifyHostname(candidate); verifyErr == nil {
				matched = candidate
				break
			}
		}
		if matched == "" {
			result.failLines = append(result.failLines, fmt.Sprintf("tls SAN mismatch: cert does not match this host (checked: %s)", strings.Join(candidates, ",")))
		} else {
			result.okLines = append(result.okLines, fmt.Sprintf("tls SAN check OK (matched host %q)", matched))
		}
	}

	if len(result.failLines) == 0 {
		result.okLines = append(result.okLines, fmt.Sprintf("tls cert/key check OK (certs=%d leaf_subject=%q)", len(certs), leaf.Subject.String()))
	}

	return result
}

func parseCertificatesFromPEM(certPEM []byte) ([]*x509.Certificate, error) {
	remaining := certPEM
	certs := make([]*x509.Certificate, 0)
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tls cert parse failed: %v", err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("tls cert parse failed: no CERTIFICATE blocks found")
	}
	return certs, nil
}

func hostCandidates(hostname string) []string {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return []string{"localhost"}
	}

	set := map[string]struct{}{}
	add := func(v string) {
		v = strings.TrimSpace(strings.TrimSuffix(v, "."))
		if v == "" {
			return
		}
		set[v] = struct{}{}
	}

	add(hostname)
	if strings.Contains(hostname, ".") {
		add(strings.SplitN(hostname, ".", 2)[0])
	}
	if cname, err := net.LookupCNAME(hostname); err == nil {
		add(cname)
	}

	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
