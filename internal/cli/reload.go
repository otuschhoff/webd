package cli

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"httpsd/internal/app"
	"httpsd/internal/server"
	"httpsd/internal/syslogx"
)

// Options controls root helper behavior for staging runtime TLS artifacts and
// signaling running httpsd processes.
type Options struct {
	HTTPAddr      string
	HTTPSAddr     string
	RunUser       string
	ConfigSource  string
	ConfigDest    string
	TLSCertSource string
	TLSKeySource  string
	TLSCertDest   string
	TLSKeyDest    string
	PrepareOnly   bool
}

// DefaultOptions returns defaults for the reload helper workflow.
func DefaultOptions() Options {
	return Options{
		HTTPAddr:      app.DefaultHTTPAddr,
		HTTPSAddr:     app.DefaultHTTPSAddr,
		RunUser:       app.DefaultRunUser,
		ConfigSource:  app.DefaultConfigPath,
		ConfigDest:    app.DefaultRuntimeConfigPath,
		TLSCertSource: app.DefaultTLSSourceCertPath,
		TLSKeySource:  app.DefaultTLSSourceKeyPath,
		TLSCertDest:   app.DefaultRuntimeTLSCertPath,
		TLSKeyDest:    app.DefaultRuntimeTLSKeyPath,
		PrepareOnly:   false,
	}
}

// Run locates running httpsd processes and sends them SIGHUP for in-place reload.
func Run(opts Options) error {
	logs, err := syslogx.NewForCommand("httpsdctl", false)
	if err != nil {
		return fmt.Errorf("setup syslog loggers: %w", err)
	}
	defer func() {
		_ = logs.Close()
	}()
	opsLog := logs.Ops
	errLog := logs.Error

	if os.Geteuid() != 0 {
		return fmt.Errorf("reload helper must run as root because it stages TLS artifacts under /run and updates ownership")
	}

	runUID, runGID, err := lookupRunUser(opts.RunUser)
	if err != nil {
		errLog.Printf("reload run-user lookup failed user=%q err=%v", opts.RunUser, err)
		return err
	}

	if err := validateRunTLSDirs(opts); err != nil {
		errLog.Printf("reload runtime-dir validation failed err=%v", err)
		return err
	}
	if err := ensureRuntimeTLSDir(opts, runUID, runGID); err != nil {
		errLog.Printf("reload runtime-dir ensure failed err=%v", err)
		return err
	}
	if err := ensureRuntimeDevLogBindMount(opts, runUID, runGID); err != nil {
		errLog.Printf("reload dev-log bind mount ensure failed err=%v", err)
		return err
	}

	var pids []int
	if !opts.PrepareOnly {
		pids, err = findHTTPSDPIDs()
		if err != nil {
			errLog.Printf("reload process discovery failed err=%v", err)
			return err
		}
		if len(pids) == 0 {
			return fmt.Errorf("no running httpsd process found")
		}

		if err := ensurePortsBoundByHTTPSD(opts.HTTPAddr, opts.HTTPSAddr, pids); err != nil {
			errLog.Printf("reload active-port validation failed err=%v", err)
			return err
		}
	}

	if err := stageTLSArtifacts(opts, runUID, runGID); err != nil {
		errLog.Printf("reload staging failed err=%v", err)
		return err
	}
	opsLog.Printf("staged runtime artifacts config=%s cert=%s key=%s owner=%s", opts.ConfigDest, opts.TLSCertDest, opts.TLSKeyDest, opts.RunUser)

	if opts.PrepareOnly {
		opsLog.Printf("prepare-only mode complete")
		return nil
	}

	sent := 0
	for _, pid := range pids {
		if killErr := syscall.Kill(pid, syscall.SIGHUP); killErr != nil {
			errLog.Printf("reload signal failed pid=%d err=%v", pid, killErr)
			continue
		}
		sent++
		opsLog.Printf("sent SIGHUP to pid=%d", pid)
	}

	if sent == 0 {
		return fmt.Errorf("could not signal any running httpsd process")
	}
	return nil
}

func ensureRuntimeDevLogBindMount(opts Options, uid, gid int) error {
	runtimeDir := filepath.Clean(filepath.Dir(opts.TLSCertDest))
	devDir := filepath.Join(runtimeDir, "dev")
	target := filepath.Join(devDir, "log")

	if err := os.MkdirAll(devDir, 0o750); err != nil {
		return fmt.Errorf("create runtime dev directory %s: %w", devDir, err)
	}
	if err := os.Chown(devDir, uid, gid); err != nil {
		return fmt.Errorf("chown runtime dev directory %s: %w", devDir, err)
	}
	if err := os.Chmod(devDir, 0o750); err != nil {
		return fmt.Errorf("chmod runtime dev directory %s: %w", devDir, err)
	}

	if st, err := os.Lstat(target); err == nil {
		if st.IsDir() {
			return fmt.Errorf("runtime dev log target is a directory: %s", target)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		f, createErr := os.OpenFile(target, os.O_CREATE|os.O_RDONLY, 0o640)
		if createErr != nil {
			return fmt.Errorf("create runtime dev log target %s: %w", target, createErr)
		}
		_ = f.Close()
		if err := os.Chown(target, uid, gid); err != nil {
			return fmt.Errorf("chown runtime dev log target %s: %w", target, err)
		}
		if err := os.Chmod(target, 0o640); err != nil {
			return fmt.Errorf("chmod runtime dev log target %s: %w", target, err)
		}
	} else {
		return fmt.Errorf("stat runtime dev log target %s: %w", target, err)
	}

	mounted, src, err := mountSourceForTarget(target)
	if err != nil {
		return err
	}
	if mounted {
		if src == "/dev/log" {
			return nil
		}
		return fmt.Errorf("runtime dev log target %s is already mounted from %s, expected /dev/log", target, src)
	}

	if err := syscall.Mount("/dev/log", target, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind mount /dev/log to %s: %w", target, err)
	}
	return nil
}

func mountSourceForTarget(target string) (bool, string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, "", fmt.Errorf("open /proc/self/mountinfo: %w", err)
	}
	defer f.Close()

	target = filepath.Clean(target)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left := strings.Fields(parts[0])
		if len(left) < 5 {
			continue
		}
		mountPoint := left[4]
		if filepath.Clean(mountPoint) != target {
			continue
		}
		right := strings.Fields(parts[1])
		if len(right) < 2 {
			return true, "", nil
		}
		return true, right[1], nil
	}
	if err := scanner.Err(); err != nil {
		return false, "", fmt.Errorf("scan /proc/self/mountinfo: %w", err)
	}
	return false, "", nil
}

func validateRunTLSDirs(opts Options) error {
	certDir := filepath.Clean(filepath.Dir(opts.TLSCertDest))
	keyDir := filepath.Clean(filepath.Dir(opts.TLSKeyDest))
	configDir := filepath.Clean(filepath.Dir(opts.ConfigDest))
	if certDir != keyDir {
		return fmt.Errorf("runtime TLS destinations must share one directory: cert dir=%s key dir=%s", certDir, keyDir)
	}
	if certDir != configDir {
		return fmt.Errorf("runtime config and TLS destinations must share one directory: config dir=%s tls dir=%s", configDir, certDir)
	}
	if !strings.HasPrefix(certDir, "/run/") {
		return fmt.Errorf("runtime TLS directory must be under /run: %s", certDir)
	}
	return nil
}

func ensureRuntimeTLSDir(opts Options, uid, gid int) error {
	runtimeDir := filepath.Clean(filepath.Dir(opts.TLSCertDest))
	if runtimeDir != filepath.Clean(filepath.Dir(opts.TLSKeyDest)) {
		return fmt.Errorf("runtime TLS destinations must share one directory")
	}
	if runtimeDir != filepath.Clean(filepath.Dir(opts.ConfigDest)) {
		return fmt.Errorf("runtime config and TLS destinations must share one directory")
	}

	st, err := os.Stat(runtimeDir)
	if err == nil {
		if !st.IsDir() {
			return fmt.Errorf("runtime TLS path is not a directory: %s", runtimeDir)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("stat runtime TLS directory %s: %w", runtimeDir, err)
	}

	if err := os.MkdirAll(runtimeDir, 0o750); err != nil {
		return fmt.Errorf("create runtime TLS directory %s: %w", runtimeDir, err)
	}
	if err := os.Chown(runtimeDir, uid, gid); err != nil {
		return fmt.Errorf("chown runtime TLS directory %s: %w", runtimeDir, err)
	}
	if err := os.Chmod(runtimeDir, 0o750); err != nil {
		return fmt.Errorf("chmod runtime TLS directory %s: %w", runtimeDir, err)
	}

	return nil
}

func lookupRunUser(name string) (uid int, gid int, err error) {
	line, err := runGetent("passwd", name)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve run user %s: %w", name, err)
	}
	parts := strings.Split(line, ":")
	if len(parts) != 7 {
		return 0, 0, fmt.Errorf("malformed passwd entry for %s: %q", name, line)
	}
	uid, err = strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid for %s: %w", name, err)
	}
	gid, err = strconv.Atoi(parts[3])
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid for %s: %w", name, err)
	}
	return uid, gid, nil
}

func runGetent(database, key string) (string, error) {
	if _, err := exec.LookPath("getent"); err != nil {
		return "", fmt.Errorf("getent not found in PATH")
	}
	out, err := exec.Command("getent", database, key).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return "", fmt.Errorf("no entry returned")
	}
	return strings.Split(line, "\n")[0], nil
}

func stageTLSArtifacts(opts Options, uid, gid int) error {
	if err := stageConfigArtifact(opts, uid, gid); err != nil {
		return err
	}

	if err := validateTLSBundleOrder(opts.TLSCertSource); err != nil {
		return fmt.Errorf("validate tls cert bundle order: %w", err)
	}

	if err := copyFileAtomic(opts.TLSCertSource, opts.TLSCertDest, 0o640); err != nil {
		return fmt.Errorf("stage tls cert: %w", err)
	}
	if err := os.Chown(opts.TLSCertDest, uid, gid); err != nil {
		return fmt.Errorf("chown staged cert %s: %w", opts.TLSCertDest, err)
	}

	if err := copyFileAtomic(opts.TLSKeySource, opts.TLSKeyDest, 0o600); err != nil {
		return fmt.Errorf("stage tls key: %w", err)
	}
	if err := os.Chown(opts.TLSKeyDest, uid, gid); err != nil {
		return fmt.Errorf("chown staged key %s: %w", opts.TLSKeyDest, err)
	}

	return nil
}

func stageConfigArtifact(opts Options, uid, gid int) error {
	cfg, err := Load(opts.ConfigSource)
	if err != nil {
		return fmt.Errorf("load config source %s: %w", opts.ConfigSource, err)
	}

	runtimeCfg, err := buildRuntimeConfig(cfg, uid, gid)
	if err != nil {
		return fmt.Errorf("build runtime config: %w", err)
	}

	jsonConfig, err := json.MarshalIndent(runtimeCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config json for %s: %w", opts.ConfigDest, err)
	}
	jsonConfig = append(jsonConfig, '\n')

	if err := writeFileAtomic(opts.ConfigDest, jsonConfig, 0o640); err != nil {
		return fmt.Errorf("stage runtime config %s: %w", opts.ConfigDest, err)
	}
	if err := os.Chown(opts.ConfigDest, uid, gid); err != nil {
		return fmt.Errorf("chown staged config %s: %w", opts.ConfigDest, err)
	}

	return nil
}

func buildRuntimeConfig(cfg *Config, uid, gid int) (*server.Config, error) {
	resolved := &server.Config{Routes: make([]server.Route, 0, len(cfg.Routes))}
	stagedCAs := make(map[string]string)
	for _, route := range cfg.Routes {
		upstream, err := buildRuntimeUpstream(route, uid, gid, stagedCAs)
		if err != nil {
			return nil, fmt.Errorf("route path_prefix=%q upstream=%q: %w", route.PathPrefix, route.Upstream, err)
		}
		resolved.Routes = append(resolved.Routes, server.Route{
			PathPrefix: route.PathPrefix,
			Upstream:   upstream,
		})
	}
	return resolved, nil
}

func buildRuntimeUpstream(route Route, uid, gid int, stagedCAs map[string]string) (server.Upstream, error) {
	u, err := url.Parse(route.Upstream)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return server.Upstream{}, fmt.Errorf("invalid upstream URL")
	}

	protocol := strings.ToLower(u.Scheme)
	hostname := u.Hostname()
	port := u.Port()
	if port == "" {
		switch protocol {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return server.Upstream{}, fmt.Errorf("unsupported scheme %q", u.Scheme)
		}
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return server.Upstream{}, fmt.Errorf("invalid port %q: %w", port, err)
	}

	resolvedIPs, err := lookupIPv4Addresses(hostname)
	if err != nil {
		return server.Upstream{}, err
	}

	var trustedCA *server.TrustedCA
	if route.TrustedCA != nil {
		trustedCA, err = stageTrustedCA(route.TrustedCA, uid, gid, stagedCAs)
		if err != nil {
			return server.Upstream{}, err
		}
	}

	return server.Upstream{
		Protocol:      protocol,
		Hostname:      hostname,
		Port:          portNum,
		Path:          u.Path,
		RawQuery:      u.RawQuery,
		IPv4Addresses: resolvedIPs,
		TrustedCA:     trustedCA,
	}, nil
}

func lookupIPv4Addresses(hostname string) ([]string, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return nil, fmt.Errorf("upstream host %q is not IPv4", hostname)
		}
		return []string{v4.String()}, nil
	}

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("dns lookup failed: %w", err)
	}
	v4s := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		s := v4.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		v4s = append(v4s, s)
	}
	if len(v4s) == 0 {
		return nil, fmt.Errorf("dns lookup returned no IPv4 addresses")
	}
	sort.Strings(v4s)
	return v4s, nil
}

func stageTrustedCA(trustedCA *TrustedCA, uid, gid int, stagedCAs map[string]string) (*server.TrustedCA, error) {
	if trustedCA == nil {
		return nil, nil
	}

	sourcePath := strings.TrimSpace(trustedCA.CertPath)
	name := strings.TrimSpace(trustedCA.Name)
	if sourcePath == "" || name == "" {
		return nil, fmt.Errorf("trusted_ca requires both name and cert_path")
	}

	if existing, ok := stagedCAs[name]; ok && existing != sourcePath {
		return nil, fmt.Errorf("trusted_ca name %q is used with multiple cert_path values", name)
	}

	if err := ensureRuntimeTrustedCADir(uid, gid); err != nil {
		return nil, err
	}
	if err := validateTrustedCAFile(sourcePath); err != nil {
		return nil, err
	}

	destPath := filepath.Join(app.DefaultRuntimeTrustedCADir, "ca-"+name+".crt")
	if _, ok := stagedCAs[name]; !ok {
		if err := copyFileAtomic(sourcePath, destPath, 0o640); err != nil {
			return nil, fmt.Errorf("stage trusted_ca %q: %w", name, err)
		}
		if err := os.Chown(destPath, uid, gid); err != nil {
			return nil, fmt.Errorf("chown staged trusted_ca %s: %w", destPath, err)
		}
		stagedCAs[name] = sourcePath
	}

	return &server.TrustedCA{Name: name, File: destPath}, nil
}

func ensureRuntimeTrustedCADir(uid, gid int) error {
	if err := os.MkdirAll(app.DefaultRuntimeTrustedCADir, 0o750); err != nil {
		return fmt.Errorf("create trusted_ca runtime directory %s: %w", app.DefaultRuntimeTrustedCADir, err)
	}
	if err := os.Chown(app.DefaultRuntimeTrustedCADir, uid, gid); err != nil {
		return fmt.Errorf("chown trusted_ca runtime directory %s: %w", app.DefaultRuntimeTrustedCADir, err)
	}
	if err := os.Chmod(app.DefaultRuntimeTrustedCADir, 0o750); err != nil {
		return fmt.Errorf("chmod trusted_ca runtime directory %s: %w", app.DefaultRuntimeTrustedCADir, err)
	}
	return nil
}

func validateTrustedCAFile(certPath string) error {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read trusted_ca %s: %w", certPath, err)
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
		return fmt.Errorf("trusted_ca file %s does not contain any PEM certificates", certPath)
	}
	return nil
}

func validateTLSBundleOrder(certPath string) error {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", certPath, err)
	}

	certs, err := parseCertificatesFromPEM(pemBytes)
	if err != nil {
		return err
	}
	if len(certs) < 2 {
		return fmt.Errorf("bundle must contain leaf certificate first, followed by issuing intermediate/sub-CA certificate")
	}

	leaf := certs[0]
	parent := certs[1]
	if !bytes.Equal(leaf.RawIssuer, parent.RawSubject) {
		return fmt.Errorf("first certificate is not issued by the second certificate (expected leaf first, then intermediate/sub-CA)")
	}
	if err := leaf.CheckSignatureFrom(parent); err != nil {
		return fmt.Errorf("leaf certificate signature does not verify against second certificate: %w", err)
	}

	return nil
}

func copyFileAtomic(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	dir := filepath.Dir(dst)
	base := filepath.Base(dst)
	tmp, err := os.CreateTemp(dir, base+".tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return err
	}
	return nil
}

func writeFileAtomic(dst string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(dst)
	base := filepath.Base(dst)
	tmp, err := os.CreateTemp(dir, base+".tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return err
	}
	return nil
}

func ensurePortsBoundByHTTPSD(httpAddr, httpsAddr string, pids []int) error {
	ports := []struct {
		label string
		addr  string
	}{
		{label: "http", addr: httpAddr},
		{label: "https", addr: httpsAddr},
	}

	for _, p := range ports {
		port, err := parsePort(p.addr)
		if err != nil {
			return fmt.Errorf("%s port parse failed for %s: %w", p.label, p.addr, err)
		}
		inodes, err := listeningInodesForPort(port)
		if err != nil {
			return fmt.Errorf("%s port lookup failed for %s: %w", p.label, p.addr, err)
		}
		if len(inodes) == 0 {
			return fmt.Errorf("%s port %s is not currently bound", p.label, p.addr)
		}
		if !anyPIDOwnsInode(pids, inodes) {
			return fmt.Errorf("%s port %s is not bound by a running httpsd process", p.label, p.addr)
		}
	}

	return nil
}

func parsePort(addr string) (int, error) {
	_, portStr, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		portStr = strings.TrimPrefix(addr, ":")
	}
	return strconv.Atoi(portStr)
}

func anyPIDOwnsInode(pids []int, inodes map[string]struct{}) bool {
	for _, pid := range pids {
		fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if _, ok := inodes[inode]; ok {
				return true
			}
		}
	}
	return false
}

func findHTTPSDPIDs() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	self := os.Getpid()
	pids := make([]int, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, convErr := strconv.Atoi(entry.Name())
		if convErr != nil || pid == self {
			continue
		}

		comm, readErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		if readErr != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == "httpsd" {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids, nil
}
