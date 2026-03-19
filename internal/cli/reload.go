package cli

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	"syscall"
	"time"

	"webd/internal/app"
	"webd/internal/server"
)

// Options controls root helper behavior for staging runtime TLS artifacts and
// signaling running webd processes.
type Options struct {
	HTTPAddr      string
	HTTPSAddr     string
	RunUser       string
	Force         bool
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
		HTTPAddr:      DefaultHTTPAddr,
		HTTPSAddr:     DefaultHTTPSAddr,
		RunUser:       DefaultRunUser,
		Force:         false,
		ConfigSource:  DefaultConfigPath,
		ConfigDest:    DefaultRuntimeConfigPath,
		TLSCertSource: DefaultTLSSourceCertPath,
		TLSKeySource:  DefaultTLSSourceKeyPath,
		TLSCertDest:   DefaultRuntimeTLSCertPath,
		TLSKeyDest:    DefaultRuntimeTLSKeyPath,
		PrepareOnly:   false,
	}
}

// Run locates running webd processes and sends them SIGHUP for in-place reload.
func Run(opts Options) error {
	logs, err := app.NewForCommand("webctl", false)
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

	var pids []int
	if !opts.PrepareOnly {
		pids, err = findHTTPSDPIDs()
		if err != nil {
			errLog.Printf("reload process discovery failed err=%v", err)
			return err
		}
		if len(pids) == 0 {
			return fmt.Errorf("no running webd process found")
		}

		if err := ensurePortsBoundByHTTPSD(opts.HTTPAddr, opts.HTTPSAddr, pids); err != nil {
			errLog.Printf("reload active-port validation failed err=%v", err)
			return err
		}
	}

	artifactsChanged, err := stageTLSArtifacts(opts, runUID, runGID)
	if err != nil {
		errLog.Printf("reload staging failed err=%v", err)
		return err
	}
	opsLog.Printf("staged runtime artifacts config=%s cert=%s key=%s owner=%s", opts.ConfigDest, opts.TLSCertDest, opts.TLSKeyDest, opts.RunUser)

	if !artifactsChanged {
		if opts.Force {
			opsLog.Printf("no runtime artifact changes detected; forcing reload due to --force")
		} else {
			opsLog.Printf("no runtime artifact changes detected; skipping reload")
			return nil
		}
	}

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
		return fmt.Errorf("could not signal any running webd process")
	}
	return nil
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

func stageTLSArtifacts(opts Options, uid, gid int) (bool, error) {
	configChanged, err := stageConfigArtifact(opts, uid, gid)
	if err != nil {
		return false, err
	}

	if err := validateTLSBundleOrder(opts.TLSCertSource); err != nil {
		return false, fmt.Errorf("validate tls cert bundle order: %w", err)
	}

	certChanged, err := copyFileAtomic(opts.TLSCertSource, opts.TLSCertDest, 0o640)
	if err != nil {
		return false, fmt.Errorf("stage tls cert: %w", err)
	}
	if certChanged {
		if err := os.Chown(opts.TLSCertDest, uid, gid); err != nil {
			return false, fmt.Errorf("chown staged cert %s: %w", opts.TLSCertDest, err)
		}
	}

	keyChanged, err := copyFileAtomic(opts.TLSKeySource, opts.TLSKeyDest, 0o600)
	if err != nil {
		return false, fmt.Errorf("stage tls key: %w", err)
	}
	if keyChanged {
		if err := os.Chown(opts.TLSKeyDest, uid, gid); err != nil {
			return false, fmt.Errorf("chown staged key %s: %w", opts.TLSKeyDest, err)
		}
	}

	return configChanged || certChanged || keyChanged, nil
}

func stageConfigArtifact(opts Options, uid, gid int) (bool, error) {
	cfg, err := Load(opts.ConfigSource)
	if err != nil {
		return false, fmt.Errorf("load config source %s: %w", opts.ConfigSource, err)
	}

	stagedCAs := make(map[string]*stagedTrustedCA)

	runtimeCfg, err := buildRuntimeConfig(cfg, uid, gid, stagedCAs)
	if err != nil {
		return false, fmt.Errorf("build runtime config: %w", err)
	}
	if err := app.ValidateRuntimeConfig(runtimeCfg); err != nil {
		return false, fmt.Errorf("validate generated runtime config against json schema: %w", err)
	}

	jsonConfig, err := json.MarshalIndent(runtimeCfg, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal config json for %s: %w", opts.ConfigDest, err)
	}
	jsonConfig = append(jsonConfig, '\n')

	configChanged, err := writeFileAtomic(opts.ConfigDest, jsonConfig, 0o640)
	if err != nil {
		return false, fmt.Errorf("stage runtime config %s: %w", opts.ConfigDest, err)
	}
	if configChanged {
		if err := os.Chown(opts.ConfigDest, uid, gid); err != nil {
			return false, fmt.Errorf("chown staged config %s: %w", opts.ConfigDest, err)
		}
	}

	trustedCAChanged := false
	for _, entry := range stagedCAs {
		if entry.changed {
			trustedCAChanged = true
			break
		}
	}

	return configChanged || trustedCAChanged, nil
}

func buildRuntimeConfig(cfg *Config, uid, gid int, stagedCAs map[string]*stagedTrustedCA) (*server.Config, error) {
	resolved := &server.Config{Routes: make([]server.Route, 0, len(cfg.Routes))}
	if stagedCAs == nil {
		stagedCAs = make(map[string]*stagedTrustedCA)
	}
	for _, route := range cfg.Routes {
		allowedIPv4Ranges, err := translateAllowedIPv4(route.AllowedIPv4)
		if err != nil {
			return nil, fmt.Errorf("route path=%q allowed_ipv4: %w", route.Path, err)
		}

		if strings.TrimSpace(route.Redirect) != "" {
			resolved.Routes = append(resolved.Routes, server.Route{
				Path:              route.Path,
				AllowedIPv4Ranges: allowedIPv4Ranges,
				Browse:            route.Browse,
				Redirect:          strings.TrimSpace(route.Redirect),
			})
			continue
		}

		handler, err := buildRuntimeHandler(route, uid, gid, stagedCAs)
		if err != nil {
			return nil, fmt.Errorf("route path=%q handler=%q: %w", route.Path, route.Handler, err)
		}
		resolved.Routes = append(resolved.Routes, server.Route{
			Path:              route.Path,
			AllowedIPv4Ranges: allowedIPv4Ranges,
			Browse:            route.Browse,
			Handler:           &handler,
		})
	}
	return resolved, nil
}

type stagedTrustedCA struct {
	sourcePath string
	destPath   string
	indexBySum map[[32]byte]int
	pemBlocks  [][]byte
	changed    bool
}

func buildRuntimeHandler(route Route, uid, gid int, stagedCAs map[string]*stagedTrustedCA) (server.Handler, error) {
	u, err := url.Parse(route.Handler)
	if err != nil || u.Scheme == "" {
		return server.Handler{}, fmt.Errorf("invalid handler URL")
	}

	protocol := strings.ToLower(u.Scheme)
	if protocol == "file" {
		host := strings.TrimSpace(u.Host)
		if host != "" && host != "localhost" {
			return server.Handler{}, fmt.Errorf("file handler host must be empty or localhost")
		}
		if strings.TrimSpace(u.Path) == "" || !filepath.IsAbs(u.Path) {
			return server.Handler{}, fmt.Errorf("file handler path must be absolute")
		}
		if route.TrustedCA != nil {
			return server.Handler{}, fmt.Errorf("trusted_ca is not supported for file handlers")
		}
		return server.Handler{
			Protocol: "file",
			Path:     u.Path,
		}, nil
	}
	if u.Host == "" {
		return server.Handler{}, fmt.Errorf("invalid handler URL")
	}

	hostname := u.Hostname()
	port := u.Port()
	if port == "" {
		switch protocol {
		case "http":
		case "ws":
			port = "80"
		case "https":
		case "wss":
			port = "443"
		default:
			return server.Handler{}, fmt.Errorf("unsupported scheme %q", u.Scheme)
		}
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return server.Handler{}, fmt.Errorf("invalid port %q: %w", port, err)
	}

	resolvedIPs, err := lookupIPv4Addresses(hostname)
	if err != nil {
		return server.Handler{}, err
	}

	var trustedCA *server.TrustedCA
	handlerCfg := server.Handler{
		Protocol:      protocol,
		Hostname:      hostname,
		Port:          portNum,
		Path:          u.Path,
		RawQuery:      u.RawQuery,
		IPv4Addresses: resolvedIPs,
	}
	if route.TrustedCA != nil {
		trustedCA, err = stageTrustedCA(route.TrustedCA, handlerCfg, uid, gid, stagedCAs)
		if err != nil {
			return server.Handler{}, err
		}
	} else if route.Insecure {
		trustedCA, err = stageInsecureTrustedCert(handlerCfg, uid, gid, stagedCAs)
		if err != nil {
			return server.Handler{}, err
		}
	} else if protocol == "https" || protocol == "wss" {
		trustedCA, err = stageAutoTrustedCA(handlerCfg, uid, gid, stagedCAs)
		if err != nil {
			return server.Handler{}, err
		}
	}

	handlerCfg.TrustedCA = trustedCA
	return handlerCfg, nil
}

func lookupIPv4Addresses(hostname string) ([]string, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return nil, fmt.Errorf("handler host %q is not IPv4", hostname)
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

func stageTrustedCA(trustedCA *TrustedCA, handler server.Handler, uid, gid int, stagedCAs map[string]*stagedTrustedCA) (*server.TrustedCA, error) {
	if trustedCA == nil {
		return nil, nil
	}

	sourcePath := strings.TrimSpace(trustedCA.CertPath)
	name := strings.TrimSpace(trustedCA.Name)
	if sourcePath == "" || name == "" {
		return nil, fmt.Errorf("trusted_ca requires both name and cert_path")
	}

	entry, ok := stagedCAs[name]
	if ok && entry.sourcePath != sourcePath {
		return nil, fmt.Errorf("trusted_ca name %q is used with multiple cert_path values", name)
	}

	if err := ensureRuntimeTrustedCADir(uid, gid); err != nil {
		return nil, err
	}

	caCerts, err := fetchVerifiedHandlerCACerts(handler, sourcePath)
	if err != nil {
		return nil, err
	}

	if !ok {
		entry = &stagedTrustedCA{
			sourcePath: sourcePath,
			destPath:   filepath.Join(DefaultRuntimeTrustedCADir, "ca-"+name+".crt"),
			indexBySum: make(map[[32]byte]int),
			pemBlocks:  make([][]byte, 0, len(caCerts)),
		}
		stagedCAs[name] = entry
	}

	for _, cert := range caCerts {
		sum := sha256.Sum256(cert.Raw)
		if _, exists := entry.indexBySum[sum]; exists {
			continue
		}
		entry.indexBySum[sum] = len(entry.pemBlocks)
		entry.pemBlocks = append(entry.pemBlocks, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}

	changed, err := writeTrustedCAFile(entry.destPath, entry.pemBlocks, uid, gid)
	if err != nil {
		return nil, fmt.Errorf("stage trusted_ca %q: %w", name, err)
	}
	entry.changed = entry.changed || changed

	return &server.TrustedCA{Name: name, File: filepath.Base(entry.destPath)}, nil
}

func stageAutoTrustedCA(handler server.Handler, uid, gid int, stagedCAs map[string]*stagedTrustedCA) (*server.TrustedCA, error) {
	name := autoTrustedCAName(handler)
	key := "auto:" + name

	entry, ok := stagedCAs[name]
	if ok && entry.sourcePath != key {
		return nil, fmt.Errorf("auto trusted_ca name %q collides with another trusted_ca entry", name)
	}

	if err := ensureRuntimeTrustedCADir(uid, gid); err != nil {
		return nil, err
	}

	caCerts, err := fetchVerifiedHandlerOSCACerts(handler)
	if err != nil {
		return nil, err
	}

	if !ok {
		entry = &stagedTrustedCA{
			sourcePath: key,
			destPath:   filepath.Join(DefaultRuntimeTrustedCADir, "ca-"+name+".crt"),
			indexBySum: make(map[[32]byte]int),
			pemBlocks:  make([][]byte, 0, len(caCerts)),
		}
		stagedCAs[name] = entry
	}

	for _, cert := range caCerts {
		sum := sha256.Sum256(cert.Raw)
		if _, exists := entry.indexBySum[sum]; exists {
			continue
		}
		entry.indexBySum[sum] = len(entry.pemBlocks)
		entry.pemBlocks = append(entry.pemBlocks, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}

	changed, err := writeTrustedCAFile(entry.destPath, entry.pemBlocks, uid, gid)
	if err != nil {
		return nil, fmt.Errorf("stage auto trusted_ca %q: %w", name, err)
	}
	entry.changed = entry.changed || changed

	return &server.TrustedCA{Name: name, File: filepath.Base(entry.destPath)}, nil
}

func stageInsecureTrustedCert(handler server.Handler, uid, gid int, stagedCAs map[string]*stagedTrustedCA) (*server.TrustedCA, error) {
	name := insecureTrustedCertName(handler)
	key := "insecure:" + name

	entry, ok := stagedCAs[name]
	if ok && entry.sourcePath != key {
		return nil, fmt.Errorf("insecure trusted_ca name %q collides with another trusted_ca entry", name)
	}

	if err := ensureRuntimeTrustedCADir(uid, gid); err != nil {
		return nil, err
	}

	peerCerts, err := fetchHandlerPeerCertificates(handler)
	if err != nil {
		return nil, err
	}
	if len(peerCerts) == 0 {
		return nil, fmt.Errorf("handler %s presented no TLS certificates", formatRuntimeHandler(handler))
	}

	leafCert := peerCerts[0]
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	if !ok {
		entry = &stagedTrustedCA{
			sourcePath: key,
			destPath:   filepath.Join(DefaultRuntimeTrustedCADir, "ca-"+name+".crt"),
			indexBySum: make(map[[32]byte]int),
			pemBlocks:  make([][]byte, 0, 1),
		}
		stagedCAs[name] = entry
	}

	sum := sha256.Sum256(leafCert.Raw)
	if _, exists := entry.indexBySum[sum]; !exists {
		entry.indexBySum[sum] = len(entry.pemBlocks)
		entry.pemBlocks = append(entry.pemBlocks, pemBlock)
	}

	changed, err := writeTrustedCAFile(entry.destPath, entry.pemBlocks, uid, gid)
	if err != nil {
		return nil, fmt.Errorf("stage insecure trusted_ca %q: %w", name, err)
	}
	entry.changed = entry.changed || changed

	return &server.TrustedCA{Name: name, File: filepath.Base(entry.destPath), PinCert: true}, nil
}

func insecureTrustedCertName(handler server.Handler) string {
	sum := sha256.Sum256([]byte("insecure:" + formatRuntimeHandler(handler)))
	return fmt.Sprintf("insecure-%x", sum[:6])
}

func autoTrustedCAName(handler server.Handler) string {
	sum := sha256.Sum256([]byte(formatRuntimeHandler(handler)))
	return fmt.Sprintf("auto-%x", sum[:6])
}

func ensureRuntimeTrustedCADir(uid, gid int) error {
	if err := os.MkdirAll(DefaultRuntimeTrustedCADir, 0o750); err != nil {
		return fmt.Errorf("create trusted_ca runtime directory %s: %w", DefaultRuntimeTrustedCADir, err)
	}
	if err := os.Chown(DefaultRuntimeTrustedCADir, uid, gid); err != nil {
		return fmt.Errorf("chown trusted_ca runtime directory %s: %w", DefaultRuntimeTrustedCADir, err)
	}
	if err := os.Chmod(DefaultRuntimeTrustedCADir, 0o750); err != nil {
		return fmt.Errorf("chmod trusted_ca runtime directory %s: %w", DefaultRuntimeTrustedCADir, err)
	}
	return nil
}

func fetchVerifiedHandlerCACerts(handler server.Handler, sourcePath string) ([]*x509.Certificate, error) {
	localPEM, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("read trusted_ca %s: %w", sourcePath, err)
	}
	localCerts, err := parseCertificatesFromPEM(localPEM)
	if err != nil {
		return nil, fmt.Errorf("parse trusted_ca %s: %w", sourcePath, err)
	}

	peerCerts, err := fetchHandlerPeerCertificates(handler)
	if err != nil {
		return nil, err
	}
	if len(peerCerts) == 0 {
		return nil, fmt.Errorf("handler %s presented no TLS certificates", formatRuntimeHandler(handler))
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for _, cert := range localCerts {
		roots.AddCert(cert)
		if !isSelfSignedCertificate(cert) {
			intermediates.AddCert(cert)
		}
	}
	for _, cert := range peerCerts[1:] {
		intermediates.AddCert(cert)
	}

	verifiedChains, err := peerCerts[0].Verify(x509.VerifyOptions{
		DNSName:       handler.Hostname,
		Roots:         roots,
		Intermediates: intermediates,
	})
	if err != nil {
		return nil, fmt.Errorf("verify handler %s against trusted_ca %s: %w", formatRuntimeHandler(handler), sourcePath, err)
	}

	chain := longestVerifiedChain(verifiedChains)
	if len(chain) == 0 {
		return nil, fmt.Errorf("no verified certificate chain found for handler %s", formatRuntimeHandler(handler))
	}
	chain = appendLocalParentChain(chain, localCerts)

	caCerts := make([]*x509.Certificate, 0, len(chain)-1)
	for _, cert := range chain[1:] {
		if cert.IsCA {
			caCerts = append(caCerts, cert)
		}
	}
	if len(caCerts) == 0 {
		return nil, fmt.Errorf("no validating CA certificates found for handler %s", formatRuntimeHandler(handler))
	}
	return caCerts, nil
}

func fetchVerifiedHandlerOSCACerts(handler server.Handler) ([]*x509.Certificate, error) {
	peerCerts, err := fetchHandlerPeerCertificates(handler)
	if err != nil {
		return nil, err
	}
	if len(peerCerts) == 0 {
		return nil, fmt.Errorf("handler %s presented no TLS certificates", formatRuntimeHandler(handler))
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system cert pool: %w", err)
	}
	if roots == nil {
		return nil, fmt.Errorf("load system cert pool: empty pool")
	}

	intermediates := x509.NewCertPool()
	for _, cert := range peerCerts[1:] {
		intermediates.AddCert(cert)
	}

	verifiedChains, err := peerCerts[0].Verify(x509.VerifyOptions{
		DNSName:       handler.Hostname,
		Roots:         roots,
		Intermediates: intermediates,
	})
	if err != nil {
		return nil, fmt.Errorf("verify handler %s against system trust store: %w", formatRuntimeHandler(handler), err)
	}

	chain := longestVerifiedChain(verifiedChains)
	if len(chain) == 0 {
		return nil, fmt.Errorf("no verified certificate chain found for handler %s", formatRuntimeHandler(handler))
	}

	caCerts := make([]*x509.Certificate, 0, len(chain)-1)
	for _, cert := range chain[1:] {
		if cert.IsCA {
			caCerts = append(caCerts, cert)
		}
	}
	if len(caCerts) == 0 {
		return nil, fmt.Errorf("no validating CA certificates found for handler %s", formatRuntimeHandler(handler))
	}
	return caCerts, nil
}

func fetchHandlerPeerCertificates(handler server.Handler) ([]*x509.Certificate, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         handler.Hostname,
		MinVersion:         tls.VersionTLS12,
	}

	var errs []string
	for _, rawIP := range handler.IPv4Addresses {
		addr := net.JoinHostPort(rawIP, strconv.Itoa(handler.Port))
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rawIP, err))
			continue
		}
		state := conn.ConnectionState()
		_ = conn.Close()
		return state.PeerCertificates, nil
	}
	return nil, fmt.Errorf("fetch handler TLS certificates for %s failed: %s", formatRuntimeHandler(handler), strings.Join(errs, "; "))
}

func formatRuntimeHandler(handler server.Handler) string {
	return (&url.URL{
		Scheme:   handler.Protocol,
		Host:     net.JoinHostPort(handler.Hostname, strconv.Itoa(handler.Port)),
		Path:     handler.Path,
		RawQuery: handler.RawQuery,
	}).String()
}

func longestVerifiedChain(chains [][]*x509.Certificate) []*x509.Certificate {
	var best []*x509.Certificate
	for _, chain := range chains {
		if len(chain) > len(best) {
			best = chain
		}
	}
	return best
}

func appendLocalParentChain(chain []*x509.Certificate, localCerts []*x509.Certificate) []*x509.Certificate {
	seen := make(map[[32]byte]struct{}, len(chain))
	for _, cert := range chain {
		seen[sha256.Sum256(cert.Raw)] = struct{}{}
	}

	current := chain[len(chain)-1]
	for {
		if isSelfSignedCertificate(current) {
			return chain
		}
		parent := findParentCertificate(current, localCerts, seen)
		if parent == nil {
			return chain
		}
		chain = append(chain, parent)
		sum := sha256.Sum256(parent.Raw)
		seen[sum] = struct{}{}
		current = parent
	}
}

func findParentCertificate(child *x509.Certificate, candidates []*x509.Certificate, seen map[[32]byte]struct{}) *x509.Certificate {
	for _, candidate := range candidates {
		sum := sha256.Sum256(candidate.Raw)
		if _, exists := seen[sum]; exists {
			continue
		}
		if !bytes.Equal(child.RawIssuer, candidate.RawSubject) {
			continue
		}
		if err := child.CheckSignatureFrom(candidate); err != nil {
			continue
		}
		return candidate
	}
	return nil
}

func isSelfSignedCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

func writeTrustedCAFile(destPath string, pemBlocks [][]byte, uid, gid int) (bool, error) {
	content := make([]byte, 0)
	for _, block := range pemBlocks {
		content = append(content, block...)
	}
	changed, err := writeFileAtomic(destPath, content, 0o640)
	if err != nil {
		return false, err
	}
	if changed {
		if err := os.Chown(destPath, uid, gid); err != nil {
			return false, err
		}
	}
	return changed, nil
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

func copyFileAtomic(src, dst string, mode os.FileMode) (bool, error) {
	content, err := os.ReadFile(src)
	if err != nil {
		return false, err
	}

	changed, err := writeFileAtomic(dst, content, mode)
	if err != nil {
		return false, err
	}
	return changed, nil
}

func writeFileAtomic(dst string, content []byte, mode os.FileMode) (bool, error) {
	existing, err := os.ReadFile(dst)
	if err == nil && bytes.Equal(existing, content) {
		return false, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}

	dir := filepath.Dir(dst)
	base := filepath.Base(dst)
	tmp, err := os.CreateTemp(dir, base+".tmp-")
	if err != nil {
		return false, err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return false, err
	}
	return true, nil
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
			return fmt.Errorf("%s port %s is not bound by a running webd process", p.label, p.addr)
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
		if strings.TrimSpace(string(comm)) == "webd" {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids, nil
}
