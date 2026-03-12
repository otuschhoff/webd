package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultConfigPath   = "/etc/httpsd/config.json"
	defaultTLSCertPath  = "/etc/pki/tls/certs/selfcrt"
	defaultTLSKeyPath   = "/etc/pki/tls/private/self.key"
	defaultAccessLog    = "/var/log/httpsd/access.log"
	defaultHTTPAddr     = ":80"
	defaultHTTPSAddr    = ":443"
	defaultServicePath  = "/etc/systemd/system/httpsd.service"
	accessLogRotateSize = 1 * 1024 * 1024
)

const (
	colorReset   = "\033[0m"
	colorCyan    = "\033[36m"
	colorYellow  = "\033[33m"
	colorGreen   = "\033[32m"
	colorMagenta = "\033[35m"
	colorRed     = "\033[31m"
)

const httpsdServiceUnit = `[Unit]
Description=Custom HTTPS Proxy for internal app
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=exec
User=httpsd
Group=httpsd
ExecStart=/opt/httpsd/current/sbin/httpsd
Restart=on-failure

# Security: Give the binary permission to bind to ports 80/443
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Hardening: Prevent the app from gaining more privileges
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
`

type appOptions struct {
	configPath    string
	httpAddr      string
	httpsAddr     string
	tlsCertPath   string
	tlsKeyPath    string
	accessLogPath string
}

type setupOptions struct {
	tlsKeyPath  string
	servicePath string
}

type routeConfig struct {
	PathPrefix string `json:"path_prefix"`
	Upstream   string `json:"upstream"`
}

type proxyConfig struct {
	Routes []routeConfig `json:"routes"`
}

type routeProxy struct {
	prefix string
	proxy  *httputil.ReverseProxy
}

type rotatingWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	size     int64
}

type certReloader struct {
	certPath string
	keyPath  string
	cert     atomic.Pointer[tls.Certificate]
}

type passwdEntry struct {
	name  string
	uid   int
	gid   int
	home  string
	shell string
}

type groupEntry struct {
	name    string
	gid     int
	members []string
}

func main() {
	opts := appOptions{
		configPath:    defaultConfigPath,
		httpAddr:      defaultHTTPAddr,
		httpsAddr:     defaultHTTPSAddr,
		tlsCertPath:   defaultTLSCertPath,
		tlsKeyPath:    defaultTLSKeyPath,
		accessLogPath: defaultAccessLog,
	}

	setupOpts := setupOptions{
		tlsKeyPath:  defaultTLSKeyPath,
		servicePath: defaultServicePath,
	}

	rootCmd := &cobra.Command{
		Use:   "httpsd",
		Short: "HTTPS reverse proxy daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(opts)
		},
	}

	rootCmd.PersistentFlags().StringVar(&opts.configPath, "config", opts.configPath, "Path to JSON reverse-proxy config")
	rootCmd.PersistentFlags().StringVar(&opts.httpAddr, "http-addr", opts.httpAddr, "HTTP listen address")
	rootCmd.PersistentFlags().StringVar(&opts.httpsAddr, "https-addr", opts.httpsAddr, "HTTPS listen address")
	rootCmd.PersistentFlags().StringVar(&opts.tlsCertPath, "tls-cert", opts.tlsCertPath, "TLS certificate file")
	rootCmd.PersistentFlags().StringVar(&opts.tlsKeyPath, "tls-key", opts.tlsKeyPath, "TLS private key file")
	rootCmd.PersistentFlags().StringVar(&opts.accessLogPath, "access-log", opts.accessLogPath, "Access log path")

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run HTTPS proxy server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(opts)
		},
	}

	reloadCmd := &cobra.Command{
		Use:   "reload",
		Short: "Reload running httpsd instance(s)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return reloadRunningProcesses()
		},
	}

	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Validate config and print it in pretty colored JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			return checkConfig(opts.configPath)
		},
	}

	setupCmd := &cobra.Command{
		Use:   "setup",
		Short: "Prepare system user/group, permissions, and service unit",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetup(setupOpts)
		},
	}
	setupCmd.Flags().StringVar(&setupOpts.tlsKeyPath, "tls-key", setupOpts.tlsKeyPath, "TLS private key path for permission setup")
	setupCmd.Flags().StringVar(&setupOpts.servicePath, "service-path", setupOpts.servicePath, "Systemd unit file path")

	rootCmd.AddCommand(runCmd, reloadCmd, checkCmd, setupCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runServer(opts appOptions) error {
	if os.Geteuid() == 0 {
		return fmt.Errorf("httpsd must not run as root; remediate by running as user 'httpsd'")
	}

	cfg, err := loadConfig(opts.configPath)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	routes, err := buildRouteProxies(cfg)
	if err != nil {
		return fmt.Errorf("route config error: %w", err)
	}

	var activeRoutes atomic.Value
	activeRoutes.Store(routes)

	rw, err := newRotatingWriter(opts.accessLogPath, accessLogRotateSize)
	if err != nil {
		return fmt.Errorf("access log setup error: %w", err)
	}
	defer func() {
		if cerr := rw.Close(); cerr != nil {
			log.Printf("close access log error: %v", cerr)
		}
	}()

	accessLogger := log.New(rw, "", 0)
	router := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routesNow := activeRoutes.Load().([]routeProxy)
		for _, route := range routesNow {
			if strings.HasPrefix(r.URL.Path, route.prefix) {
				route.proxy.ServeHTTP(w, r)
				return
			}
		}
		http.NotFound(w, r)
	})
	handler := accessLogMiddleware(router, accessLogger)

	httpSrv := &http.Server{Addr: opts.httpAddr, Handler: handler}

	certs, err := newCertReloader(opts.tlsCertPath, opts.tlsKeyPath)
	if err != nil {
		return fmt.Errorf("tls setup error: %w", err)
	}

	httpsSrv := &http.Server{
		Addr:    opts.httpsAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certs.GetCertificate,
		},
	}

	log.Printf("httpsd starting http=%s https=%s config=%s access_log=%s routes=%d", opts.httpAddr, opts.httpsAddr, opts.configPath, opts.accessLogPath, len(routes))
	log.Printf("reload enabled: send SIGHUP to reload TLS cert/key and proxy config")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		for range sigCh {
			cfgNow, cfgErr := loadConfig(opts.configPath)
			if cfgErr != nil {
				log.Printf("config reload failed: %v", cfgErr)
			} else {
				reloadedRoutes, routesErr := buildRouteProxies(cfgNow)
				if routesErr != nil {
					log.Printf("route reload failed: %v", routesErr)
				} else {
					activeRoutes.Store(reloadedRoutes)
					log.Printf("proxy routes reloaded successfully: routes=%d", len(reloadedRoutes))
				}
			}

			if reloadErr := certs.Reload(); reloadErr != nil {
				log.Printf("tls reload failed: %v", reloadErr)
				continue
			}
			log.Printf("tls cert/key reloaded successfully")
		}
	}()

	errCh := make(chan error, 2)
	go func() {
		log.Printf("listening HTTP on %s", opts.httpAddr)
		errCh <- httpSrv.ListenAndServe()
	}()
	go func() {
		log.Printf("listening HTTPS on %s", opts.httpsAddr)
		tlsListener, listenErr := tls.Listen("tcp", opts.httpsAddr, httpsSrv.TLSConfig)
		if listenErr != nil {
			errCh <- listenErr
			return
		}
		errCh <- httpsSrv.Serve(tlsListener)
	}()

	return <-errCh
}

func reloadRunningProcesses() error {
	pids, err := findHTTPSDPIDs()
	if err != nil {
		return err
	}
	if len(pids) == 0 {
		return fmt.Errorf("no running httpsd process found")
	}

	sent := 0
	for _, pid := range pids {
		if killErr := syscall.Kill(pid, syscall.SIGHUP); killErr != nil {
			log.Printf("reload failed pid=%d err=%v", pid, killErr)
			continue
		}
		sent++
		fmt.Printf("sent SIGHUP to pid=%d\n", pid)
	}

	if sent == 0 {
		return fmt.Errorf("could not signal any running httpsd process")
	}
	return nil
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

func checkConfig(path string) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if _, err := buildRouteProxies(cfg); err != nil {
		return err
	}

	pretty, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal pretty config: %w", err)
	}

	fmt.Println(colorizePrettyJSON(string(pretty), os.Getenv("NO_COLOR") == ""))
	return nil
}

func colorizePrettyJSON(in string, useColor bool) string {
	if !useColor {
		return in
	}

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

func runSetup(opts setupOptions) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("setup must be run as root")
	}

	httpsdGroup, httpsdGroupCreated, err := ensureGroupExists("httpsd", -1)
	if err != nil {
		return err
	}
	if httpsdGroupCreated {
		fmt.Printf("created group httpsd gid=%d\n", httpsdGroup)
	}

	httpsdUID, httpsdPrimaryGID, httpsdUserCreated, err := ensureUserExists("httpsd", httpsdGroup)
	if err != nil {
		return err
	}
	if httpsdUserCreated {
		fmt.Printf("created user httpsd uid=%d gid=%d\n", httpsdUID, httpsdPrimaryGID)
	}

	tlskeyGID, tlskeyCreated, err := ensureGroupExists("tlskey", -1)
	if err != nil {
		return err
	}
	if tlskeyCreated {
		fmt.Printf("created group tlskey gid=%d\n", tlskeyGID)
	}

	membershipChanged, err := ensureUserInGroup("httpsd", "tlskey")
	if err != nil {
		return err
	}
	if membershipChanged {
		fmt.Println("added user httpsd to group tlskey")
	}

	if err := os.Chown(opts.tlsKeyPath, 0, tlskeyGID); err != nil {
		return fmt.Errorf("set owner root:tlskey on %s: %w", opts.tlsKeyPath, err)
	}
	if err := os.Chmod(opts.tlsKeyPath, 0o640); err != nil {
		return fmt.Errorf("set mode 0640 on %s: %w", opts.tlsKeyPath, err)
	}
	fmt.Printf("set TLS key ownership and mode on %s\n", opts.tlsKeyPath)

	if err := os.MkdirAll("/var/log/httpsd", 0o750); err != nil {
		return fmt.Errorf("create /var/log/httpsd: %w", err)
	}
	if err := os.Chown("/var/log/httpsd", httpsdUID, httpsdGroup); err != nil {
		return fmt.Errorf("chown /var/log/httpsd: %w", err)
	}
	if err := os.Chmod("/var/log/httpsd", 0o750); err != nil {
		return fmt.Errorf("chmod /var/log/httpsd: %w", err)
	}
	fmt.Println("ensured /var/log/httpsd ownership=httpsd:httpsd perms=750")

	serviceExists, err := systemdServiceExists("httpsd")
	if err != nil {
		return err
	}
	if !serviceExists {
		if err := os.WriteFile(opts.servicePath, []byte(httpsdServiceUnit), 0o644); err != nil {
			return fmt.Errorf("write systemd unit %s: %w", opts.servicePath, err)
		}
		fmt.Printf("created systemd unit %s\n", opts.servicePath)
	} else {
		fmt.Println("systemd service httpsd already exists")
	}

	fmt.Println("setup complete")
	fmt.Println("next step: run 'systemctl daemon-reload' if a new unit file was created")
	return nil
}

func ensureUserExists(name string, defaultGID int) (uid int, gid int, created bool, err error) {
	entries, err := readPasswdEntries()
	if err != nil {
		return 0, 0, false, err
	}
	for _, e := range entries {
		if e.name == name {
			return e.uid, e.gid, false, nil
		}
	}

	nextUID := nextAvailableUID(entries)
	gid = defaultGID
	line := fmt.Sprintf("%s:x:%d:%d:%s service user:/nonexistent:/usr/sbin/nologin", name, nextUID, gid, name)
	if err := appendLine("/etc/passwd", line); err != nil {
		return 0, 0, false, fmt.Errorf("append /etc/passwd: %w", err)
	}
	return nextUID, gid, true, nil
}

func ensureGroupExists(name string, preferredGID int) (gid int, created bool, err error) {
	entries, lines, err := readGroupEntriesAndLines()
	if err != nil {
		return 0, false, err
	}
	for _, e := range entries {
		if e.name == name {
			return e.gid, false, nil
		}
	}

	gid = preferredGID
	if gid <= 0 || gidInUse(entries, gid) {
		gid = nextAvailableGID(entries)
	}
	lines = append(lines, fmt.Sprintf("%s:x:%d:", name, gid))
	if err := writeLines("/etc/group", lines); err != nil {
		return 0, false, fmt.Errorf("write /etc/group: %w", err)
	}
	return gid, true, nil
}

func ensureUserInGroup(username, groupName string) (bool, error) {
	entries, lines, err := readGroupEntriesAndLines()
	if err != nil {
		return false, err
	}

	lineIndex := -1
	for i, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) != 4 {
			continue
		}
		if parts[0] == groupName {
			lineIndex = i
			break
		}
	}
	if lineIndex == -1 {
		return false, fmt.Errorf("group %s not found in /etc/group", groupName)
	}

	for _, e := range entries {
		if e.name != groupName {
			continue
		}
		for _, member := range e.members {
			if member == username {
				return false, nil
			}
		}
		members := append(e.members, username)
		sort.Strings(members)
		lines[lineIndex] = fmt.Sprintf("%s:x:%d:%s", e.name, e.gid, strings.Join(members, ","))
		if err := writeLines("/etc/group", lines); err != nil {
			return false, fmt.Errorf("write /etc/group: %w", err)
		}
		return true, nil
	}

	return false, fmt.Errorf("group %s parse mismatch", groupName)
}

func systemdServiceExists(name string) (bool, error) {
	paths := []string{
		filepath.Join("/etc/systemd/system", name+".service"),
		filepath.Join("/usr/lib/systemd/system", name+".service"),
		filepath.Join("/lib/systemd/system", name+".service"),
	}
	for _, p := range paths {
		_, err := os.Stat(p)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("stat %s: %w", p, err)
		}
	}
	return false, nil
}

func readPasswdEntries() ([]passwdEntry, error) {
	lines, err := readLines("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("read /etc/passwd: %w", err)
	}

	entries := make([]passwdEntry, 0)
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 7 {
			continue
		}
		uid, uidErr := strconv.Atoi(parts[2])
		gid, gidErr := strconv.Atoi(parts[3])
		if uidErr != nil || gidErr != nil {
			continue
		}
		entries = append(entries, passwdEntry{
			name:  parts[0],
			uid:   uid,
			gid:   gid,
			home:  parts[5],
			shell: parts[6],
		})
	}
	return entries, nil
}

func readGroupEntriesAndLines() ([]groupEntry, []string, error) {
	lines, err := readLines("/etc/group")
	if err != nil {
		return nil, nil, fmt.Errorf("read /etc/group: %w", err)
	}

	entries := make([]groupEntry, 0)
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 4 {
			continue
		}
		gid, gidErr := strconv.Atoi(parts[2])
		if gidErr != nil {
			continue
		}
		members := make([]string, 0)
		if parts[3] != "" {
			for _, m := range strings.Split(parts[3], ",") {
				m = strings.TrimSpace(m)
				if m != "" {
					members = append(members, m)
				}
			}
		}
		entries = append(entries, groupEntry{name: parts[0], gid: gid, members: members})
	}

	return entries, lines, nil
}

func nextAvailableUID(entries []passwdEntry) int {
	maxUID := 999
	for _, e := range entries {
		if e.uid > maxUID {
			maxUID = e.uid
		}
	}
	return maxUID + 1
}

func gidInUse(entries []groupEntry, gid int) bool {
	for _, e := range entries {
		if e.gid == gid {
			return true
		}
	}
	return false
}

func nextAvailableGID(entries []groupEntry) int {
	maxGID := 999
	for _, e := range entries {
		if e.gid > maxGID {
			maxGID = e.gid
		}
	}
	return maxGID + 1
}

func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return []string{}, nil
	}
	return strings.Split(text, "\n"), nil
}

func writeLines(path string, lines []string) error {
	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0o644)
}

func newCertReloader(certPath, keyPath string) (*certReloader, error) {
	cr := &certReloader{certPath: certPath, keyPath: keyPath}
	if err := cr.Reload(); err != nil {
		return nil, err
	}
	return cr, nil
}

func (c *certReloader) Reload() error {
	loaded, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
	if err != nil {
		return fmt.Errorf("load tls cert/key: %w", err)
	}
	c.cert.Store(&loaded)
	return nil
}

func (c *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	loaded := c.cert.Load()
	if loaded == nil {
		return nil, fmt.Errorf("tls certificate is not loaded")
	}
	return loaded, nil
}

func newRotatingWriter(path string, maxBytes int64) (*rotatingWriter, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("invalid maxBytes %d", maxBytes)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat log file: %w", err)
	}

	return &rotatingWriter{path: path, maxBytes: maxBytes, file: f, size: st.Size()}, nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rotatingWriter) rotate() error {
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("close log file: %w", err)
	}

	archive := fmt.Sprintf("%s.%s", w.path, time.Now().UTC().Format("20060102T150405"))
	if err := os.Rename(w.path, archive); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("rotate log file: %w", err)
	}

	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("reopen log file: %w", err)
	}

	w.file = f
	w.size = 0
	return nil
}

func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	return w.file.Close()
}

func loadConfig(path string) (*proxyConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg proxyConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if len(cfg.Routes) == 0 {
		return nil, fmt.Errorf("config %s must contain at least one route", path)
	}

	return &cfg, nil
}

func buildRouteProxies(cfg *proxyConfig) ([]routeProxy, error) {
	routes := make([]routeProxy, 0, len(cfg.Routes))

	for _, r := range cfg.Routes {
		prefix := strings.TrimSpace(r.PathPrefix)
		if prefix == "" {
			prefix = "/"
		}
		if !strings.HasPrefix(prefix, "/") {
			return nil, fmt.Errorf("path_prefix must begin with '/': %q", prefix)
		}

		u, err := url.Parse(r.Upstream)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("invalid upstream for prefix %q: %q", prefix, r.Upstream)
		}
		upstream := u.String()

		proxy := httputil.NewSingleHostReverseProxy(u)
		proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, proxyErr error) {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			log.Printf("proxy_error upstream=%q path=%q err=%v", upstream, req.URL.Path, proxyErr)
		}

		routes = append(routes, routeProxy{prefix: prefix, proxy: proxy})
	}

	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].prefix) > len(routes[j].prefix)
	})

	return routes, nil
}

func clientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	size   int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.status = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.size += n
	return n, err
}

func accessLogMiddleware(next http.Handler, logger *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		dur := time.Since(start)

		logger.Printf(
			"ts=%s ip=%s method=%s url=%s status=%d size=%d duration_ms=%d agent=%s",
			start.UTC().Format(time.RFC3339),
			clientIP(r),
			r.Method,
			r.URL.RequestURI(),
			rec.status,
			rec.size,
			dur.Milliseconds(),
			strconv.Quote(r.UserAgent()),
		)
	})
}
