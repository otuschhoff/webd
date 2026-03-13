package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"httpsd/internal/app"
	"httpsd/internal/proxycfg"
	"httpsd/internal/reloadcmd"
)

type routeProxy struct {
	prefix string
	proxy  *httputil.ReverseProxy
}

// Run starts the HTTP and HTTPS reverse proxy servers and handles SIGHUP reloads.
func Run(opts app.RunOptions) error {
	log.Printf("startup begin pid=%d uid=%d euid=%d run_user=%q force=%t", os.Getpid(), os.Getuid(), os.Geteuid(), opts.RunUser, opts.Force)
	if current, err := user.LookupId(strconv.Itoa(os.Geteuid())); err == nil {
		log.Printf("startup identity user=%q uid=%s gid=%s home=%q", current.Username, current.Uid, current.Gid, current.HomeDir)
	} else {
		log.Printf("startup identity lookup failed: %v", err)
	}
	log.Printf("startup paths config=%q tls_cert=%q tls_key=%q access_log=%q", opts.ConfigPath, opts.TLSCertPath, opts.TLSKeyPath, opts.AccessLogPath)
	logFileMetadata("config", opts.ConfigPath)
	logFileMetadata("tls_cert", opts.TLSCertPath)
	logFileMetadata("tls_key", opts.TLSKeyPath)

	if os.Geteuid() == 0 {
		if err := bootstrapRootRun(opts); err != nil {
			return err
		}
		log.Printf("startup privilege drop complete uid=%d euid=%d user=%q", os.Getuid(), os.Geteuid(), opts.RunUser)
	}

	if err := enforceRuntimeUser(opts); err != nil {
		return err
	}
	log.Printf("runtime user enforcement passed")

	cfg, err := proxycfg.Load(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	routes, err := buildRouteProxies(cfg)
	if err != nil {
		return fmt.Errorf("route config error: %w", err)
	}
	for i, route := range cfg.Routes {
		log.Printf("route configured index=%d path_prefix=%q upstream=%q", i, strings.TrimSpace(route.PathPrefix), strings.TrimSpace(route.Upstream))
	}

	var activeRoutes atomic.Value
	activeRoutes.Store(routes)

	rw, err := newRotatingWriter(opts.AccessLogPath, app.AccessLogRotateSize)
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

	httpSrv := &http.Server{Addr: opts.HTTPAddr, Handler: handler}

	certs, err := newCertReloader(opts.TLSCertPath, opts.TLSKeyPath)
	if err != nil {
		return fmt.Errorf("tls setup error: %w", err)
	}

	httpsSrv := &http.Server{
		Addr:    opts.HTTPSAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certs.GetCertificate,
		},
	}

	log.Printf("httpsd version=%s", app.VersionString())
	log.Printf("httpsd starting http=%s https=%s config=%s access_log=%s routes=%d", opts.HTTPAddr, opts.HTTPSAddr, opts.ConfigPath, opts.AccessLogPath, len(routes))
	log.Printf("reload enabled: send SIGHUP to reload TLS cert/key and proxy config")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		for range sigCh {
			cfgNow, cfgErr := proxycfg.Load(opts.ConfigPath)
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
		log.Printf("listening HTTP on %s", opts.HTTPAddr)
		err := httpSrv.ListenAndServe()
		log.Printf("http server stopped addr=%s err=%v", opts.HTTPAddr, err)
		errCh <- err
	}()
	go func() {
		log.Printf("listening HTTPS on %s", opts.HTTPSAddr)
		tlsListener, listenErr := tls.Listen("tcp", opts.HTTPSAddr, httpsSrv.TLSConfig)
		if listenErr != nil {
			log.Printf("https listener setup failed addr=%s cert=%q key=%q err=%v", opts.HTTPSAddr, opts.TLSCertPath, opts.TLSKeyPath, listenErr)
			errCh <- listenErr
			return
		}
		err := httpsSrv.Serve(tlsListener)
		log.Printf("https server stopped addr=%s err=%v", opts.HTTPSAddr, err)
		errCh <- err
	}()

	return <-errCh
}

func bootstrapRootRun(opts app.RunOptions) error {
	uid, gid, groupIDs, account, err := lookupRuntimeAccount(opts.RunUser)
	if err != nil {
		return err
	}

	if err := validateRuntimeTLSPrepared(opts, uid, gid); err != nil {
		log.Printf("startup root bootstrap: runtime TLS artifacts not ready: %v", err)
		reloadOpts := reloadcmd.DefaultOptions()
		reloadOpts.HTTPAddr = opts.HTTPAddr
		reloadOpts.HTTPSAddr = opts.HTTPSAddr
		reloadOpts.RunUser = opts.RunUser
		reloadOpts.TLSCertDest = opts.TLSCertPath
		reloadOpts.TLSKeyDest = opts.TLSKeyPath
		reloadOpts.PrepareOnly = true
		if err := reloadcmd.Run(reloadOpts); err != nil {
			return fmt.Errorf("startup root bootstrap prepare-only failed: %w", err)
		}
		if err := validateRuntimeTLSPrepared(opts, uid, gid); err != nil {
			return fmt.Errorf("startup root bootstrap validation failed after prepare-only: %w", err)
		}
	} else {
		log.Printf("startup root bootstrap: runtime TLS artifacts already prepared")
	}

	if err := dropPrivileges(uid, gid, groupIDs, account); err != nil {
		return err
	}
	return nil
}

func logFileMetadata(kind, path string) {
	st, err := os.Stat(path)
	if err != nil {
		log.Printf("startup file check kind=%s path=%q err=%v", kind, path, err)
		return
	}
	mode := st.Mode().Perm()
	log.Printf("startup file check kind=%s path=%q mode=%#o size=%d mtime=%s", kind, path, mode, st.Size(), st.ModTime().UTC().Format(time.RFC3339))
}

func enforceRuntimeUser(opts app.RunOptions) error {
	expected := strings.TrimSpace(opts.RunUser)
	if expected == "" {
		return fmt.Errorf("run-user cannot be empty")
	}

	if opts.Force {
		return nil
	}

	current, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		return fmt.Errorf("resolve current user: %w", err)
	}

	if current.Username != expected {
		return fmt.Errorf("refusing to run as user %q; expected %q (use --force to override)", current.Username, expected)
	}

	return nil
}

func lookupRuntimeAccount(name string) (int, int, []int, *user.User, error) {
	account, err := user.Lookup(strings.TrimSpace(name))
	if err != nil {
		return 0, 0, nil, nil, fmt.Errorf("resolve run user %q: %w", name, err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return 0, 0, nil, nil, fmt.Errorf("parse uid for run user %q: %w", name, err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return 0, 0, nil, nil, fmt.Errorf("parse gid for run user %q: %w", name, err)
	}
	groupIDs, err := account.GroupIds()
	if err != nil {
		return 0, 0, nil, nil, fmt.Errorf("resolve supplementary groups for run user %q: %w", name, err)
	}
	parsedGroupIDs := make([]int, 0, len(groupIDs))
	seen := map[int]struct{}{gid: {}}
	parsedGroupIDs = append(parsedGroupIDs, gid)
	for _, raw := range groupIDs {
		groupID, err := strconv.Atoi(raw)
		if err != nil {
			return 0, 0, nil, nil, fmt.Errorf("parse supplementary gid %q for run user %q: %w", raw, name, err)
		}
		if _, ok := seen[groupID]; ok {
			continue
		}
		seen[groupID] = struct{}{}
		parsedGroupIDs = append(parsedGroupIDs, groupID)
	}
	sort.Ints(parsedGroupIDs)
	return uid, gid, parsedGroupIDs, account, nil
}

func validateRuntimeTLSPrepared(opts app.RunOptions, uid, gid int) error {
	runtimeDir := filepath.Clean(filepath.Dir(opts.TLSCertPath))
	if runtimeDir != filepath.Clean(filepath.Dir(opts.TLSKeyPath)) {
		return fmt.Errorf("tls cert and key must share one runtime directory")
	}
	if err := validateOwnedPath(runtimeDir, uid, gid, 0o750, true); err != nil {
		return fmt.Errorf("runtime dir %s: %w", runtimeDir, err)
	}
	if err := validateOwnedPath(opts.TLSCertPath, uid, gid, 0o640, false); err != nil {
		return fmt.Errorf("tls cert %s: %w", opts.TLSCertPath, err)
	}
	if err := validateOwnedPath(opts.TLSKeyPath, uid, gid, 0o600, false); err != nil {
		return fmt.Errorf("tls key %s: %w", opts.TLSKeyPath, err)
	}
	return nil
}

func validateOwnedPath(path string, uid, gid int, mode os.FileMode, wantDir bool) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() != wantDir {
		if wantDir {
			return fmt.Errorf("is not a directory")
		}
		return fmt.Errorf("is not a regular file")
	}
	if st.Mode().Perm() != mode {
		return fmt.Errorf("mode=%#o want=%#o", st.Mode().Perm(), mode)
	}
	statT, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("stat owner metadata unavailable")
	}
	if int(statT.Uid) != uid || int(statT.Gid) != gid {
		return fmt.Errorf("owner uid=%d gid=%d want uid=%d gid=%d", statT.Uid, statT.Gid, uid, gid)
	}
	return nil
}

func dropPrivileges(uid, gid int, groupIDs []int, account *user.User) error {
	if err := syscall.Setgroups(groupIDs); err != nil {
		return fmt.Errorf("set supplementary groups for %q: %w", account.Username, err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("set gid=%d for %q: %w", gid, account.Username, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("set uid=%d for %q: %w", uid, account.Username, err)
	}
	if err := os.Setenv("HOME", account.HomeDir); err != nil {
		return fmt.Errorf("set HOME for %q: %w", account.Username, err)
	}
	if err := os.Setenv("USER", account.Username); err != nil {
		return fmt.Errorf("set USER for %q: %w", account.Username, err)
	}
	if err := os.Setenv("LOGNAME", account.Username); err != nil {
		return fmt.Errorf("set LOGNAME for %q: %w", account.Username, err)
	}
	return nil
}

func buildRouteProxies(cfg *proxycfg.Config) ([]routeProxy, error) {
	routes := make([]routeProxy, 0, len(cfg.Routes))

	for _, r := range cfg.Routes {
		prefix := strings.TrimSpace(r.PathPrefix)
		if prefix == "" {
			prefix = "/"
		}

		u, err := url.Parse(r.Upstream)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("invalid upstream for prefix %q: %q", prefix, r.Upstream)
		}
		upstream := u.String()
		pool, err := newUpstreamPool(u)
		if err != nil {
			return nil, fmt.Errorf("prepare upstream pool for prefix %q: %w", prefix, err)
		}

		proxy := httputil.NewSingleHostReverseProxy(u)
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			setForwardedHeaders(req)
		}
		proxy.Transport = newUpstreamTransport(pool)
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

func setForwardedHeaders(req *http.Request) {
	clientAddr := requestRemoteIP(req)
	proto := requestScheme(req)
	port := requestPort(req, proto)
	host := req.Host

	req.Header.Set("X-Real-IP", clientAddr)
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-Proto", proto)
	req.Header.Set("X-Forwarded-Port", port)

	forwardedValue := fmt.Sprintf("for=%s;host=%q;proto=%s", formatForwardedFor(clientAddr), host, proto)
	if existing := strings.TrimSpace(req.Header.Get("Forwarded")); existing != "" {
		req.Header.Set("Forwarded", existing+", "+forwardedValue)
		return
	}
	req.Header.Set("Forwarded", forwardedValue)
}

func requestRemoteIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

func requestScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

func requestPort(req *http.Request, proto string) string {
	if _, port, err := net.SplitHostPort(req.Host); err == nil && port != "" {
		return port
	}

	switch proto {
	case "https":
		return "443"
	default:
		return "80"
	}
}

func formatForwardedFor(ip string) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("\"[%s]\"", ip)
	}
	return fmt.Sprintf("\"%s\"", ip)
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
