package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultConfigPath   = "/etc/httpsd/config.json"
	defaultTLSCertPath  = "/etc/pki/tls/certs/selfcrt"
	defaultTLSKeyPath   = "/etc/pki/tls/private/self.key"
	defaultAccessLog    = "/var/log/httpsd/access.log"
	defaultHTTPAddr     = ":80"
	defaultHTTPSAddr    = ":443"
	accessLogRotateSize = 1 * 1024 * 1024
)

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

	return &rotatingWriter{
		path:     path,
		maxBytes: maxBytes,
		file:     f,
		size:     st.Size(),
	}, nil
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

	// Longest prefix wins to keep path routing deterministic.
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

func main() {
	configPath := flag.String("config", defaultConfigPath, "Path to JSON reverse-proxy config")
	httpAddr := flag.String("http-addr", defaultHTTPAddr, "HTTP listen address")
	httpsAddr := flag.String("https-addr", defaultHTTPSAddr, "HTTPS listen address")
	tlsCert := flag.String("tls-cert", defaultTLSCertPath, "TLS certificate file")
	tlsKey := flag.String("tls-key", defaultTLSKeyPath, "TLS private key file")
	accessLogPath := flag.String("access-log", defaultAccessLog, "Access log path")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	routes, err := buildRouteProxies(cfg)
	if err != nil {
		log.Fatalf("route config error: %v", err)
	}

	var activeRoutes atomic.Value
	activeRoutes.Store(routes)

	rw, err := newRotatingWriter(*accessLogPath, accessLogRotateSize)
	if err != nil {
		log.Fatalf("access log setup error: %v", err)
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

	httpSrv := &http.Server{
		Addr:    *httpAddr,
		Handler: handler,
	}

	certs, err := newCertReloader(*tlsCert, *tlsKey)
	if err != nil {
		log.Fatalf("tls setup error: %v", err)
	}

	httpsSrv := &http.Server{
		Addr:    *httpsAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certs.GetCertificate,
		},
	}

	log.Printf("httpsd starting http=%s https=%s config=%s access_log=%s routes=%d", *httpAddr, *httpsAddr, *configPath, *accessLogPath, len(routes))
	log.Printf("reload enabled: send SIGHUP to reload TLS cert/key and proxy config")

	// Reload certificate files on SIGHUP without restarting listeners.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		for range sigCh {
			cfg, cfgErr := loadConfig(*configPath)
			if cfgErr != nil {
				log.Printf("config reload failed: %v", cfgErr)
			} else {
				reloadedRoutes, routesErr := buildRouteProxies(cfg)
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
		log.Printf("listening HTTP on %s", *httpAddr)
		errCh <- httpSrv.ListenAndServe()
	}()
	go func() {
		log.Printf("listening HTTPS on %s", *httpsAddr)
		tlsListener, listenErr := tls.Listen("tcp", *httpsAddr, httpsSrv.TLSConfig)
		if listenErr != nil {
			errCh <- listenErr
			return
		}
		errCh <- httpsSrv.Serve(tlsListener)
	}()

	err = <-errCh
	log.Fatalf("server exited: %v", err)
}
