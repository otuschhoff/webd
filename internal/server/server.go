package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"httpsd/internal/app"
	"httpsd/internal/syslogx"
)

// RunOptions defines daemon runtime options accepted by Run.
// It aliases app.RunOptions so callers of internal/server do not need to import internal/app.
type RunOptions = app.RunOptions

type routeProxy struct {
	prefix string
	proxy  *httputil.ReverseProxy
}

var reverseProxyBufferPool = &byteSlicePool{pool: sync.Pool{}}

type byteSlicePool struct {
	pool sync.Pool
}

func (p *byteSlicePool) Get() []byte {
	if buf, ok := p.pool.Get().([]byte); ok && len(buf) == 32*1024 {
		return buf
	}
	return make([]byte, 32*1024)
}

func (p *byteSlicePool) Put(b []byte) {
	if cap(b) < 32*1024 {
		return
	}
	p.pool.Put(b[:32*1024])
}

// Run starts the HTTP and HTTPS reverse proxy servers and handles SIGHUP reloads.
func Run(opts RunOptions) error {
	logs, err := syslogx.New("httpsd", true)
	if err != nil {
		return fmt.Errorf("setup syslog loggers: %w", err)
	}
	defer func() {
		_ = logs.Close()
	}()

	opsLog := logs.Ops
	errLog := logs.Error
	accessLog := logs.Access

	opsLog.Printf("startup begin pid=%d uid=%d euid=%d", os.Getpid(), os.Getuid(), os.Geteuid())
	opsLog.Printf("startup paths config=%q tls_cert=%q tls_key=%q", opts.ConfigPath, opts.TLSCertPath, opts.TLSKeyPath)

	cfg, err := LoadJSON(opts.ConfigPath)
	if err != nil {
		errLog.Printf("config load failed path=%q err=%v", opts.ConfigPath, err)
		return fmt.Errorf("config error: %w", err)
	}

	routes, err := buildRouteProxies(cfg, errLog)
	if err != nil {
		errLog.Printf("route config build failed err=%v", err)
		return fmt.Errorf("route config error: %w", err)
	}
	for i, route := range cfg.Routes {
		opsLog.Printf("route configured index=%d path_prefix=%q upstream=%s", i, strings.TrimSpace(route.PathPrefix), formatUpstream(route.Upstream))
	}

	var activeRoutes atomic.Value
	activeRoutes.Store(routes)
	defer closeRouteProxies(activeRoutes.Load().([]routeProxy))

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
	handler := accessLogMiddleware(router, accessLog)

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

	opsLog.Printf("httpsd version=%s", app.VersionString())
	opsLog.Printf("httpsd starting http=%s https=%s config=%s routes=%d", opts.HTTPAddr, opts.HTTPSAddr, opts.ConfigPath, len(routes))
	opsLog.Printf("reload enabled: send SIGHUP to reload TLS cert/key and proxy config")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		for range sigCh {
			cfgNow, cfgErr := LoadJSON(opts.ConfigPath)
			if cfgErr != nil {
				errLog.Printf("config reload failed: %v", cfgErr)
			} else {
				reloadedRoutes, routesErr := buildRouteProxies(cfgNow, errLog)
				if routesErr != nil {
					errLog.Printf("route reload failed: %v", routesErr)
				} else {
					oldRoutes := activeRoutes.Load().([]routeProxy)
					activeRoutes.Store(reloadedRoutes)
					closeRouteProxies(oldRoutes)
					opsLog.Printf("proxy routes reloaded successfully: routes=%d", len(reloadedRoutes))
				}
			}

			if reloadErr := certs.Reload(); reloadErr != nil {
				errLog.Printf("tls reload failed: %v", reloadErr)
				continue
			}
			opsLog.Printf("tls cert/key reloaded successfully")
		}
	}()

	errCh := make(chan error, 2)
	go func() {
		opsLog.Printf("listening HTTP on %s", opts.HTTPAddr)
		err := httpSrv.ListenAndServe()
		if err != nil {
			errLog.Printf("http server stopped addr=%s err=%v", opts.HTTPAddr, err)
		} else {
			opsLog.Printf("http server stopped addr=%s", opts.HTTPAddr)
		}
		errCh <- err
	}()
	go func() {
		opsLog.Printf("listening HTTPS on %s", opts.HTTPSAddr)
		tlsListener, listenErr := tls.Listen("tcp", opts.HTTPSAddr, httpsSrv.TLSConfig)
		if listenErr != nil {
			errLog.Printf("https listener setup failed addr=%s cert=%q key=%q err=%v", opts.HTTPSAddr, opts.TLSCertPath, opts.TLSKeyPath, listenErr)
			errCh <- listenErr
			return
		}
		err := httpsSrv.Serve(tlsListener)
		if err != nil {
			errLog.Printf("https server stopped addr=%s err=%v", opts.HTTPSAddr, err)
		} else {
			opsLog.Printf("https server stopped addr=%s", opts.HTTPSAddr)
		}
		errCh <- err
	}()

	return <-errCh
}

func closeRouteProxies(routes []routeProxy) {
	for _, route := range routes {
		if route.proxy == nil || route.proxy.Transport == nil {
			continue
		}
		if closer, ok := route.proxy.Transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

func buildRouteProxies(cfg *Config, errLog *log.Logger) ([]routeProxy, error) {
	routes := make([]routeProxy, 0, len(cfg.Routes))

	for _, r := range cfg.Routes {
		prefix := strings.TrimSpace(r.PathPrefix)
		if prefix == "" {
			prefix = "/"
		}

		targetURL := upstreamURL(r.Upstream)
		upstream := targetURL.String()

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.BufferPool = reverseProxyBufferPool
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			setForwardedHeaders(req)
		}
		transport, transportErr := newStaticUpstreamTransport(r.Upstream)
		if transportErr != nil {
			return nil, fmt.Errorf("configure transport for prefix %q: %w", prefix, transportErr)
		}
		proxy.Transport = transport
		proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, proxyErr error) {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			errLog.Printf("proxy_error upstream=%q path=%q err=%v", upstream, req.URL.Path, proxyErr)
		}

		routes = append(routes, routeProxy{prefix: prefix, proxy: proxy})
	}

	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].prefix) > len(routes[j].prefix)
	})

	return routes, nil
}

func newStaticUpstreamTransport(upstream Upstream) (http.RoundTripper, error) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	addresses := append([]string(nil), upstream.IPv4Addresses...)
	port := strconv.Itoa(upstream.Port)
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if len(addresses) == 0 {
			return nil, fmt.Errorf("no upstream IPv4 addresses configured")
		}
		errs := make([]string, 0, len(addresses))
		for _, rawIP := range addresses {
			addr := net.JoinHostPort(rawIP, port)
			conn, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				return conn, nil
			}
			errs = append(errs, fmt.Sprintf("%s: %v", rawIP, err))
		}
		return nil, fmt.Errorf("dial upstream %s:%s failed: %s", upstream.Hostname, port, strings.Join(errs, "; "))
	}

	if strings.EqualFold(upstream.Protocol, "https") {
		if base.TLSClientConfig == nil {
			base.TLSClientConfig = &tls.Config{}
		} else {
			base.TLSClientConfig = base.TLSClientConfig.Clone()
		}
		if upstream.Hostname != "" {
			base.TLSClientConfig.ServerName = upstream.Hostname
		}
		if upstream.TrustedCA != nil {
			pool, err := loadTrustedCertPool(upstream.TrustedCA.File)
			if err != nil {
				return nil, fmt.Errorf("load trusted_ca %q from %s: %w", upstream.TrustedCA.Name, upstream.TrustedCA.File, err)
			}
			base.TLSClientConfig.RootCAs = pool
		}
	}
	return base, nil
}

func upstreamURL(upstream Upstream) *url.URL {
	host := net.JoinHostPort(upstream.Hostname, strconv.Itoa(upstream.Port))
	return &url.URL{
		Scheme:   upstream.Protocol,
		Host:     host,
		Path:     upstream.Path,
		RawQuery: upstream.RawQuery,
	}
}

func formatUpstream(upstream Upstream) string {
	return upstreamURL(upstream).String()
}

func loadTrustedCertPool(certPath string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", certPath, err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}
	return pool, nil
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
