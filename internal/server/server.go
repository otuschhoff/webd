package server

import (
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

	"webd/internal/app"
)

type routeProxy struct {
	prefix            string
	redirectTarget    string
	proxy             *httputil.ReverseProxy
	localHandler      http.Handler
	allowedIPv4Ranges []IPv4Range
}

const (
	acmeChallengeURLPrefix = "/.well-known/acme-challenge/"
	acmeChallengeJailDir   = "/acme-challenge"
)

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
	logs, err := app.New("webd", true)
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
		opsLog.Printf("route configured index=%d path=%q target=%s", i, strings.TrimSpace(route.Path), formatRouteTarget(route))
	}

	var activeRoutes atomic.Value
	activeRoutes.Store(routes)
	defer closeRouteProxies(activeRoutes.Load().([]routeProxy))

	router := newRequestRouter(&activeRoutes, errLog)
	handler := accessLogMiddleware(router, accessLog)

	httpSrv := &http.Server{Addr: opts.HTTPAddr, Handler: handler}
	httpSrv.SetKeepAlivesEnabled(true)

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
	httpsSrv.SetKeepAlivesEnabled(true)

	opsLog.Printf("webd version=%s", app.VersionString())
	opsLog.Printf("webd starting http=%s https=%s config=%s routes=%d", opts.HTTPAddr, opts.HTTPSAddr, opts.ConfigPath, len(routes))
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
		prefix := strings.TrimSpace(r.Path)
		if prefix == "" {
			prefix = "/"
		}

		if strings.TrimSpace(r.Redirect) != "" {
			routes = append(routes, routeProxy{
				prefix:            prefix,
				redirectTarget:    strings.TrimSpace(r.Redirect),
				allowedIPv4Ranges: append([]IPv4Range(nil), r.AllowedIPv4Ranges...),
			})
			continue
		}

		if r.Handler == nil {
			return nil, fmt.Errorf("route for path %q has no handler", prefix)
		}
		handlerCfg := *r.Handler
		if strings.EqualFold(strings.TrimSpace(handlerCfg.Protocol), "file") {
			localHandler, localErr := newLocalFileHandler(prefix, handlerCfg.Path, r.Browse)
			if localErr != nil {
				return nil, fmt.Errorf("configure local file handler for path %q: %w", prefix, localErr)
			}
			routes = append(routes, routeProxy{prefix: prefix, localHandler: localHandler, allowedIPv4Ranges: append([]IPv4Range(nil), r.AllowedIPv4Ranges...)})
			continue
		}

		targetURL := handlerURL(handlerCfg)
		handler := targetURL.String()

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.BufferPool = reverseProxyBufferPool
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			handleProxyForwardedHeaders(req)
		}
		transport, transportErr := handleProxyTransport(handlerCfg)
		if transportErr != nil {
			return nil, fmt.Errorf("configure transport for path %q: %w", prefix, transportErr)
		}
		proxy.Transport = transport
		proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, proxyErr error) {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			errLog.Printf("proxy_error handler=%q path=%q err=%v", handler, req.URL.Path, proxyErr)
		}

		routes = append(routes, routeProxy{prefix: prefix, proxy: proxy, allowedIPv4Ranges: append([]IPv4Range(nil), r.AllowedIPv4Ranges...)})
	}

	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].prefix) > len(routes[j].prefix)
	})

	return routes, nil
}

func isClientIPv4Allowed(rawIP string, ranges []IPv4Range) bool {
	parsed := net.ParseIP(strings.TrimSpace(rawIP))
	if parsed == nil {
		return false
	}
	v4 := parsed.To4()
	if v4 == nil {
		return false
	}
	n := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	for _, r := range ranges {
		if n >= r.Start && n <= r.End {
			return true
		}
	}
	return false
}

func handlerURL(handler Handler) *url.URL {
	host := net.JoinHostPort(handler.Hostname, strconv.Itoa(handler.Port))
	return &url.URL{
		Scheme:   proxyScheme(handler.Protocol),
		Host:     host,
		Path:     handler.Path,
		RawQuery: handler.RawQuery,
	}
}

func formatHandler(handler Handler) string {
	host := net.JoinHostPort(handler.Hostname, strconv.Itoa(handler.Port))
	return (&url.URL{
		Scheme:   handler.Protocol,
		Host:     host,
		Path:     handler.Path,
		RawQuery: handler.RawQuery,
	}).String()
}

func formatRouteTarget(route Route) string {
	if strings.TrimSpace(route.Redirect) != "" {
		return "redirect:" + strings.TrimSpace(route.Redirect)
	}
	if route.Handler == nil {
		return "<invalid>"
	}
	if strings.EqualFold(strings.TrimSpace(route.Handler.Protocol), "file") {
		return "handler:file://" + route.Handler.Path
	}
	return formatHandler(*route.Handler)
}

func proxyScheme(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "ws":
		return "http"
	case "wss":
		return "https"
	default:
		return protocol
	}
}

func usesTLSHandler(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "https", "wss":
		return true
	default:
		return false
	}
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
			"t=%s i=%s x=%s u=%s c=%d b=%d d=%d a=%s",
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
