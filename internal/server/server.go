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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"httpsd/internal/app"
	"httpsd/internal/proxycfg"
)

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
func Run(opts app.RunOptions) error {
	log.Printf("startup begin pid=%d uid=%d euid=%d", os.Getpid(), os.Getuid(), os.Geteuid())
	log.Printf("startup paths config=%q tls_cert=%q tls_key=%q access_log=%q", opts.ConfigPath, opts.TLSCertPath, opts.TLSKeyPath, opts.AccessLogPath)

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
	defer closeRouteProxies(activeRoutes.Load().([]routeProxy))

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
					oldRoutes := activeRoutes.Load().([]routeProxy)
					activeRoutes.Store(reloadedRoutes)
					closeRouteProxies(oldRoutes)
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
		proxy.BufferPool = reverseProxyBufferPool
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
