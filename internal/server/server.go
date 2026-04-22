package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
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
	websocketProxy    *httputil.ReverseProxy
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
		ops := formatRouteTarget(route)
		if route.WebsocketHandler != nil {
			ops += " websocket=" + formatHandler(*route.WebsocketHandler)
		}
		opsLog.Printf("route configured index=%d path=%q target=%s", i, strings.TrimSpace(route.Path), ops)
	}

	var activeRoutes atomic.Value
	activeRoutes.Store(routes)
	defer closeRouteProxies(activeRoutes.Load().([]routeProxy))

	router := newRequestRouter(&activeRoutes, errLog, opts.HTTPSAddr)
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
		closeProxyTransport(route.proxy)
		closeProxyTransport(route.websocketProxy)
	}
}

func closeProxyTransport(proxy *httputil.ReverseProxy) {
	if proxy == nil || proxy.Transport == nil {
		return
	}
	if closer, ok := proxy.Transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
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
		configureRouteProxyDirector(proxy, targetURL, prefix)

		var locationRewriteRe *regexp.Regexp
		locationReplace := ""
		if r.RewriteLocation != nil {
			compiled, compileErr := regexp.Compile(normalizeRegexPattern(r.RewriteLocation.Match))
			if compileErr != nil {
				return nil, fmt.Errorf("compile rewrite_location.match for path %q: %w", prefix, compileErr)
			}
			locationRewriteRe = compiled
			locationReplace = r.RewriteLocation.Replace
		}
		rewriteBaseHref := true
		if r.RewriteBaseHref != nil {
			rewriteBaseHref = *r.RewriteBaseHref
		}
		configureLocationHeaderRewrite(proxy, locationRewriteRe, locationReplace, rewriteBaseHref, prefix, targetURL.Path)
		transport, transportErr := handleProxyTransport(handlerCfg)
		if transportErr != nil {
			return nil, fmt.Errorf("configure transport for path %q: %w", prefix, transportErr)
		}
		proxy.Transport = transport
		proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, proxyErr error) {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			errLog.Printf("proxy_error handler=%q path=%q err=%v", handler, req.URL.Path, proxyErr)
		}

		var wsProxy *httputil.ReverseProxy
		if r.WebsocketHandler != nil {
			wsCfg := *r.WebsocketHandler
			wsTargetURL := handlerURL(wsCfg)
			wsTarget := wsTargetURL.String()
			wsProxy = httputil.NewSingleHostReverseProxy(wsTargetURL)
			wsProxy.BufferPool = reverseProxyBufferPool
			configureRouteProxyDirector(wsProxy, wsTargetURL, prefix)
			configureLocationHeaderRewrite(wsProxy, locationRewriteRe, locationReplace, rewriteBaseHref, prefix, wsTargetURL.Path)
			wsTransport, wsTransportErr := handleProxyTransport(wsCfg)
			if wsTransportErr != nil {
				return nil, fmt.Errorf("configure websocket transport for path %q: %w", prefix, wsTransportErr)
			}
			wsProxy.Transport = wsTransport
			wsProxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, proxyErr error) {
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
				errLog.Printf("websocket_proxy_error handler=%q path=%q err=%v", wsTarget, req.URL.Path, proxyErr)
			}
		}

		routes = append(routes, routeProxy{
			prefix:            prefix,
			proxy:             proxy,
			websocketProxy:    wsProxy,
			allowedIPv4Ranges: append([]IPv4Range(nil), r.AllowedIPv4Ranges...),
		})
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

func configureRouteProxyDirector(proxy *httputil.ReverseProxy, target *url.URL, routePrefix string) {
	targetQuery := target.RawQuery
	proxy.Director = func(req *http.Request) {
		trimmedPath, trimmedRawPath := trimRoutePrefix(req.URL.Path, req.URL.RawPath, routePrefix)

		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = joinProxyPath(target.Path, trimmedPath)
		req.URL.RawPath = joinProxyPath(target.RawPath, trimmedRawPath)

		switch {
		case targetQuery == "":
			// keep request query as-is
		case req.URL.RawQuery == "":
			req.URL.RawQuery = targetQuery
		default:
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}

		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
		handleProxyForwardedHeaders(req)
	}
}

func trimRoutePrefix(path, rawPath, routePrefix string) (string, string) {
	prefix := strings.TrimSpace(routePrefix)
	if prefix == "" || prefix == "/" {
		return path, rawPath
	}
	prefix = strings.TrimRight(prefix, "/")

	trimmedPath := path
	if path == prefix {
		trimmedPath = ""
	} else if strings.HasPrefix(path, prefix+"/") {
		trimmedPath = path[len(prefix):]
	}

	trimmedRawPath := rawPath
	if rawPath != "" {
		if rawPath == prefix {
			trimmedRawPath = ""
		} else if strings.HasPrefix(rawPath, prefix+"/") {
			trimmedRawPath = rawPath[len(prefix):]
		}
	}

	return trimmedPath, trimmedRawPath
}

func joinProxyPath(base, suffix string) string {
	if suffix == "" {
		if base == "" {
			return "/"
		}
		return base
	}
	if base == "" {
		return suffix
	}
	aslash := strings.HasSuffix(base, "/")
	bslash := strings.HasPrefix(suffix, "/")
	switch {
	case aslash && bslash:
		return base + suffix[1:]
	case !aslash && !bslash:
		return base + "/" + suffix
	}
	return base + suffix
}

func configureLocationHeaderRewrite(proxy *httputil.ReverseProxy, matchRe *regexp.Regexp, replace string, rewriteBaseHref bool, routePrefix, handlerBasePath string) {
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp == nil {
			return nil
		}
		location := resp.Header.Get("Location")
		if location == "" {
			// no location header rewrite needed
		} else {
			rewritten := rewriteLocationToRequestHTTPS(location, resp.Request)
			if matchRe != nil {
				rewritten = matchRe.ReplaceAllString(rewritten, replace)
			}
			if rewritten != location {
				resp.Header.Set("Location", rewritten)
			}
		}

		if rewriteBaseHref {
			if err := rewriteHTMLBaseHref(resp, routePrefix, handlerBasePath); err != nil {
				return err
			}
		}
		return nil
	}
}

func rewriteHTMLBaseHref(resp *http.Response, routePrefix, handlerBasePath string) error {
	if resp == nil || resp.Body == nil {
		return nil
	}
	contentType := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "application/xhtml+xml") {
		return nil
	}
	contentEncoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if contentEncoding != "" && contentEncoding != "identity" {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	baseHref := desiredFrontendBaseHref(routePrefix, handlerBasePath, resp.Request)
	rewrittenBody, changed := injectOrReplaceBaseHref(body, baseHref)
	if !changed {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return nil
	}

	resp.Body = io.NopCloser(bytes.NewReader(rewrittenBody))
	resp.ContentLength = int64(len(rewrittenBody))
	resp.Header.Set("Content-Length", strconv.Itoa(len(rewrittenBody)))
	return nil
}

func desiredFrontendBaseHref(routePrefix, handlerBasePath string, req *http.Request) string {
	backendPath := "/"
	if req != nil && req.URL != nil && strings.TrimSpace(req.URL.Path) != "" {
		backendPath = req.URL.Path
	}
	rel := stripBasePathPrefix(backendPath, handlerBasePath)
	dir := path.Dir(rel)
	if dir == "." {
		dir = "/"
	}
	if !strings.HasPrefix(dir, "/") {
		dir = "/" + dir
	}
	frontend := joinProxyPath(normalizeRoutePrefix(routePrefix), dir)
	if frontend == "" {
		frontend = "/"
	}
	if !strings.HasSuffix(frontend, "/") {
		frontend += "/"
	}
	return frontend
}

func stripBasePathPrefix(fullPath, basePath string) string {
	full := strings.TrimSpace(fullPath)
	if full == "" {
		full = "/"
	}
	if !strings.HasPrefix(full, "/") {
		full = "/" + full
	}

	base := strings.TrimSpace(basePath)
	if base == "" || base == "/" {
		return full
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	base = strings.TrimRight(base, "/")

	if full == base {
		return "/"
	}
	if strings.HasPrefix(full, base+"/") {
		return full[len(base):]
	}
	return full
}

func normalizeRoutePrefix(routePrefix string) string {
	p := strings.TrimSpace(routePrefix)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if p != "/" {
		p = strings.TrimRight(p, "/")
	}
	return p
}

var (
	headTagRe      = regexp.MustCompile(`(?is)<head\b[^>]*>`)
	headCloseTagRe = regexp.MustCompile(`(?is)</head\s*>`)
	baseTagRe      = regexp.MustCompile(`(?is)<base\b[^>]*>`)
	htmlTagRe      = regexp.MustCompile(`(?is)<html\b[^>]*>`)
	bodyTagRe      = regexp.MustCompile(`(?is)<body\b[^>]*>`)
	hrefAttrRe     = regexp.MustCompile(`(?is)\bhref\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
)

func injectOrReplaceBaseHref(body []byte, href string) ([]byte, bool) {
	doc := string(body)
	baseTag := `<base href="` + href + `">`

	headLoc := headTagRe.FindStringIndex(doc)
	if headLoc == nil {
		insert := `<head>` + baseTag + `</head>`
		if htmlLoc := htmlTagRe.FindStringIndex(doc); htmlLoc != nil {
			out := doc[:htmlLoc[1]] + insert + doc[htmlLoc[1]:]
			return []byte(out), true
		}
		if bodyLoc := bodyTagRe.FindStringIndex(doc); bodyLoc != nil {
			out := doc[:bodyLoc[0]] + insert + doc[bodyLoc[0]:]
			return []byte(out), true
		}
		out := insert + doc
		return []byte(out), true
	}

	headStart := headLoc[1]
	headRest := doc[headStart:]
	headCloseRel := headCloseTagRe.FindStringIndex(headRest)
	headEnd := len(doc)
	if headCloseRel != nil {
		headEnd = headStart + headCloseRel[0]
	}

	headInner := doc[headStart:headEnd]
	baseLoc := baseTagRe.FindStringIndex(headInner)
	if baseLoc != nil {
		orig := headInner[baseLoc[0]:baseLoc[1]]
		repl := replaceOrInsertHrefAttr(orig, href)
		if repl == orig {
			return body, false
		}
		out := doc[:headStart+baseLoc[0]] + repl + doc[headStart+baseLoc[1]:]
		return []byte(out), true
	}

	out := doc[:headStart] + baseTag + doc[headStart:]
	return []byte(out), true
}

func replaceOrInsertHrefAttr(baseTag, href string) string {
	hrefQuoted := `"` + href + `"`
	if loc := hrefAttrRe.FindStringIndex(baseTag); loc != nil {
		return baseTag[:loc[0]] + "href=" + hrefQuoted + baseTag[loc[1]:]
	}
	trimmed := strings.TrimRight(baseTag, ">")
	if strings.HasSuffix(trimmed, "/") {
		trimmed = strings.TrimRight(strings.TrimSpace(trimmed[:len(trimmed)-1]), " ")
		return trimmed + " href=" + hrefQuoted + "/>"
	}
	return trimmed + " href=" + hrefQuoted + ">"
}

func rewriteLocationToRequestHTTPS(location string, req *http.Request) string {
	if req == nil {
		return location
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return location
	}
	if parsed.Host == "" && parsed.Scheme == "" && !strings.HasPrefix(location, "//") {
		return location
	}

	requestHost := requestFQDN(req.Host)
	if requestHost == "" {
		return location
	}

	parsed.Scheme = "https"
	parsed.Host = requestHost
	return parsed.String()
}

func requestFQDN(host string) string {
	hostname, _ := splitRequestHostPort(host)
	if hostname != "" {
		return hostname
	}
	trimmed := strings.TrimSpace(host)
	if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		return strings.Trim(trimmed, "[]")
	}
	return trimmed
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

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
	}
	return h.Hijack()
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
