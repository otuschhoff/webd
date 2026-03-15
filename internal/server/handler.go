package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func newRequestRouter(activeRoutes *atomic.Value, errLog *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleIncomingRequest(w, r, activeRoutes, errLog)
	})
}

func handleIncomingRequest(w http.ResponseWriter, r *http.Request, activeRoutes *atomic.Value, errLog *log.Logger) {
	if handleACMEChallengeRequest(w, r, errLog) {
		return
	}

	routesNow := activeRoutes.Load().([]routeProxy)
	if handleRouteRequest(w, r, routesNow, errLog) {
		return
	}

	handleNotFoundRequest(w, r)
}

func handleACMEChallengeRequest(w http.ResponseWriter, r *http.Request, errLog *log.Logger) bool {
	if !strings.HasPrefix(r.URL.Path, acmeChallengeURLPrefix) {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return true
	}

	token := strings.TrimPrefix(r.URL.Path, acmeChallengeURLPrefix)
	if token == "" || strings.Contains(token, "/") || strings.Contains(token, "\\") || strings.Contains(token, "..") {
		http.NotFound(w, r)
		return true
	}

	path := filepath.Join(acmeChallengeJailDir, filepath.Base(token))
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return true
		}
		errLog.Printf("acme_challenge_read_failed path=%q err=%v", path, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return true
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return true
	}
	_, _ = w.Write(b)
	return true
}

func handleRouteRequest(w http.ResponseWriter, r *http.Request, routes []routeProxy, errLog *log.Logger) bool {
	clientIP := handleRequestRemoteIP(r)
	for _, route := range routes {
		if strings.HasPrefix(r.URL.Path, route.prefix) {
			return handleMatchedRouteRequest(w, r, route, clientIP, errLog)
		}
	}
	return false
}

func handleMatchedRouteRequest(w http.ResponseWriter, r *http.Request, route routeProxy, clientIP string, errLog *log.Logger) bool {
	if len(route.allowedIPv4Ranges) > 0 && !isClientIPv4Allowed(clientIP, route.allowedIPv4Ranges) {
		handleForbiddenRequest(w, r, route.prefix, clientIP, errLog)
		return true
	}
	if route.redirectTarget != "" {
		handleRedirectRequest(w, r, route.redirectTarget)
		return true
	}
	if route.localHandler != nil {
		handleLocalFileRequest(w, r, route.localHandler)
		return true
	}
	if route.proxy == nil {
		handleNotFoundRequest(w, r)
		return true
	}
	handleProxyRequest(w, r, route.proxy)
	return true
}

func handleForbiddenRequest(w http.ResponseWriter, r *http.Request, routePrefix, clientIP string, errLog *log.Logger) {
	http.Error(w, "Forbidden", http.StatusForbidden)
	errLog.Printf("access_denied path=%q route_prefix=%q client_ip=%q reason=client_ip_not_allowed", r.URL.Path, routePrefix, clientIP)
}

func handleRedirectRequest(w http.ResponseWriter, r *http.Request, target string) {
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func handleProxyRequest(w http.ResponseWriter, r *http.Request, proxy http.Handler) {
	proxy.ServeHTTP(w, r)
}

func handleLocalFileRequest(w http.ResponseWriter, r *http.Request, localHandler http.Handler) {
	localHandler.ServeHTTP(w, r)
}

func handleNotFoundRequest(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func handleProxyTransport(handler Handler) (http.RoundTripper, error) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DisableKeepAlives = false
	base.MaxIdleConns = 1024
	base.MaxIdleConnsPerHost = 1024
	base.IdleConnTimeout = 0
	base.MaxConnsPerHost = 0
	base.ForceAttemptHTTP2 = true
	base.TLSHandshakeTimeout = 10 * time.Second
	base.ExpectContinueTimeout = 1 * time.Second
	addresses := append([]string(nil), handler.IPv4Addresses...)
	port := strconv.Itoa(handler.Port)
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if len(addresses) == 0 {
			return nil, fmt.Errorf("no handler IPv4 addresses configured")
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
		return nil, fmt.Errorf("dial handler %s:%s failed: %s", handler.Hostname, port, strings.Join(errs, "; "))
	}

	if usesTLSHandler(handler.Protocol) {
		if base.TLSClientConfig == nil {
			base.TLSClientConfig = &tls.Config{}
		} else {
			base.TLSClientConfig = base.TLSClientConfig.Clone()
		}
		if handler.Hostname != "" {
			base.TLSClientConfig.ServerName = handler.Hostname
		}
		if handler.TrustedCA != nil {
			pool, err := loadTrustedCertPool(handler.TrustedCA.File)
			if err != nil {
				return nil, fmt.Errorf("load trusted_ca %q from %s: %w", handler.TrustedCA.Name, handler.TrustedCA.File, err)
			}
			base.TLSClientConfig.RootCAs = pool
		}
	}
	return base, nil
}

func handleProxyForwardedHeaders(req *http.Request) {
	clientAddr := handleRequestRemoteIP(req)
	proto := handleRequestScheme(req)
	port := handleRequestPort(req, proto)
	host := req.Host

	req.Header.Set("X-Real-IP", clientAddr)
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-Proto", proto)
	req.Header.Set("X-Forwarded-Port", port)

	forwardedValue := fmt.Sprintf("for=%s;host=%q;proto=%s", handleFormatForwardedFor(clientAddr), host, proto)
	if existing := strings.TrimSpace(req.Header.Get("Forwarded")); existing != "" {
		req.Header.Set("Forwarded", existing+", "+forwardedValue)
		return
	}
	req.Header.Set("Forwarded", forwardedValue)
}

func handleRequestRemoteIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

func handleRequestScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

func handleRequestPort(req *http.Request, proto string) string {
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

func handleFormatForwardedFor(ip string) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("\"[%s]\"", ip)
	}
	return fmt.Sprintf("\"%s\"", ip)
}
