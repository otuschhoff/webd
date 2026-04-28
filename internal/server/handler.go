package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"webd/internal/app"
)

const (
	defaultMaxIdleConns        = 256
	defaultMaxIdleConnsPerHost = 64
	defaultMaxConnsPerHost     = 256
	defaultIdleConnTimeout     = 90 * time.Second
)

func newRequestRouter(activeRoutes *atomic.Value, errLog *log.Logger, httpsAddr string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleIncomingRequest(w, r, activeRoutes, errLog, httpsAddr)
	})
}

func handleIncomingRequest(w http.ResponseWriter, r *http.Request, activeRoutes *atomic.Value, errLog *log.Logger, httpsAddr string) {
	if handleACMEChallengeRequest(w, r, errLog) {
		return
	}
	if handleHTTPToHTTPSRedirectRequest(w, r, httpsAddr) {
		return
	}

	routesNow := activeRoutes.Load().(routeSet)
	if handleRouteRequest(w, r, routesNow.matcher, errLog) {
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

func handleHTTPToHTTPSRedirectRequest(w http.ResponseWriter, r *http.Request, httpsAddr string) bool {
	if r.TLS != nil {
		return false
	}
	httpsURL := buildEquivalentHTTPSURL(r, httpsAddr)
	http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
	return true
}

func buildEquivalentHTTPSURL(r *http.Request, httpsAddr string) string {
	hostname, reqPort := splitRequestHostPort(r.Host)
	if hostname == "" {
		hostname = r.Host
	}
	if hostname == "" {
		hostname = "localhost"
	}

	httpsPort := parseListenPort(httpsAddr)
	if httpsPort == "" {
		httpsPort = reqPort
	}

	host := hostname
	if httpsPort != "" && httpsPort != "443" {
		host = net.JoinHostPort(hostname, httpsPort)
	}

	return (&url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}).String()
}

func splitRequestHostPort(host string) (string, string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", ""
	}

	parsedHost, parsedPort, err := net.SplitHostPort(host)
	if err == nil {
		return parsedHost, parsedPort
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return strings.Trim(host, "[]"), ""
	}

	return host, ""
}

func parseListenPort(addr string) string {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return ""
	}

	if strings.HasPrefix(trimmed, ":") {
		return strings.TrimPrefix(trimmed, ":")
	}

	if host, port, err := net.SplitHostPort(trimmed); err == nil {
		_ = host
		return port
	}

	return ""
}

func handleRouteRequest(w http.ResponseWriter, r *http.Request, matcher *routeTrieNode, errLog *log.Logger) bool {
	clientIP := handleRequestRemoteIP(r)
	route := matcher.match(r.URL.Path)
	if route == nil {
		return false
	}
	return handleMatchedRouteRequest(w, r, *route, clientIP, errLog)
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
	if route.websocketProxy != nil && isWebSocketUpgrade(r) {
		handleProxyRequest(w, r, route.websocketProxy)
		return true
	}
	handleProxyRequest(w, r, route.proxy)
	return true
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
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
	base.MaxIdleConns = defaultMaxIdleConns
	base.MaxIdleConnsPerHost = defaultMaxIdleConnsPerHost
	base.IdleConnTimeout = defaultIdleConnTimeout
	base.MaxConnsPerHost = defaultMaxConnsPerHost
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
		attempts := 0
		firstIP := ""
		var firstErr error
		for _, rawIP := range addresses {
			attempts++
			addr := net.JoinHostPort(rawIP, port)
			conn, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				return conn, nil
			}
			if firstErr == nil {
				firstErr = err
				firstIP = rawIP
			}
		}
		return nil, fmt.Errorf("dial handler %s:%s failed after %d attempts (first %s: %v)", handler.Hostname, port, attempts, firstIP, firstErr)
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
			if handler.TrustedCA.PinCert {
				pinnedCerts, err := loadPinnedCerts(handler.TrustedCA.File)
				if err != nil {
					return nil, fmt.Errorf("load pinned cert %q from %s: %w", handler.TrustedCA.Name, handler.TrustedCA.File, err)
				}
				base.TLSClientConfig.InsecureSkipVerify = true
				base.TLSClientConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return fmt.Errorf("no peer certificates presented")
					}

					leafCert, err := x509.ParseCertificate(rawCerts[0])
					if err != nil {
						return fmt.Errorf("parse peer leaf certificate: %w", err)
					}

					now := time.Now()
					if now.Before(leafCert.NotBefore) || now.After(leafCert.NotAfter) {
						return fmt.Errorf("peer certificate is not valid at current time")
					}

					if handler.Hostname != "" {
						if err := app.VerifyCertificateHostname(leafCert, handler.Hostname); err != nil {
							return fmt.Errorf("peer certificate hostname mismatch: %w", err)
						}
					}

					for _, pinned := range pinnedCerts {
						if bytes.Equal(pinned.Raw, leafCert.Raw) {
							return nil
						}
					}
					return fmt.Errorf("peer leaf certificate does not match pinned certificate")
				}
			} else {
				pool, err := loadTrustedCertPool(handler.TrustedCA.File)
				if err != nil {
					return nil, fmt.Errorf("load trusted_ca %q from %s: %w", handler.TrustedCA.Name, handler.TrustedCA.File, err)
				}
				base.TLSClientConfig.RootCAs = pool
			}
		}
	}
	return base, nil
}

func loadPinnedCerts(certPath string) ([]*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", certPath, err)
	}

	certs := make([]*x509.Certificate, 0, 1)
	rest := pemBytes
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse certificate from %s: %w", certPath, parseErr)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}

	return certs, nil
}

func handleProxyForwardedHeaders(req *http.Request, forwardedPrefix string) {
	clientAddr := handleRequestRemoteIP(req)
	proto := handleRequestScheme(req)
	port := handleRequestPort(req, proto)
	host := req.Host

	req.Header.Set("X-Real-IP", clientAddr)
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-Proto", proto)
	req.Header.Set("X-Forwarded-Port", port)
	if forwardedPrefix != "" {
		req.Header.Set("X-Forwarded-Prefix", forwardedPrefix)
	} else {
		req.Header.Del("X-Forwarded-Prefix")
	}

	existing := strings.TrimSpace(req.Header.Get("Forwarded"))
	var b strings.Builder
	b.Grow(len(existing) + len(clientAddr) + len(host) + len(proto) + 48)
	if existing != "" {
		b.WriteString(existing)
		b.WriteString(", ")
	}
	b.WriteString("for=")
	appendForwardedForValue(&b, clientAddr)
	b.WriteString(";host=")
	appendQuotedHeaderValue(&b, host)
	b.WriteString(";proto=")
	b.WriteString(proto)
	req.Header.Set("Forwarded", b.String())
}

func appendForwardedForValue(b *strings.Builder, ip string) {
	if strings.Contains(ip, ":") {
		b.WriteString("\"[")
		b.WriteString(ip)
		b.WriteString("]\"")
		return
	}
	b.WriteByte('"')
	b.WriteString(ip)
	b.WriteByte('"')
}

func appendQuotedHeaderValue(b *strings.Builder, value string) {
	b.WriteByte('"')
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\\', '"':
			b.WriteByte('\\')
		}
		b.WriteByte(value[i])
	}
	b.WriteByte('"')
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
		return "\"[" + ip + "]\""
	}
	return "\"" + ip + "\""
}
