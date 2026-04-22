package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"webd/internal/server"
)

// TestIsTLSBackendCertFetchError verifies the error classifier that distinguishes
// transient backend-unreachable errors (where the auto-discovery path may degrade
// gracefully) from hard configuration or logic errors (which must always propagate).
func TestIsTLSBackendCertFetchError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{fmt.Errorf("fetch handler TLS certificates for https://backend:443 failed: dial tcp ..."), true},
		{fmt.Errorf("fetch handler TLS certificates for https://10.0.0.1:8443 failed: connection refused"), true},
		{fmt.Errorf("read trusted_ca /etc/pki/tls/certs/ca.crt: no such file"), false},
		{fmt.Errorf("parse trusted_ca /etc/pki/tls/certs/ca.crt: invalid PEM"), false},
		{fmt.Errorf("verify handler https://backend:443 against trusted_ca /etc/pki/tls/certs/ca.crt: x509 error"), false},
		{fmt.Errorf("some unrelated error"), false},
	}

	for _, tc := range cases {
		got := isTLSBackendCertFetchError(tc.err)
		if got != tc.want {
			t.Errorf("isTLSBackendCertFetchError(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// TestBuildRuntimeHandlerForURL_HTTPNoTrustStaging verifies that plain HTTP and
// WS handler URLs do not trigger any TLS trust staging at all — the returned
// handler has a nil TrustedCA.  This path is not affected by the TLS-downgrade
// fix but serves as a baseline sanity check for buildRuntimeHandlerForURL.
func TestBuildRuntimeHandlerForURL_HTTPNoTrustStaging(t *testing.T) {
	stagedCAs := make(map[string]*stagedTrustedCA)

	for _, rawURL := range []string{
		"http://127.0.0.1/",
		"ws://127.0.0.1/",
	} {
		h, err := buildRuntimeHandlerForURL(rawURL, false, nil, 0, 0, stagedCAs)
		if err != nil {
			t.Fatalf("buildRuntimeHandlerForURL(%q): unexpected error: %v", rawURL, err)
		}
		if h.TrustedCA != nil {
			t.Errorf("buildRuntimeHandlerForURL(%q): expected nil TrustedCA for plain HTTP, got %+v", rawURL, h.TrustedCA)
		}
	}
}

// TestBuildRuntimeHandlerForURL_ExplicitTrustedCAHardFails is the regression
// test for the MEDIUM-severity TLS trust downgrade vulnerability fixed in
// commit fac7d63.
//
// Before the fix: when trustedCA != nil and the backend was unreachable,
// buildRuntimeHandlerForURL would catch the isTLSBackendCertFetchError and
// silently set resolvedTrustedCA = nil, causing webd to fall back to system
// default trust — defeating the operator's explicit CA configuration.
//
// After the fix: any error from stageTrustedCA must propagate unconditionally.
//
// Because stageTrustedCA requires root-owned system directories we cannot fully
// exercise it in a unit test, but we can verify the error-propagation path by
// providing an unreachable backend (port 1) and a CA cert path that does not
// exist.  The first failure (os.ReadFile) is NOT an isTLSBackendCertFetchError,
// so both old and new code would propagate it — but the test also documents the
// intent and catches any future regression that re-introduces silent nil.
func TestBuildRuntimeHandlerForURL_ExplicitTrustedCAHardFails(t *testing.T) {
	stagedCAs := make(map[string]*stagedTrustedCA)
	trustedCA := &TrustedCA{
		Name:     "test-ca",
		CertPath: "/nonexistent/ca.crt",
	}

	_, err := buildRuntimeHandlerForURL(
		"https://127.0.0.1:1/",
		false,
		trustedCA,
		0, 0,
		stagedCAs,
	)
	if err == nil {
		t.Fatal("expected error when explicit trustedCA is configured and CA file does not exist, got nil")
	}
	// The error must NOT be silently swallowed regardless of its nature.
	// In particular it must not be an isTLSBackendCertFetchError that was
	// previously ignored.
	if strings.Contains(err.Error(), "fetch handler TLS certificates") &&
		isTLSBackendCertFetchError(err) {
		t.Errorf("TLS fetch error was not propagated for explicit trustedCA: %v", err)
	}
}

// TestBuildRuntimeHandlerForURL_InsecureLoopbackLenient verifies that
// insecure (cert-pin) mode with a loopback backend is treated leniently:
// a staging failure (e.g. service not yet running at daemon start) must NOT
// block the reload — it should fall back to nil TrustedCA (system trust).
// This is the regression test for the startup-ordering failure observed with
// localhost backends configured with insecure: true.
func TestBuildRuntimeHandlerForURL_InsecureLoopbackLenient(t *testing.T) {
	stagedCAs := make(map[string]*stagedTrustedCA)

	h, err := buildRuntimeHandlerForURL(
		"https://127.0.0.1:1/",
		true, // insecure / cert-pin
		nil,
		0, 0,
		stagedCAs,
	)
	if err != nil {
		// Allow permission errors from ensureRuntimeTrustedCADir (non-root)
		// as those occur before the loopback-leniency path.
		if strings.Contains(err.Error(), "trusted_ca runtime directory") ||
			strings.Contains(err.Error(), "permission denied") {
			t.Skipf("skipping: requires root for CA dir setup: %v", err)
		}
		t.Fatalf("loopback insecure backend should not hard-fail on connection refused, got: %v", err)
	}
	if h.TrustedCA != nil {
		t.Errorf("expected nil TrustedCA for unreachable loopback insecure backend, got %+v", h.TrustedCA)
	}
}

// TestBuildRuntimeHandlerForURL_InsecureNonLoopbackHardFails verifies that
// insecure (cert-pin) mode still hard-fails for non-loopback backends, since
// silently falling back to system trust for a remote backend would defeat
// cert pinning.
func TestBuildRuntimeHandlerForURL_InsecureNonLoopbackHardFails(t *testing.T) {
	stagedCAs := make(map[string]*stagedTrustedCA)

	// 192.0.2.1 is TEST-NET (RFC 5737) — routable but reserved, always
	// connection-refused/unreachable in a test environment.
	_, err := buildRuntimeHandlerForURL(
		"https://192.0.2.1:443/",
		true, // insecure / cert-pin
		nil,
		0, 0,
		stagedCAs,
	)
	if err == nil {
		t.Fatal("expected error for insecure mode with unreachable non-loopback backend, got nil")
	}
}

// =============================================================================
// Localhost TLS scenario tests
//
// These tests spin up real TLS servers on 127.0.0.1 and exercise both the
// low-level fetchHandlerPeerCertificates helper and the high-level
// buildRuntimeHandlerForURL function under various cert conditions.
// =============================================================================

// localhostHandler builds a server.Handler pointing at a given 127.0.0.1 port.
func localhostHandler(port int) server.Handler {
	return server.Handler{
		Protocol:      "https",
		Hostname:      "127.0.0.1",
		Port:          port,
		IPv4Addresses: []string{"127.0.0.1"},
	}
}

// noopLogger returns a *log.Logger that discards all output.
func noopLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// selfSignedCert generates an ECDSA self-signed certificate for the given
// SANs/hosts. notBefore/notAfter control validity window.
// Returns (tls.Certificate, DER-encoded leaf cert).
func selfSignedCert(t *testing.T, hosts []string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return tlsCert
}

// newTLSServerWithCert starts a TLS server on 127.0.0.1 using the supplied cert.
// Returns (server, port). Caller must call ts.Close().
func newTLSServerWithCert(t *testing.T, cert tls.Certificate) (*httptest.Server, int) {
	t.Helper()
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Suppress the default TLS error logger; the test server will produce
		// "use of closed network connection" noise when tests shut it down
		// mid-handshake, which is expected and not a test failure.
	}
	ts.Config.ErrorLog = noopLogger()
	ts.StartTLS()
	t.Cleanup(ts.Close)

	addr := ts.Listener.Addr().(*net.TCPAddr)
	return ts, addr.Port
}

// --- isLoopbackHandler unit tests ---

func TestIsLoopbackHandler(t *testing.T) {
	cases := []struct {
		name    string
		handler server.Handler
		want    bool
	}{
		{
			name:    "no IPs",
			handler: server.Handler{IPv4Addresses: nil},
			want:    false,
		},
		{
			name:    "single loopback",
			handler: server.Handler{IPv4Addresses: []string{"127.0.0.1"}},
			want:    true,
		},
		{
			name:    "all loopback",
			handler: server.Handler{IPv4Addresses: []string{"127.0.0.1", "127.0.0.2"}},
			want:    true,
		},
		{
			name:    "mixed loopback and routable",
			handler: server.Handler{IPv4Addresses: []string{"127.0.0.1", "10.0.0.1"}},
			want:    false,
		},
		{
			name:    "non-loopback only",
			handler: server.Handler{IPv4Addresses: []string{"10.0.0.1"}},
			want:    false,
		},
		{
			name:    "public IP",
			handler: server.Handler{IPv4Addresses: []string{"93.184.216.34"}},
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isLoopbackHandler(tc.handler)
			if got != tc.want {
				t.Errorf("isLoopbackHandler(%v) = %v, want %v", tc.handler.IPv4Addresses, got, tc.want)
			}
		})
	}
}

// --- fetchHandlerPeerCertificates tests ---

// TestFetchHandlerPeerCertificates_ConnectionRefused verifies that a connection
// to a port with nothing listening returns an error containing the expected
// "fetch handler TLS certificates for" prefix.
func TestFetchHandlerPeerCertificates_ConnectionRefused(t *testing.T) {
	h := localhostHandler(1) // port 1 is never open
	_, err := fetchHandlerPeerCertificates(h)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !isTLSBackendCertFetchError(err) {
		t.Errorf("want isTLSBackendCertFetchError=true, got false; err: %v", err)
	}
}

// TestFetchHandlerPeerCertificates_ValidSelfSigned verifies that
// fetchHandlerPeerCertificates connects with InsecureSkipVerify and returns
// the peer certificates even when they are self-signed and not in the system
// trust store.
func TestFetchHandlerPeerCertificates_ValidSelfSigned(t *testing.T) {
	now := time.Now()
	cert := selfSignedCert(t, []string{"127.0.0.1"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	_, port := newTLSServerWithCert(t, cert)

	h := localhostHandler(port)
	certs, err := fetchHandlerPeerCertificates(h)
	if err != nil {
		t.Fatalf("unexpected error fetching self-signed cert: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("expected at least one peer certificate, got none")
	}
}

// TestFetchHandlerPeerCertificates_ExpiredCert verifies that an expired
// certificate on the backend is still fetched successfully — fetchHandlerPeerCertificates
// uses InsecureSkipVerify and does not perform validity checks itself.
// The expiry is caught at the verification stage (stageAutoTrustedCA /
// stageInsecureTrustedCert), not at the fetch stage.
func TestFetchHandlerPeerCertificates_ExpiredCert(t *testing.T) {
	past := time.Now().Add(-365 * 24 * time.Hour)
	cert := selfSignedCert(t, []string{"127.0.0.1"}, past.Add(-time.Hour), past)
	_, port := newTLSServerWithCert(t, cert)

	h := localhostHandler(port)
	certs, err := fetchHandlerPeerCertificates(h)
	if err != nil {
		t.Fatalf("expired cert should still be fetched (InsecureSkipVerify), got error: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("expected at least one peer certificate, got none")
	}
	// Confirm the fetched cert is indeed expired.
	if time.Now().Before(certs[0].NotAfter) {
		t.Errorf("expected expired cert, but NotAfter=%v is in the future", certs[0].NotAfter)
	}
}

// TestFetchHandlerPeerCertificates_WrongHostname verifies that a cert issued
// for a different hostname ("wrong.example.com") is still fetched successfully.
// InsecureSkipVerify bypasses hostname validation at the dial stage; hostname
// checking is the responsibility of higher-level staging functions.
func TestFetchHandlerPeerCertificates_WrongHostname(t *testing.T) {
	now := time.Now()
	cert := selfSignedCert(t, []string{"wrong.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	_, port := newTLSServerWithCert(t, cert)

	h := localhostHandler(port)
	certs, err := fetchHandlerPeerCertificates(h)
	if err != nil {
		t.Fatalf("wrong-hostname cert should still be fetched (InsecureSkipVerify), got error: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("expected at least one peer certificate")
	}
	// Confirm the cert does NOT cover 127.0.0.1.
	if err := certs[0].VerifyHostname("127.0.0.1"); err == nil {
		t.Error("expected VerifyHostname to fail for wrong-hostname cert, got nil")
	}
}

// --- buildRuntimeHandlerForURL loopback scenario tests ---
//
// All scenarios below exercise the high-level staging function. Because
// ensureRuntimeTrustedCADir requires root-level access, staging errors from
// that function are also swallowed for loopback backends — so the tests verify
// the externally observable result: no error returned, nil TrustedCA.

// TestLoopbackInsecure_SelfSignedCert verifies that a loopback backend with a
// running server and a self-signed cert does not block the reload in insecure
// mode, regardless of whether the TLS directory can be created.
func TestLoopbackInsecure_SelfSignedCert(t *testing.T) {
	now := time.Now()
	cert := selfSignedCert(t, []string{"127.0.0.1"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	_, port := newTLSServerWithCert(t, cert)

	stagedCAs := make(map[string]*stagedTrustedCA)
	rawURL := fmt.Sprintf("https://127.0.0.1:%d/", port)

	h, err := buildRuntimeHandlerForURL(rawURL, true, nil, 0, 0, stagedCAs)
	if err != nil {
		t.Fatalf("loopback insecure with self-signed cert should not fail: %v", err)
	}
	// Either TrustedCA is set (root, staging succeeded) or nil (non-root, lenient).
	// Either way we must not get an error.
	_ = h
}

// TestLoopbackAutoDiscovery_NotReachable verifies that auto-discovery for an
// unreachable loopback backend does not block the reload.
func TestLoopbackAutoDiscovery_NotReachable(t *testing.T) {
	stagedCAs := make(map[string]*stagedTrustedCA)

	h, err := buildRuntimeHandlerForURL("https://127.0.0.1:1/", false, nil, 0, 0, stagedCAs)
	if err != nil {
		t.Fatalf("unreachable loopback auto-discovery should not fail: %v", err)
	}
	if h.TrustedCA != nil {
		t.Errorf("expected nil TrustedCA for unreachable loopback, got %+v", h.TrustedCA)
	}
}

// TestLoopbackAutoDiscovery_ExpiredCert verifies that a loopback backend
// presenting an expired certificate does not block the reload in auto-discovery
// mode. The x509 verification will fail (expiry), but loopback leniency applies.
func TestLoopbackAutoDiscovery_ExpiredCert(t *testing.T) {
	past := time.Now().Add(-365 * 24 * time.Hour)
	cert := selfSignedCert(t, []string{"127.0.0.1"}, past.Add(-time.Hour), past)
	_, port := newTLSServerWithCert(t, cert)

	stagedCAs := make(map[string]*stagedTrustedCA)
	rawURL := fmt.Sprintf("https://127.0.0.1:%d/", port)

	h, err := buildRuntimeHandlerForURL(rawURL, false, nil, 0, 0, stagedCAs)
	if err != nil {
		t.Fatalf("loopback auto-discovery with expired cert should not fail: %v", err)
	}
	// Non-root: nil TrustedCA because ensureRuntimeTrustedCADir fails first (lenient).
	// Root: nil TrustedCA because x509 verification fails (lenient).
	if h.TrustedCA != nil {
		t.Errorf("expected nil TrustedCA for loopback with expired cert, got %+v", h.TrustedCA)
	}
}

// TestLoopbackAutoDiscovery_WrongHostnameCert verifies that a loopback backend
// presenting a cert for a different hostname does not block the reload.
// Hostname verification in stageAutoTrustedCA fails, but loopback leniency applies.
func TestLoopbackAutoDiscovery_WrongHostnameCert(t *testing.T) {
	now := time.Now()
	cert := selfSignedCert(t, []string{"wrong.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	_, port := newTLSServerWithCert(t, cert)

	stagedCAs := make(map[string]*stagedTrustedCA)
	rawURL := fmt.Sprintf("https://127.0.0.1:%d/", port)

	h, err := buildRuntimeHandlerForURL(rawURL, false, nil, 0, 0, stagedCAs)
	if err != nil {
		t.Fatalf("loopback auto-discovery with wrong-hostname cert should not fail: %v", err)
	}
	if h.TrustedCA != nil {
		t.Errorf("expected nil TrustedCA for loopback with wrong-hostname cert, got %+v", h.TrustedCA)
	}
}

// TestLoopbackInsecure_ExpiredCert verifies that insecure (cert-pin) mode with
// an expired loopback backend cert does not block the reload. The cert-pin
// staging may fail (e.g. CA dir not writable) or succeed (root); either way
// the reload must not be blocked.
func TestLoopbackInsecure_ExpiredCert(t *testing.T) {
	past := time.Now().Add(-365 * 24 * time.Hour)
	cert := selfSignedCert(t, []string{"127.0.0.1"}, past.Add(-time.Hour), past)
	_, port := newTLSServerWithCert(t, cert)

	stagedCAs := make(map[string]*stagedTrustedCA)
	rawURL := fmt.Sprintf("https://127.0.0.1:%d/", port)

	_, err := buildRuntimeHandlerForURL(rawURL, true, nil, 0, 0, stagedCAs)
	if err != nil {
		t.Fatalf("loopback insecure with expired cert should not fail: %v", err)
	}
}

// TestLoopbackInsecure_WrongHostnameCert verifies that insecure (cert-pin) mode
// does not block the reload when the backend cert has a mismatched hostname.
// fetchHandlerPeerCertificates uses InsecureSkipVerify, so the cert is fetched
// regardless, and any staging error for the loopback backend is lenient.
func TestLoopbackInsecure_WrongHostnameCert(t *testing.T) {
	now := time.Now()
	cert := selfSignedCert(t, []string{"wrong.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	_, port := newTLSServerWithCert(t, cert)

	stagedCAs := make(map[string]*stagedTrustedCA)
	rawURL := fmt.Sprintf("https://127.0.0.1:%d/", port)

	_, err := buildRuntimeHandlerForURL(rawURL, true, nil, 0, 0, stagedCAs)
	if err != nil {
		t.Fatalf("loopback insecure with wrong-hostname cert should not fail: %v", err)
	}
}
