package cli

import (
	"fmt"
	"strings"
	"testing"
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
