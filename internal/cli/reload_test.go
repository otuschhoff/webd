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

// TestBuildRuntimeHandlerForURL_InsecureHardFails mirrors the above for the
// insecure (cert-pin) mode: stageInsecureTrustedCert must always hard-fail
// rather than falling back to system trust.
//
// With port 1 the connection is refused before any system-dir operations, so
// we do get a genuine isTLSBackendCertFetchError.  Under the old code this
// would have been swallowed; under the fixed code it must propagate.
func TestBuildRuntimeHandlerForURL_InsecureHardFails(t *testing.T) {
	stagedCAs := make(map[string]*stagedTrustedCA)

	_, err := buildRuntimeHandlerForURL(
		"https://127.0.0.1:1/",
		true, // insecure / cert-pin
		nil,
		0, 0,
		stagedCAs,
	)
	if err == nil {
		t.Fatal("expected error for insecure mode with unreachable backend, got nil")
	}
	// The error must be the real fetch failure, not a nil TrustedCA result.
	if !isTLSBackendCertFetchError(err) {
		// It might be an ensureRuntimeTrustedCADir failure (non-root); that is
		// also an error propagation, which is correct.
		t.Logf("got non-fetch error (likely permission): %v", err)
	}
}
