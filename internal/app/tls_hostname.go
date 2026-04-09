package app

import (
	"crypto/x509"
	"net"
	"strings"
)

// VerifyCertificateHostname accepts normal SAN-based matches and falls back to
// legacy Common Name matching only when the certificate has no SANs at all.
func VerifyCertificateHostname(cert *x509.Certificate, hostname string) error {
	if err := cert.VerifyHostname(hostname); err == nil {
		return nil
	} else if certificateHasSANs(cert) {
		return err
	}

	commonName := strings.TrimSpace(cert.Subject.CommonName)
	if commonName == "" {
		return cert.VerifyHostname(hostname)
	}
	if !legacyCommonNameMatchesHost(commonName, hostname) {
		return cert.VerifyHostname(hostname)
	}
	return nil
}

func certificateHasSANs(cert *x509.Certificate) bool {
	return len(cert.DNSNames) > 0 || len(cert.EmailAddresses) > 0 || len(cert.IPAddresses) > 0 || len(cert.URIs) > 0
}

func legacyCommonNameMatchesHost(commonName, hostname string) bool {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	pattern := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(commonName)), ".")
	if host == "" || pattern == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	if pattern == host {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:]
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	leftmost := strings.TrimSuffix(host, suffix)
	if strings.Contains(leftmost, ".") {
		return false
	}
	return leftmost != ""
}