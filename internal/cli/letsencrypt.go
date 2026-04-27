package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"webd/internal/app"
)

// LetsEncryptOptions controls ACME certificate issuance and deployment.
type LetsEncryptOptions struct {
	Host         string
	Email        string
	DirectoryURL string
	ChallengeDir string
	CertPath     string
	KeyPath      string
	Deploy       bool
	NoPostfixACL bool

	Reload Options
}

func defaultLetsEncryptOptions() LetsEncryptOptions {
	reload := DefaultOptions()
	return LetsEncryptOptions{
		Host:         "",
		Email:        "",
		DirectoryURL: acme.LetsEncryptURL,
		ChallengeDir: filepath.Join(DefaultRuntimeTLSDir, "acme-challenge"),
		CertPath:     "",
		KeyPath:      "",
		Deploy:       true,
		Reload:       reload,
	}
}

// RunLetsEncrypt requests a Let's Encrypt certificate using HTTP-01 challenge,
// stores cert+chain and key on disk, and optionally deploys them to a running webd.
func RunLetsEncrypt(opts LetsEncryptOptions) error {
	logs, err := app.NewForCommand("webctl", false)
	if err != nil {
		return fmt.Errorf("setup syslog loggers: %w", err)
	}
	defer func() {
		_ = logs.Close()
	}()
	opsLog := logs.Ops
	errLog := logs.Error

	if os.Geteuid() != 0 {
		return fmt.Errorf("letsencrypt requires root to write cert/key paths and challenge files")
	}

	host := strings.TrimSpace(opts.Host)
	if host == "" {
		host, err = localFQDN()
		if err != nil {
			return fmt.Errorf("resolve local fqdn: %w", err)
		}
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("host must not be empty")
	}
	if strings.ContainsAny(host, " /\\") {
		return fmt.Errorf("host contains invalid characters: %q", host)
	}

	now := time.Now().UTC()
	certPath, keyPath, useDefaultLayout, err := resolveLetsEncryptOutputPaths(host, opts.CertPath, opts.KeyPath, now)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return fmt.Errorf("create cert output dir for %s: %w", certPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return fmt.Errorf("create key output dir for %s: %w", keyPath, err)
	}

	runUID, runGID, err := lookupRunUser(opts.Reload.RunUser)
	if err != nil {
		return err
	}
	if err := ensureChallengeDir(opts.ChallengeDir, runUID, runGID); err != nil {
		return err
	}

	// Manage webd service lifecycle for ACME challenge serving
	webdWasRunning := isWebdServiceRunning()
	if !webdWasRunning {
		if err := startWebdService(opsLog); err != nil {
			return fmt.Errorf("auto-start webd for acme challenge: %w", err)
		}
	}
	// Ensure webd is stopped if we started it, even if there's an error
	defer func() {
		if !webdWasRunning && isWebdServiceRunning() {
			if stopErr := stopWebdService(opsLog); stopErr != nil {
				errLog.Printf("failed to stop webd service after letsencrypt: %v", stopErr)
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	acctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate acme account key: %w", err)
	}
	acmeClient := &acme.Client{
		Key:          acctKey,
		DirectoryURL: strings.TrimSpace(opts.DirectoryURL),
		UserAgent:    "webctl/" + app.VersionString(),
	}

	account := &acme.Account{}
	email := strings.TrimSpace(opts.Email)
	if email == "" {
		email = defaultACMEEmailForHost(host)
	}
	if email != "" {
		account.Contact = []string{"mailto:" + email}
	}
	if _, err := acmeClient.Register(ctx, account, acme.AcceptTOS); err != nil {
		return fmt.Errorf("register acme account: %w", err)
	}

	order, err := acmeClient.AuthorizeOrder(ctx, acme.DomainIDs(host))
	if err != nil {
		return fmt.Errorf("create acme order for %q: %w", host, err)
	}

	challengeFiles := make([]string, 0, len(order.AuthzURLs))
	defer func() {
		for _, p := range challengeFiles {
			_ = os.Remove(p)
		}
	}()

	for _, authzURL := range order.AuthzURLs {
		authz, err := acmeClient.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("get authorization %s: %w", authzURL, err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}

		var httpChallenge *acme.Challenge
		for _, c := range authz.Challenges {
			if c != nil && c.Type == "http-01" {
				httpChallenge = c
				break
			}
		}
		if httpChallenge == nil {
			return fmt.Errorf("authorization %s did not provide http-01 challenge", authzURL)
		}

		keyAuth, err := acmeClient.HTTP01ChallengeResponse(httpChallenge.Token)
		if err != nil {
			return fmt.Errorf("build challenge response for %s: %w", authzURL, err)
		}

		tokenPath := filepath.Join(opts.ChallengeDir, filepath.Base(httpChallenge.Token))
		if _, err := writeFileAtomic(tokenPath, []byte(keyAuth), 0o644); err != nil {
			return fmt.Errorf("write challenge token %s: %w", tokenPath, err)
		}
		if err := os.Chown(tokenPath, runUID, runGID); err != nil {
			return fmt.Errorf("chown challenge token %s: %w", tokenPath, err)
		}
		challengeFiles = append(challengeFiles, tokenPath)
		opsLog.Printf("staged acme challenge host=%q token_file=%q", host, tokenPath)

		if _, err := acmeClient.Accept(ctx, httpChallenge); err != nil {
			return fmt.Errorf("accept challenge for %s: %w", authzURL, err)
		}
		if _, err := acmeClient.WaitAuthorization(ctx, authz.URI); err != nil {
			return fmt.Errorf("wait authorization %s: %w", authzURL, err)
		}
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate certificate private key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: host},
		DNSNames: []string{host},
	}, certKey)
	if err != nil {
		return fmt.Errorf("create csr: %w", err)
	}

	order, err = acmeClient.WaitOrder(ctx, order.URI)
	if err != nil {
		return fmt.Errorf("wait order readiness: %w", err)
	}

	derCerts, _, err := acmeClient.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return fmt.Errorf("finalize order and fetch certificate: %w", err)
	}
	if len(derCerts) == 0 {
		return fmt.Errorf("acme returned empty certificate chain")
	}

	certPEM := make([]byte, 0, len(derCerts)*1200)
	for _, der := range derCerts {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if _, err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write cert chain to %s: %w", certPath, err)
	}
	if _, err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write private key to %s: %w", keyPath, err)
	}

	if useDefaultLayout {
		if err := ensureLetsEncryptDefaultSymlinks(host, now); err != nil {
			return err
		}
	}
	opsLog.Printf("saved letsencrypt certificate host=%q cert=%q key=%q", host, certPath, keyPath)

	// Set ACLs for postfix user if not disabled
	if !opts.NoPostfixACL {
		keyDir := filepath.Dir(keyPath)
		if err := setPostfixDirACL(keyDir); err != nil {
			// Log the error but don't fail the entire operation
			errLog.Printf("warning: failed to set postfix directory ACL on %s: %v", keyDir, err)
		} else {
			opsLog.Printf("set postfix execute ACL on directory=%q", keyDir)
		}

		if err := setPostfixKeyACL(keyPath); err != nil {
			// Log the error but don't fail the entire operation
			errLog.Printf("warning: failed to set postfix key ACL on %s: %v", keyPath, err)
		} else {
			opsLog.Printf("set postfix read ACL on key=%q", keyPath)
		}

		// If using default layout, also set ACL on /etc/pki/tls/private/self.key
		if useDefaultLayout {
			selfKeyPath := filepath.Join(filepath.Dir(keyPath), "..", "self.key")
			if err := setPostfixKeyACL(selfKeyPath); err != nil {
				// Log the error but don't fail the entire operation
				errLog.Printf("warning: failed to set postfix ACL on self.key: %v", err)
			} else {
				opsLog.Printf("set postfix read ACL on self.key=%q", selfKeyPath)
			}
		}
	}

	// Check if postfix config references the cert/key and reload if needed
	if err := checkAndReloadPostfix(opsLog, errLog, certPath, keyPath); err != nil {
		// This is already handled as a warning inside checkAndReloadPostfix, so just log
		errLog.Printf("postfix reload check error: %v", err)
	}

	if !opts.Deploy {
		return nil
	}

	reload := opts.Reload
	reload.TLSCertSource = certPath
	reload.TLSKeySource = keyPath
	if err := Run(reload); err != nil {
		errLog.Printf("letsencrypt deploy failed host=%q err=%v", host, err)
		return fmt.Errorf("deploy certificate to running webd: %w", err)
	}
	opsLog.Printf("deployed letsencrypt certificate host=%q", host)
	return nil
}

func ensureChallengeDir(path string, uid, gid int) error {
	clean := filepath.Clean(path)
	if !strings.HasPrefix(clean, "/run/") {
		return fmt.Errorf("acme challenge dir must be under /run: %s", clean)
	}
	if err := os.MkdirAll(clean, 0o755); err != nil {
		return fmt.Errorf("create acme challenge dir %s: %w", clean, err)
	}
	if err := os.Chown(clean, uid, gid); err != nil {
		return fmt.Errorf("chown acme challenge dir %s: %w", clean, err)
	}
	if err := os.Chmod(clean, 0o755); err != nil {
		return fmt.Errorf("chmod acme challenge dir %s: %w", clean, err)
	}
	return nil
}

func localFQDN() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return "", fmt.Errorf("local hostname is empty")
	}
	if strings.Contains(hostname, ".") {
		return hostname, nil
	}

	cname, err := net.LookupCNAME(hostname)
	if err == nil {
		fqdn := strings.TrimSuffix(strings.TrimSpace(cname), ".")
		if fqdn != "" {
			return fqdn, nil
		}
	}

	return hostname, nil
}

func defaultACMEEmailForHost(host string) string {
	h := strings.TrimSuffix(strings.TrimSpace(host), ".")
	i := strings.IndexByte(h, '.')
	if i < 0 || i+1 >= len(h) {
		return ""
	}
	domain := h[i+1:]
	if domain == "" {
		return ""
	}
	return "it@" + domain
}

func resolveLetsEncryptOutputPaths(host, certPath, keyPath string, now time.Time) (string, string, bool, error) {
	trimmedCert := strings.TrimSpace(certPath)
	trimmedKey := strings.TrimSpace(keyPath)

	if trimmedCert != "" && trimmedKey != "" {
		return trimmedCert, trimmedKey, false, nil
	}
	if trimmedCert == "" && trimmedKey == "" {
		fqdn := strings.TrimSuffix(strings.TrimSpace(host), ".")
		if fqdn == "" {
			return "", "", false, fmt.Errorf("resolve default cert/key paths: host is empty")
		}
		dateDir := now.Format("2006-01-02")
		cert := filepath.Join("/etc/pki/tls/certs", fqdn, dateDir, fqdn+".crt")
		key := filepath.Join("/etc/pki/tls/private", fqdn, dateDir, fqdn+".key")
		return cert, key, true, nil
	}

	if trimmedCert == "" {
		return "", "", false, fmt.Errorf("--cert-path must be provided when --key-path is set")
	}
	return "", "", false, fmt.Errorf("--key-path must be provided when --cert-path is set")
}

func ensureLetsEncryptDefaultSymlinks(host string, now time.Time) error {
	fqdn := strings.TrimSuffix(strings.TrimSpace(host), ".")
	if fqdn == "" {
		return fmt.Errorf("create default letsencrypt symlinks: host is empty")
	}
	short := fqdn
	if i := strings.IndexByte(fqdn, '.'); i > 0 {
		short = fqdn[:i]
	}
	dateDir := now.Format("2006-01-02")

	certsBase := "/etc/pki/tls/certs"
	keysBase := "/etc/pki/tls/private"

	if err := os.MkdirAll(filepath.Join(certsBase, fqdn, dateDir), 0o755); err != nil {
		return fmt.Errorf("create cert dated dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(keysBase, fqdn, dateDir), 0o700); err != nil {
		return fmt.Errorf("create key dated dir: %w", err)
	}

	if err := ensureSymlink(filepath.Join(certsBase, fqdn, "current"), dateDir); err != nil {
		return err
	}
	if err := ensureSymlink(filepath.Join(keysBase, fqdn, "current"), dateDir); err != nil {
		return err
	}

	if err := ensureSymlink(filepath.Join(certsBase, "self"), fqdn); err != nil {
		return err
	}
	if err := ensureSymlink(filepath.Join(keysBase, "self"), fqdn); err != nil {
		return err
	}

	if err := ensureSymlink(filepath.Join(certsBase, "self.crt"), filepath.Join("self", "current", fqdn+".crt")); err != nil {
		return err
	}
	if err := ensureSymlink(filepath.Join(keysBase, "self.key"), filepath.Join("self", "current", fqdn+".key")); err != nil {
		return err
	}

	if err := ensureSymlink(filepath.Join(certsBase, fqdn+".crt"), "self.crt"); err != nil {
		return err
	}
	if err := ensureSymlink(filepath.Join(keysBase, fqdn+".key"), "self.key"); err != nil {
		return err
	}

	if err := ensureSymlink(filepath.Join(certsBase, short+".crt"), "self.crt"); err != nil {
		return err
	}
	if err := ensureSymlink(filepath.Join(keysBase, short+".key"), "self.key"); err != nil {
		return err
	}

	return nil
}

func ensureSymlink(path, target string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create symlink directory for %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("cannot replace non-symlink path %s", path)
		}
		existingTarget, readErr := os.Readlink(path)
		if readErr == nil && existingTarget == target {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("lstat %s: %w", path, err)
	}

	// Create a temporary symlink then atomically rename it over the destination.
	// This avoids the TOCTOU window between removing the old symlink and creating
	// the new one: os.Rename is atomic on Linux and macOS (same filesystem).
	tmpPath := fmt.Sprintf("%s.symtmp%d", path, os.Getpid())
	if err := os.Symlink(target, tmpPath); err != nil {
		return fmt.Errorf("create temp symlink for %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic replace symlink %s -> %s: %w", path, target, err)
	}
	return nil
}

// isWebdServiceRunning checks if the webd systemd service is currently active.
func isWebdServiceRunning() bool {
	cmd := exec.Command("systemctl", "is-active", "webd")
	err := cmd.Run()
	// is-active returns exit 0 if the service is active
	return err == nil
}

// startWebdService starts the webd systemd service and waits for it to be ready.
func startWebdService(opsLog *log.Logger) error {
	if isWebdServiceRunning() {
		opsLog.Printf("webd service already running")
		return nil
	}

	opsLog.Printf("starting webd service via systemctl")
	cmd := exec.Command("systemctl", "start", "webd")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl start webd failed: %w\noutput: %s", err, string(output))
	}

	// Wait for webd to be ready (listening on HTTP port 80)
	// Try for up to 10 seconds
	startTime := time.Now()
	timeout := 10 * time.Second
	for time.Since(startTime) < timeout {
		conn, err := net.Dial("tcp", ":80")
		if err == nil {
			_ = conn.Close()
			opsLog.Printf("webd service ready after %.1f seconds", time.Since(startTime).Seconds())
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("webd service did not start listening on HTTP port 80 within %v", timeout)
}

// stopWebdService stops the webd systemd service if it's running.
func stopWebdService(opsLog *log.Logger) error {
	if !isWebdServiceRunning() {
		return nil
	}

	opsLog.Printf("stopping webd service via systemctl")
	cmd := exec.Command("systemctl", "stop", "webd")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl stop webd failed: %w\noutput: %s", err, string(output))
	}

	opsLog.Printf("webd service stopped")
	return nil
}

// checkAndReloadPostfix checks if postfix configuration references the given
// certificate or key paths. If so, reloads the postfix service.
func checkAndReloadPostfix(opsLog, errLog *log.Logger, certPath, keyPath string) error {
	const postfixConfigPath = "/etc/postfix/main.cf"

	// Check if postfix config file exists
	postfixConfig, err := os.ReadFile(postfixConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Postfix not configured, nothing to do
			return nil
		}
		// If there's a read error, log a warning but don't fail
		errLog.Printf("warning: could not read postfix config %s: %v", postfixConfigPath, err)
		return nil
	}

	configStr := string(postfixConfig)
	certReferenced := strings.Contains(configStr, certPath)
	keyReferenced := strings.Contains(configStr, keyPath)

	if !certReferenced && !keyReferenced {
		// Postfix config doesn't reference these cert/key paths
		return nil
	}

	opsLog.Printf("postfix config references new cert/key cert=%v key=%v", certReferenced, keyReferenced)

	// Reload postfix service
	cmd := exec.Command("systemctl", "reload", "postfix")
	if output, err := cmd.CombinedOutput(); err != nil {
		// Log as warning but don't fail the letsencrypt operation
		errLog.Printf("warning: postfix reload failed: %v\noutput: %s", err, string(output))
		return nil
	}

	opsLog.Printf("postfix service reloaded")
	return nil
}
