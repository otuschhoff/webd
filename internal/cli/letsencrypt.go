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
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"webd/internal/app"
	"webd/internal/syslogx"
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

	Reload Options
}

func defaultLetsEncryptOptions() LetsEncryptOptions {
	reload := DefaultOptions()
	return LetsEncryptOptions{
		Host:         "",
		Email:        "",
		DirectoryURL: acme.LetsEncryptURL,
		ChallengeDir: filepath.Join(DefaultRuntimeTLSDir, "acme-challenge"),
		CertPath:     DefaultTLSSourceCertPath,
		KeyPath:      DefaultTLSSourceKeyPath,
		Deploy:       true,
		Reload:       reload,
	}
}

// RunLetsEncrypt requests a Let's Encrypt certificate using HTTP-01 challenge,
// stores cert+chain and key on disk, and optionally deploys them to a running webd.
func RunLetsEncrypt(opts LetsEncryptOptions) error {
	logs, err := syslogx.NewForCommand("webctl", false)
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
		host, err = os.Hostname()
		if err != nil {
			return fmt.Errorf("resolve local hostname: %w", err)
		}
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("host must not be empty")
	}
	if strings.ContainsAny(host, " /\\") {
		return fmt.Errorf("host contains invalid characters: %q", host)
	}

	runUID, runGID, err := lookupRunUser(opts.Reload.RunUser)
	if err != nil {
		return err
	}
	if err := ensureChallengeDir(opts.ChallengeDir, runUID, runGID); err != nil {
		return err
	}

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
	if email := strings.TrimSpace(opts.Email); email != "" {
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
		if err := writeFileAtomic(tokenPath, []byte(keyAuth), 0o644); err != nil {
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

	if err := writeFileAtomic(opts.CertPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write cert chain to %s: %w", opts.CertPath, err)
	}
	if err := writeFileAtomic(opts.KeyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write private key to %s: %w", opts.KeyPath, err)
	}
	opsLog.Printf("saved letsencrypt certificate host=%q cert=%q key=%q", host, opts.CertPath, opts.KeyPath)

	if !opts.Deploy {
		return nil
	}

	reload := opts.Reload
	reload.TLSCertSource = opts.CertPath
	reload.TLSKeySource = opts.KeyPath
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
