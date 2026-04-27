package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync/atomic"
	"time"
)

type certReloader struct {
	certPath string
	keyPath  string
	cert     atomic.Pointer[tls.Certificate]
}

func newCertReloader(certPath, keyPath string) (*certReloader, error) {
	cr := &certReloader{certPath: certPath, keyPath: keyPath}
	if err := cr.Reload(); err != nil {
		// If cert files don't exist, create a temporary self-signed certificate
		// This allows ACME-only mode (serving challenges via HTTP on port 80)
		if os.IsNotExist(err) {
			if err := createTemporarySelfSignedCert(cr); err != nil {
				return nil, fmt.Errorf("create temporary self-signed cert: %w", err)
			}
			return cr, nil
		}
		return nil, err
	}
	return cr, nil
}

func (c *certReloader) Reload() error {
	loaded, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
	if err != nil {
		return fmt.Errorf("load tls cert/key: %w (cert=%s key=%s; ensure cert PEM starts with the leaf certificate, followed by intermediates, and that the private key matches the leaf cert)", err, c.certPath, c.keyPath)
	}
	c.cert.Store(&loaded)
	return nil
}

func (c *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	loaded := c.cert.Load()
	if loaded == nil {
		return nil, fmt.Errorf("tls certificate is not loaded")
	}
	return loaded, nil
}

// createTemporarySelfSignedCert generates a temporary self-signed certificate
// for ACME-only mode when cert files don't exist yet.
func createTemporarySelfSignedCert(cr *certReloader) error {
	// Generate a new ECDSA key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}

	// Create a self-signed certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "127.0.0.1"},
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	// Encode to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Load the certificate into the reloader
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("load temporary cert/key pair: %w", err)
	}

	cr.cert.Store(&tlsCert)
	return nil
}
