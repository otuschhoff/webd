package server

import (
	"crypto/tls"
	"fmt"
	"sync/atomic"
)

type certReloader struct {
	certPath string
	keyPath  string
	cert     atomic.Pointer[tls.Certificate]
}

func newCertReloader(certPath, keyPath string) (*certReloader, error) {
	cr := &certReloader{certPath: certPath, keyPath: keyPath}
	if err := cr.Reload(); err != nil {
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
