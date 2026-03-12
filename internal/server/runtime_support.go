package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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
		return nil, err
	}
	return cr, nil
}

func (c *certReloader) Reload() error {
	loaded, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
	if err != nil {
		return fmt.Errorf("load tls cert/key: %w", err)
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

type rotatingWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	size     int64
}

func newRotatingWriter(path string, maxBytes int64) (*rotatingWriter, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("invalid maxBytes %d", maxBytes)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat log file: %w", err)
	}

	return &rotatingWriter{path: path, maxBytes: maxBytes, file: f, size: st.Size()}, nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rotatingWriter) rotate() error {
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("close log file: %w", err)
	}

	archive := fmt.Sprintf("%s.%s", w.path, time.Now().UTC().Format("20060102T150405"))
	if err := os.Rename(w.path, archive); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("rotate log file: %w", err)
	}

	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("reopen log file: %w", err)
	}

	w.file = f
	w.size = 0
	return nil
}

func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	return w.file.Close()
}
