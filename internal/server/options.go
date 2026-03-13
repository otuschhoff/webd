package server

// RunOptions contains runtime configuration for the proxy process.
type RunOptions struct {
	// ConfigPath points to the runtime route configuration file.
	ConfigPath string
	// HTTPAddr is the plain HTTP listen address.
	HTTPAddr string
	// HTTPSAddr is the TLS-enabled HTTPS listen address.
	HTTPSAddr string
	// TLSCertPath points to the certificate chain PEM file.
	TLSCertPath string
	// TLSKeyPath points to the private key PEM file.
	TLSKeyPath string
}
