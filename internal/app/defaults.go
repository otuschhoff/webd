package app

// DefaultConfigPath is the default YAML configuration file location.
// DefaultTLSCertPath is the default TLS certificate bundle path.
// DefaultTLSKeyPath is the default TLS private key path.
// DefaultAccessLog is the default access log file path.
// DefaultRunUser is the default non-root runtime account for the daemon.
// DefaultHTTPAddr is the default HTTP listen address.
// DefaultHTTPSAddr is the default HTTPS listen address.
// DefaultBinaryPath is the default installed binary path used by setup and systemd.
// DefaultServicePath is the default systemd unit file path.
// AccessLogRotateSize is the log size threshold that triggers access log rotation.
const (
	DefaultConfigPath   = "/etc/httpsd/config.yaml"
	DefaultTLSCertPath  = "/etc/pki/tls/certs/self.crt"
	DefaultTLSKeyPath   = "/etc/pki/tls/private/self.key"
	DefaultAccessLog    = "/var/log/httpsd/access.log"
	DefaultRunUser      = "httpsd"
	DefaultHTTPAddr     = ":80"
	DefaultHTTPSAddr    = ":443"
	DefaultBinaryPath   = "/opt/httpsd/current/sbin/httpsd"
	DefaultServicePath  = "/etc/systemd/system/httpsd.service"
	AccessLogRotateSize = int64(1 * 1024 * 1024)
)

// ServiceUnitContent is the desired systemd unit file content written by setup.
const ServiceUnitContent = `[Unit]
Description=HTTPS Proxy
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=exec
User=httpsd
Group=httpsd
ExecStart=/opt/httpsd/current/sbin/httpsd
Restart=on-failure

# Security: Give the binary permission to bind to ports 80/443
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Hardening: Prevent the app from gaining more privileges
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
`

// RunOptions contains runtime configuration for the proxy process.
type RunOptions struct {
	// ConfigPath points to the YAML route configuration file.
	ConfigPath string
	// HTTPAddr is the plain HTTP listen address.
	HTTPAddr string
	// HTTPSAddr is the TLS-enabled HTTPS listen address.
	HTTPSAddr string
	// TLSCertPath points to the certificate chain PEM file.
	TLSCertPath string
	// TLSKeyPath points to the private key PEM file.
	TLSKeyPath string
	// AccessLogPath points to the access log written by the daemon.
	AccessLogPath string
	// RunUser is the expected account name for the running server process.
	RunUser string
	// Force disables the runtime user enforcement check.
	Force bool
}

// SetupOptions contains host-level paths used by the setup subcommand.
type SetupOptions struct {
	// TLSCertPath points to the certificate file whose ownership and mode are enforced.
	TLSCertPath string
	// TLSKeyPath points to the private key file whose ownership and mode are enforced.
	TLSKeyPath string
	// ServicePath is the systemd unit file path managed by setup.
	ServicePath string
	// BinaryPath is the installed httpsd binary path used for capability setup.
	BinaryPath string
}

// DefaultRunOptions returns the runtime defaults used by the root and run commands.
func DefaultRunOptions() RunOptions {
	return RunOptions{
		ConfigPath:    DefaultConfigPath,
		HTTPAddr:      DefaultHTTPAddr,
		HTTPSAddr:     DefaultHTTPSAddr,
		TLSCertPath:   DefaultTLSCertPath,
		TLSKeyPath:    DefaultTLSKeyPath,
		AccessLogPath: DefaultAccessLog,
		RunUser:       DefaultRunUser,
		Force:         false,
	}
}

// DefaultSetupOptions returns the default file paths used by the setup command.
func DefaultSetupOptions() SetupOptions {
	return SetupOptions{
		TLSCertPath: DefaultTLSCertPath,
		TLSKeyPath:  DefaultTLSKeyPath,
		ServicePath: DefaultServicePath,
		BinaryPath:  DefaultBinaryPath,
	}
}
