package app

// DefaultConfigPath is the default YAML configuration file location.
// DefaultTLSSourceCertPath is the default source TLS certificate bundle path.
// DefaultTLSSourceKeyPath is the default source TLS private key path.
// DefaultRuntimeTLSDir is the runtime directory used for staged TLS artifacts.
// DefaultRuntimeTLSCertPath is the staged runtime TLS certificate path.
// DefaultRuntimeTLSKeyPath is the staged runtime TLS private key path.
// DefaultTLSCertPath is the default TLS certificate path used by the running server.
// DefaultTLSKeyPath is the default TLS private key path used by the running server.
// DefaultAccessLog is the default access log file path.
// DefaultRunUser is the default non-root runtime account for the daemon.
// DefaultHTTPAddr is the default HTTP listen address.
// DefaultHTTPSAddr is the default HTTPS listen address.
// DefaultBinaryPath is the default installed binary path used by setup and systemd.
// DefaultServicePath is the default systemd unit file path.
// AccessLogRotateSize is the log size threshold that triggers access log rotation.
const (
	DefaultConfigPath         = "/etc/httpsd/config.yaml"
	DefaultTLSSourceCertPath  = "/etc/pki/tls/certs/self.crt"
	DefaultTLSSourceKeyPath   = "/etc/pki/tls/private/self.key"
	DefaultRuntimeTLSDir      = "/run/httpsd"
	DefaultRuntimeTLSCertPath = "/run/httpsd/tls.crt"
	DefaultRuntimeTLSKeyPath  = "/run/httpsd/tls.key"
	DefaultTLSCertPath        = DefaultRuntimeTLSCertPath
	DefaultTLSKeyPath         = DefaultRuntimeTLSKeyPath
	DefaultAccessLog          = "/var/log/httpsd/access.log"
	DefaultRunUser            = "httpsd"
	DefaultHTTPAddr           = ":80"
	DefaultHTTPSAddr          = ":443"
	DefaultBinaryPath         = "/opt/httpsd/current/sbin/httpsd"
	DefaultServicePath        = "/etc/systemd/system/httpsd.service"
	AccessLogRotateSize       = int64(1 * 1024 * 1024)
)

// ServiceUnitContent is the desired systemd unit file content written by setup.
const ServiceUnitContent = `[Unit]
Description=HTTPS Proxy
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=simple
User=httpsd
Group=httpsd
PermissionsStartOnly=true
SyslogIdentifier=httpsd
StandardOutput=journal
StandardError=journal
RuntimeDirectory=httpsd
RuntimeDirectoryMode=0750
ExecStartPre=/opt/httpsd/current/sbin/httpsdctl reload --prepare-only
ExecStart=/opt/httpsd/current/sbin/httpsd
ExecReload=/opt/httpsd/current/sbin/httpsdctl reload
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
	// TLSCertPath points to the source certificate file validated by setup.
	TLSCertPath string
	// TLSKeyPath points to the source private key file validated by setup.
	TLSKeyPath string
	// ServicePath is the systemd unit file path managed by setup.
	ServicePath string
	// BinaryPath is the installed httpsd binary path used for capability setup.
	BinaryPath string
	// Force allows setup to overwrite an existing, non-matching systemd unit file.
	Force bool
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
		TLSCertPath: DefaultTLSSourceCertPath,
		TLSKeyPath:  DefaultTLSSourceKeyPath,
		ServicePath: DefaultServicePath,
		BinaryPath:  DefaultBinaryPath,
		Force:       false,
	}
}
