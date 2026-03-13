package app

// Base paths used to derive default filesystem locations.
const (
	defaultEtcDir            = "/etc/web"
	defaultRuntimeDir        = "/run/webd"
	defaultInstallCurrentDir = "/opt/web/current"
	defaultLibexecDir        = defaultInstallCurrentDir + "/libexec"
)

// Public defaults shared by daemon and control-plane commands.
const (
	DefaultConfigPath          = defaultEtcDir + "/config.yaml"
	DefaultTLSSourceCertPath   = "/etc/pki/tls/certs/self.crt"
	DefaultTLSSourceKeyPath    = "/etc/pki/tls/private/self.key"
	DefaultRuntimeTLSDir       = defaultRuntimeDir
	DefaultRuntimeConfigPath   = defaultRuntimeDir + "/config.json"
	DefaultRuntimeTLSCertPath  = defaultRuntimeDir + "/tls.crt"
	DefaultRuntimeTLSKeyPath   = defaultRuntimeDir + "/tls.key"
	DefaultRuntimeTrustedCADir = defaultRuntimeDir
	DefaultTLSCertPath         = DefaultRuntimeTLSCertPath
	DefaultTLSKeyPath          = DefaultRuntimeTLSKeyPath
	DefaultRunUser             = "webd"
	DefaultHTTPAddr            = ":80"
	DefaultHTTPSAddr           = ":443"
	DefaultBinaryPath          = defaultLibexecDir + "/webd"
	DefaultServicePath         = "/etc/systemd/system/webd.service"
)

// ServiceUnitContent is the desired systemd unit file content written by setup.
const ServiceUnitContent = `[Unit]
Description=HTTPS Proxy
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=simple
User=webd
Group=webd
PermissionsStartOnly=true
SyslogIdentifier=webd
StandardOutput=journal
StandardError=journal
RuntimeDirectory=webd
RuntimeDirectoryMode=0750
RootDirectory=/run/webd
RootDirectoryStartOnly=true
WorkingDirectory=/
BindReadOnlyPaths=/opt/web/current/libexec/webd
BindReadOnlyPaths=/opt/web/current/sbin/webctl
BindPaths=/dev/log
ExecStartPre=/opt/web/current/sbin/webctl reload --prepare-only
ExecStart=/opt/web/current/libexec/webd
ExecReload=/opt/web/current/sbin/webctl reload
Restart=on-failure

# Security: grant low-port bind capability at service runtime
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Hardening: Prevent the app from gaining more privileges
NoNewPrivileges=true
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
	// BinaryPath is the installed webd binary path used for capability setup.
	BinaryPath string
	// Force allows setup to overwrite an existing, non-matching systemd unit file.
	Force bool
}

// DefaultRunOptions returns the runtime defaults used by the root and run commands.
func DefaultRunOptions() RunOptions {
	return RunOptions{
		ConfigPath:  DefaultConfigPath,
		HTTPAddr:    DefaultHTTPAddr,
		HTTPSAddr:   DefaultHTTPSAddr,
		TLSCertPath: DefaultTLSCertPath,
		TLSKeyPath:  DefaultTLSKeyPath,
		RunUser:     DefaultRunUser,
		Force:       false,
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
