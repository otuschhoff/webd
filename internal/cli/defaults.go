package cli

import "webd/internal/server"

// Base paths used to derive default filesystem locations.
const (
	defaultEtcDir            = "/etc/webd"
	defaultRuntimeDir        = "/run/webd"
	defaultInstallCurrentDir = "/opt/webd/current"
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
BindReadOnlyPaths=/opt/webd/current/libexec/webd
BindReadOnlyPaths=/opt/webd/current/sbin/webctl
BindReadOnlyPaths=/dev/log
# Run reload helpers with full privileges outside service sandbox.
ExecStartPre=+/opt/webd/current/sbin/webctl reload --prepare-only
ExecStart=/opt/webd/current/libexec/webd
ExecReload=+/opt/webd/current/sbin/webctl reload
Restart=on-failure

# Security: grant low-port bind capability at service runtime
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Hardening: Prevent the app from gaining more privileges
NoNewPrivileges=true
LockPersonality=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Syscall Filter
SystemCallArchitectures=native
SystemCallFilter=@system-service @network-io @file-system @signal @process
SystemCallFilter=~@clock @debug @module @mount @obsolete @privileged @raw-io @reboot @swap

# Resources
MemoryMax=32M
Environment=GOMEMLIMIT=24MiB

# Jailing
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
`

// SetupOptions contains host-level paths used by the setup subcommand.
type SetupOptions struct {
	// TLSCertPath points to the source certificate file validated by setup.
	TLSCertPath string
	// TLSKeyPath points to the source private key file validated by setup.
	TLSKeyPath string
	// ServicePath is the systemd unit file path managed by setup.
	ServicePath string
	// Force allows setup to overwrite an existing, non-matching systemd unit file.
	Force bool
}

// DefaultRunOptions returns runtime defaults used by control-plane commands.
func DefaultRunOptions() server.RunOptions {
	return server.RunOptions{
		ConfigPath:  DefaultConfigPath,
		HTTPAddr:    DefaultHTTPAddr,
		HTTPSAddr:   DefaultHTTPSAddr,
		TLSCertPath: DefaultTLSCertPath,
		TLSKeyPath:  DefaultTLSKeyPath,
	}
}

// DefaultSetupOptions returns the default file paths used by the setup command.
func DefaultSetupOptions() SetupOptions {
	return SetupOptions{
		TLSCertPath: DefaultTLSSourceCertPath,
		TLSKeyPath:  DefaultTLSSourceKeyPath,
		ServicePath: DefaultServicePath,
		Force:       false,
	}
}
