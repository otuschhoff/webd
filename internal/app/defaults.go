package app

const (
	DefaultConfigPath   = "/etc/httpsd/config.json"
	DefaultTLSCertPath  = "/etc/pki/tls/certs/selfcrt"
	DefaultTLSKeyPath   = "/etc/pki/tls/private/self.key"
	DefaultAccessLog    = "/var/log/httpsd/access.log"
	DefaultRunUser      = "httpsd"
	DefaultHTTPAddr     = ":80"
	DefaultHTTPSAddr    = ":443"
	DefaultBinaryPath   = "/opt/httpsd/current/sbin/httpsd"
	DefaultServicePath  = "/etc/systemd/system/httpsd.service"
	AccessLogRotateSize = int64(1 * 1024 * 1024)
)

const ServiceUnitContent = `[Unit]
Description=Custom HTTPS Proxy for internal app
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

type RunOptions struct {
	ConfigPath    string
	HTTPAddr      string
	HTTPSAddr     string
	TLSCertPath   string
	TLSKeyPath    string
	AccessLogPath string
	RunUser       string
	Force         bool
}

type SetupOptions struct {
	TLSCertPath string
	TLSKeyPath  string
	ServicePath string
	BinaryPath  string
}

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

func DefaultSetupOptions() SetupOptions {
	return SetupOptions{
		TLSCertPath: DefaultTLSCertPath,
		TLSKeyPath:  DefaultTLSKeyPath,
		ServicePath: DefaultServicePath,
		BinaryPath:  DefaultBinaryPath,
	}
}
