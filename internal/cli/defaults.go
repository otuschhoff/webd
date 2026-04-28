package cli

import (
	"fmt"
	"path"

	"webd/internal/server"
)

// Base paths used to derive default filesystem locations.
const (
	defaultAppName           = "webd"
	defaultServiceUser       = defaultAppName
	defaultServiceGroup      = defaultAppName
	defaultInstallRootDir    = "/opt/" + defaultAppName
	defaultEtcDir            = "/etc/" + defaultAppName
	defaultRuntimeDir        = "/run/" + defaultAppName
	defaultInstallCurrentDir = defaultInstallRootDir + "/current"
	defaultLibexecDir        = defaultInstallCurrentDir + "/libexec"
	defaultSbinDir           = defaultInstallCurrentDir + "/sbin"

	defaultSystemdJournalDevLogPath = "/run/systemd/journal/dev-log"
	defaultServiceMemoryMaxMiB      = 32
	defaultServiceGoMemPercent      = 75
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
	DefaultRunUser             = defaultServiceUser
	DefaultHTTPAddr            = ":80"
	DefaultHTTPSAddr           = ":443"
	DefaultBinaryPath          = defaultLibexecDir + "/webd"
	DefaultWebctlPath          = defaultSbinDir + "/webctl"
	DefaultServicePath         = "/etc/systemd/system/" + defaultAppName + ".service"
)

// ServiceUnitContent is the desired systemd unit file content written by setup.
var ServiceUnitContent = buildServiceUnitContent()

func buildServiceUnitContent() string {
	runtimeDirName := path.Base(defaultRuntimeDir)
	memoryMax := fmt.Sprintf("%dM", defaultServiceMemoryMaxMiB)
	goMemLimitMiB := defaultServiceMemoryMaxMiB * defaultServiceGoMemPercent / 100
	if goMemLimitMiB < 1 {
		goMemLimitMiB = 1
	}
	goMemLimit := fmt.Sprintf("%dMiB", goMemLimitMiB)

	return fmt.Sprintf(`[Unit]
Description=HTTPS Proxy
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=simple
User=%s
Group=%s
PermissionsStartOnly=true
SyslogIdentifier=%s
StandardOutput=journal
StandardError=journal
RuntimeDirectory=%s
RuntimeDirectoryMode=0750
RootDirectory=%s
RootDirectoryStartOnly=true
WorkingDirectory=/
PrivateDevices=true
ProtectProc=invisible
ProcSubset=pid
BindReadOnlyPaths=%s
BindReadOnlyPaths=%s
BindReadOnlyPaths=/dev/log
BindReadOnlyPaths=%s:/dev/log
TemporaryFileSystem=/tmp
TemporaryFileSystem=/run
# Run reload helpers with full privileges outside service sandbox.
ExecStartPre=+%s reload --prepare-only
ExecStart=%s
ExecReload=+%s reload
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
SystemCallFilter=~unlink unlinkat rename renameat renameat2 rmdir mkdir mkdirat mknod mknodat link linkat symlink symlinkat

# Resources
MemoryMax=%s
Environment=GOMEMLIMIT=%s

# Jailing
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
`,
		defaultServiceUser,
		defaultServiceGroup,
		defaultAppName,
		runtimeDirName,
		defaultRuntimeDir,
		DefaultBinaryPath,
		DefaultWebctlPath,
		defaultSystemdJournalDevLogPath,
		DefaultWebctlPath,
		DefaultBinaryPath,
		DefaultWebctlPath,
		memoryMax,
		goMemLimit,
	)
}

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
