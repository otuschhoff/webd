package cli

import (
	"github.com/spf13/cobra"

	"httpsd/internal/app"
)

// ExecuteControl runs the control-plane CLI (check, reload, setup).
func ExecuteControl() error {
	runOpts := app.DefaultRunOptions()
	setupOpts := app.DefaultSetupOptions()
	reloadOpts := DefaultOptions()

	rootCmd := &cobra.Command{
		Use:     "httpsdctl",
		Short:   "HTTPS proxy control-plane commands",
		Version: app.VersionString(),
	}

	rootCmd.PersistentFlags().StringVar(&runOpts.ConfigPath, "config", runOpts.ConfigPath, "Path to YAML reverse-proxy config")
	rootCmd.PersistentFlags().StringVar(&runOpts.HTTPAddr, "http-addr", runOpts.HTTPAddr, "HTTP listen address")
	rootCmd.PersistentFlags().StringVar(&runOpts.HTTPSAddr, "https-addr", runOpts.HTTPSAddr, "HTTPS listen address")
	rootCmd.PersistentFlags().StringVar(&runOpts.TLSCertPath, "tls-cert", runOpts.TLSCertPath, "TLS certificate file")
	rootCmd.PersistentFlags().StringVar(&runOpts.TLSKeyPath, "tls-key", runOpts.TLSKeyPath, "TLS private key file")
	rootCmd.PersistentFlags().StringVar(&runOpts.RunUser, "run-user", runOpts.RunUser, "Expected runtime user for the server process")
	reloadCmd := &cobra.Command{
		Use:   "reload",
		Short: "Stage TLS artifacts under /run and reload running httpsd",
		RunE: func(cmd *cobra.Command, args []string) error {
			reloadOpts.HTTPAddr = runOpts.HTTPAddr
			reloadOpts.HTTPSAddr = runOpts.HTTPSAddr
			reloadOpts.RunUser = runOpts.RunUser
			reloadOpts.ConfigSource = runOpts.ConfigPath
			reloadOpts.TLSCertDest = runOpts.TLSCertPath
			reloadOpts.TLSKeyDest = runOpts.TLSKeyPath
			return Run(reloadOpts)
		},
	}
	reloadCmd.Flags().StringVar(&reloadOpts.TLSCertSource, "tls-cert-source", reloadOpts.TLSCertSource, "Source TLS certificate path copied into runtime TLS path")
	reloadCmd.Flags().StringVar(&reloadOpts.TLSKeySource, "tls-key-source", reloadOpts.TLSKeySource, "Source TLS private key path copied into runtime TLS path")
	reloadCmd.Flags().BoolVar(&reloadOpts.PrepareOnly, "prepare-only", reloadOpts.PrepareOnly, "Only stage runtime TLS files without signaling running process")

	checkCmd := &cobra.Command{
		Use:           "check",
		Short:         "Validate config and print it in pretty colored YAML",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(runOpts)
		},
	}

	setupCmd := &cobra.Command{
		Use:           "setup",
		Short:         "Prepare system user/group, permissions, and service unit",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetup(setupOpts)
		},
	}
	setupCmd.Flags().StringVar(&setupOpts.TLSKeyPath, "tls-key", setupOpts.TLSKeyPath, "TLS private key path for permission setup")
	setupCmd.Flags().StringVar(&setupOpts.TLSCertPath, "tls-cert", setupOpts.TLSCertPath, "TLS certificate path for permission setup")
	setupCmd.Flags().StringVar(&setupOpts.ServicePath, "service-path", setupOpts.ServicePath, "Systemd unit file path")
	setupCmd.Flags().StringVar(&setupOpts.BinaryPath, "binary", setupOpts.BinaryPath, "httpsd binary path for setcap configuration")
	setupCmd.Flags().BoolVar(&setupOpts.Force, "force", setupOpts.Force, "Allow overwriting an existing non-matching systemd unit file")

	rootCmd.AddCommand(reloadCmd, checkCmd, setupCmd)
	return rootCmd.Execute()
}
