package cli

import (
	"github.com/spf13/cobra"

	"webd/internal/app"
)

// ExecuteControl runs the control-plane CLI (check, reload, setup, letsencrypt).
func ExecuteControl() error {
	runOpts := DefaultRunOptions()
	setupOpts := DefaultSetupOptions()
	reloadOpts := DefaultOptions()
	letsEncryptOpts := defaultLetsEncryptOptions()

	rootCmd := &cobra.Command{
		Use:     "webctl",
		Short:   "HTTPS proxy control-plane commands",
		Version: app.VersionString(),
	}

	rootCmd.PersistentFlags().StringVar(&runOpts.ConfigPath, "config", runOpts.ConfigPath, "Path to YAML reverse-proxy config")
	rootCmd.PersistentFlags().StringVar(&runOpts.HTTPAddr, "http-addr", runOpts.HTTPAddr, "HTTP listen address")
	rootCmd.PersistentFlags().StringVar(&runOpts.HTTPSAddr, "https-addr", runOpts.HTTPSAddr, "HTTPS listen address")
	rootCmd.PersistentFlags().StringVar(&runOpts.TLSCertPath, "tls-cert", runOpts.TLSCertPath, "TLS certificate file")
	rootCmd.PersistentFlags().StringVar(&runOpts.TLSKeyPath, "tls-key", runOpts.TLSKeyPath, "TLS private key file")
	rootCmd.PersistentFlags().StringVar(&reloadOpts.RunUser, "run-user", reloadOpts.RunUser, "Expected runtime user for the server process")
	reloadCmd := &cobra.Command{
		Use:   "reload",
		Short: "Stage TLS artifacts under /run and reload running webd",
		RunE: func(cmd *cobra.Command, args []string) error {
			reloadOpts.HTTPAddr = runOpts.HTTPAddr
			reloadOpts.HTTPSAddr = runOpts.HTTPSAddr
			reloadOpts.ConfigSource = runOpts.ConfigPath
			reloadOpts.TLSCertDest = runOpts.TLSCertPath
			reloadOpts.TLSKeyDest = runOpts.TLSKeyPath
			return Run(reloadOpts)
		},
	}
	reloadCmd.Flags().StringVar(&reloadOpts.TLSCertSource, "tls-cert-source", reloadOpts.TLSCertSource, "Source TLS certificate path copied into runtime TLS path")
	reloadCmd.Flags().StringVar(&reloadOpts.TLSKeySource, "tls-key-source", reloadOpts.TLSKeySource, "Source TLS private key path copied into runtime TLS path")
	reloadCmd.Flags().BoolVarP(&reloadOpts.Force, "force", "f", reloadOpts.Force, "Reload even when staged runtime artifacts are unchanged")
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
	setupCmd.Flags().BoolVar(&setupOpts.Force, "force", setupOpts.Force, "Allow overwriting an existing non-matching systemd unit file")

	letsEncryptCmd := &cobra.Command{
		Use:           "letsencrypt",
		Short:         "Request a Let's Encrypt certificate and deploy it",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			letsEncryptOpts.Reload.HTTPAddr = runOpts.HTTPAddr
			letsEncryptOpts.Reload.HTTPSAddr = runOpts.HTTPSAddr
			letsEncryptOpts.Reload.RunUser = reloadOpts.RunUser
			letsEncryptOpts.Reload.ConfigSource = runOpts.ConfigPath
			letsEncryptOpts.Reload.TLSCertDest = runOpts.TLSCertPath
			letsEncryptOpts.Reload.TLSKeyDest = runOpts.TLSKeyPath
			return RunLetsEncrypt(letsEncryptOpts)
		},
	}
	letsEncryptCmd.Flags().StringVar(&letsEncryptOpts.Host, "host", letsEncryptOpts.Host, "DNS host name to request (defaults to local FQDN)")
	letsEncryptCmd.Flags().StringVar(&letsEncryptOpts.Email, "email", letsEncryptOpts.Email, "Contact email for ACME account (defaults to it@<domain-of-host>)")
	letsEncryptCmd.Flags().StringVar(&letsEncryptOpts.DirectoryURL, "directory-url", letsEncryptOpts.DirectoryURL, "ACME directory URL")
	letsEncryptCmd.Flags().StringVar(&letsEncryptOpts.ChallengeDir, "challenge-dir", letsEncryptOpts.ChallengeDir, "Directory where webd serves ACME HTTP-01 challenge files")
	letsEncryptCmd.Flags().StringVar(&letsEncryptOpts.CertPath, "cert-path", letsEncryptOpts.CertPath, "Path to save certificate chain PEM")
	letsEncryptCmd.Flags().StringVar(&letsEncryptOpts.KeyPath, "key-path", letsEncryptOpts.KeyPath, "Path to save private key PEM")
	letsEncryptCmd.Flags().BoolVar(&letsEncryptOpts.Deploy, "deploy", letsEncryptOpts.Deploy, "Deploy to running webd after issuance")

	rootCmd.AddCommand(reloadCmd, checkCmd, setupCmd, letsEncryptCmd)
	return rootCmd.Execute()
}
