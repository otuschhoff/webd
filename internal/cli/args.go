package cli

import (
	"fmt"
	"io"
	"runtime/debug"
	"sort"
	"strings"

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
		Use:   "webctl",
		Short: "HTTPS proxy control-plane commands",
	}
	rootCmd.AddGroup(
		&cobra.Group{ID: "info", Title: "Info Commands"},
		&cobra.Group{ID: "ops", Title: "Control Commands"},
	)
	addCompletionCommand(rootCmd)
	rootCmd.SetHelpCommand(newHelpCommand(rootCmd))

	rootCmd.PersistentFlags().StringVar(&runOpts.ConfigPath, "config", runOpts.ConfigPath, "Path to YAML reverse-proxy config")
	rootCmd.PersistentFlags().StringVar(&runOpts.HTTPAddr, "http-addr", runOpts.HTTPAddr, "HTTP listen address")
	rootCmd.PersistentFlags().StringVar(&runOpts.HTTPSAddr, "https-addr", runOpts.HTTPSAddr, "HTTPS listen address")
	rootCmd.PersistentFlags().StringVar(&runOpts.TLSCertPath, "tls-cert", runOpts.TLSCertPath, "TLS certificate file")
	rootCmd.PersistentFlags().StringVar(&runOpts.TLSKeyPath, "tls-key", runOpts.TLSKeyPath, "TLS private key file")
	rootCmd.PersistentFlags().StringVar(&reloadOpts.RunUser, "run-user", reloadOpts.RunUser, "Expected runtime user for the server process")
	versionCmd := &cobra.Command{
		Use:           "version",
		Aliases:       []string{"v", "V"},
		Short:         "Show build, Go, and dependency versions",
		SilenceUsage:  true,
		SilenceErrors: true,
		GroupID:       "info",
		Args:          cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			printVersionInfo(cmd.OutOrStdout())
		},
	}
	reloadCmd := &cobra.Command{
		Use:     "reload",
		Short:   "Stage TLS artifacts under /run and reload running webd",
		GroupID: "ops",
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
	reloadCmd.Flags().BoolVar(&reloadOpts.OnlyLocalTLS, "only-local-tls", reloadOpts.OnlyLocalTLS, "Only compare and stage local TLS cert/key files; skip runtime config and handler trust material updates")
	reloadCmd.Flags().BoolVar(&reloadOpts.PrepareOnly, "prepare-only", reloadOpts.PrepareOnly, "Only stage runtime TLS files without signaling running process")

	reloadTimerInterval := defaultReloadTimerPeriod
	reloadTimerCmd := &cobra.Command{
		Use:     "reload-timer",
		Short:   "Manage periodic local TLS refresh timer for webd",
		GroupID: "ops",
	}
	reloadTimerAddCmd := &cobra.Command{
		Use:           "add",
		Short:         "Install and enable daily local TLS refresh timer",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReloadTimerAdd(reloadTimerInterval)
		},
	}
	reloadTimerAddCmd.Flags().StringVarP(&reloadTimerInterval, "interval", "i", reloadTimerInterval, "Timer interval (e.g. 10m, 1h, 12h, 1d)")

	reloadTimerShowCmd := &cobra.Command{
		Use:           "show",
		Short:         "Show current reload timer setup and runtime state",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReloadTimerShow()
		},
	}

	reloadTimerModifyCmd := &cobra.Command{
		Use:           "modify",
		Short:         "Modify reload timer settings",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReloadTimerModify(reloadTimerInterval)
		},
	}
	reloadTimerModifyCmd.Flags().StringVarP(&reloadTimerInterval, "interval", "i", reloadTimerInterval, "Timer interval (e.g. 10m, 1h, 12h, 1d)")

	reloadTimerDeleteCmd := &cobra.Command{
		Use:           "delete",
		Short:         "Disable and remove reload timer",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReloadTimerDelete()
		},
	}
	reloadTimerCmd.AddCommand(reloadTimerAddCmd, reloadTimerShowCmd, reloadTimerModifyCmd, reloadTimerDeleteCmd)

	checkCmd := &cobra.Command{
		Use:           "check",
		Short:         "Validate config and print it in pretty colored YAML",
		SilenceUsage:  true,
		SilenceErrors: true,
		GroupID:       "ops",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(runOpts)
		},
	}

	setupCmd := &cobra.Command{
		Use:           "setup",
		Short:         "Prepare system user/group, permissions, and service unit",
		SilenceUsage:  true,
		SilenceErrors: true,
		GroupID:       "ops",
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
		GroupID:       "ops",
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

	rootCmd.AddCommand(versionCmd, reloadCmd, reloadTimerCmd, checkCmd, setupCmd, letsEncryptCmd)
	return rootCmd.Execute()
}

func printVersionInfo(w io.Writer) {
	fmt.Fprintf(w, "webctl %s\n", app.VersionString())

	bi, ok := debug.ReadBuildInfo()
	if !ok || bi == nil {
		fmt.Fprintln(w, "go unknown")
		fmt.Fprintln(w, "dependencies unknown")
		return
	}

	fmt.Fprintf(w, "go %s\n", strings.TrimSpace(bi.GoVersion))

	deps := make([]*debug.Module, 0, len(bi.Deps))
	for _, dep := range bi.Deps {
		if dep != nil {
			deps = append(deps, dep)
		}
	}
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].Path < deps[j].Path
	})

	fmt.Fprintln(w, "dependencies:")
	for _, dep := range deps {
		version := dep.Version
		if version == "" {
			version = "unknown"
		}
		if dep.Replace != nil {
			replVersion := dep.Replace.Version
			if replVersion == "" {
				replVersion = "(local)"
			}
			fmt.Fprintf(w, "  %s %s => %s %s\n", dep.Path, version, dep.Replace.Path, replVersion)
			continue
		}
		fmt.Fprintf(w, "  %s %s\n", dep.Path, version)
	}
}

func newHelpCommand(rootCmd *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:           "help [command]",
		Short:         "Help about any command",
		SilenceUsage:  true,
		SilenceErrors: true,
		GroupID:       "info",
		Args:          cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			helpTarget := rootCmd
			if len(args) > 0 {
				found, _, err := rootCmd.Find(args)
				if err != nil {
					return err
				}
				helpTarget = found
			}
			return helpTarget.Help()
		},
	}
}
