package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"httpsd/internal/app"
	"httpsd/internal/proxycfg"
	"httpsd/internal/reloadcmd"
	"httpsd/internal/server"
	"httpsd/internal/setup"
)

func Execute() error {
	runOpts := app.DefaultRunOptions()
	setupOpts := app.DefaultSetupOptions()

	rootCmd := &cobra.Command{
		Use:   "httpsd",
		Short: "HTTPS reverse proxy daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return server.Run(runOpts)
		},
	}

	rootCmd.PersistentFlags().StringVar(&runOpts.ConfigPath, "config", runOpts.ConfigPath, "Path to JSON reverse-proxy config")
	rootCmd.PersistentFlags().StringVar(&runOpts.HTTPAddr, "http-addr", runOpts.HTTPAddr, "HTTP listen address")
	rootCmd.PersistentFlags().StringVar(&runOpts.HTTPSAddr, "https-addr", runOpts.HTTPSAddr, "HTTPS listen address")
	rootCmd.PersistentFlags().StringVar(&runOpts.TLSCertPath, "tls-cert", runOpts.TLSCertPath, "TLS certificate file")
	rootCmd.PersistentFlags().StringVar(&runOpts.TLSKeyPath, "tls-key", runOpts.TLSKeyPath, "TLS private key file")
	rootCmd.PersistentFlags().StringVar(&runOpts.AccessLogPath, "access-log", runOpts.AccessLogPath, "Access log path")
	rootCmd.PersistentFlags().StringVar(&runOpts.RunUser, "run-user", runOpts.RunUser, "Expected runtime user for the server process")
	rootCmd.PersistentFlags().BoolVar(&runOpts.Force, "force", runOpts.Force, "Allow running as a user other than --run-user")

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run HTTPS proxy server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return server.Run(runOpts)
		},
	}

	reloadCmd := &cobra.Command{
		Use:   "reload",
		Short: "Reload running httpsd instance(s)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return reloadcmd.Run()
		},
	}

	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Validate config and print it in pretty colored JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(runOpts.ConfigPath)
		},
	}

	setupCmd := &cobra.Command{
		Use:   "setup",
		Short: "Prepare system user/group, permissions, and service unit",
		RunE: func(cmd *cobra.Command, args []string) error {
			return setup.Run(setupOpts)
		},
	}
	setupCmd.Flags().StringVar(&setupOpts.TLSKeyPath, "tls-key", setupOpts.TLSKeyPath, "TLS private key path for permission setup")
	setupCmd.Flags().StringVar(&setupOpts.ServicePath, "service-path", setupOpts.ServicePath, "Systemd unit file path")

	rootCmd.AddCommand(runCmd, reloadCmd, checkCmd, setupCmd)
	return rootCmd.Execute()
}

func runCheck(configPath string) error {
	cfg, err := proxycfg.Load(configPath)
	if err != nil {
		return err
	}
	pretty, err := proxycfg.PrettyJSON(cfg)
	if err != nil {
		return err
	}

	fmt.Println(proxycfg.ColorizeJSON(pretty, os.Getenv("NO_COLOR") == ""))
	return nil
}
