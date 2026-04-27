package main

import (
	"fmt"
	"os"

	"webd/internal/app"
	"webd/internal/server"
)

const (
	configPath    = "config.json"
	tlsCertPath   = "tls.crt"
	tlsKeyPath    = "tls.key"
	httpAddr      = ":80"
	httpsAddr     = ":443"
	minRuntimeUID = 500
	maxRuntimeUID = 999
)

func main() {
	logs, err := app.New("webd", false)
	if err != nil {
		os.Exit(1)
	}
	defer func() {
		_ = logs.Close()
	}()
	errLog := logs.Error

	if len(os.Args) != 1 {
		errLog.Printf("fatal: %v", fmt.Errorf("webd does not accept flags or subcommands; use webctl for control operations"))
		os.Exit(1)
	}

	euid := os.Geteuid()
	if euid < minRuntimeUID || euid > maxRuntimeUID {
		errLog.Printf("fatal: euid=%d is outside allowed runtime range %d-%d", euid, minRuntimeUID, maxRuntimeUID)
		os.Exit(1)
	}

	// TLS key and cert are optional (ACME-only mode will create temporary certs)
	// Config is optional (empty config for ACME-only mode)
	// Validate only the TLS key existence if cert exists (they must be paired)
	if certInfo, certErr := os.Stat(tlsCertPath); certErr == nil && !certInfo.IsDir() {
		if _, keyErr := os.ReadFile(tlsKeyPath); keyErr != nil {
			errLog.Printf("fatal: TLS cert exists but key file cannot be read: %v", keyErr)
			os.Exit(1)
		}
	}

	opts := server.RunOptions{
		ConfigPath:  configPath,
		HTTPAddr:    httpAddr,
		HTTPSAddr:   httpsAddr,
		TLSCertPath: tlsCertPath,
		TLSKeyPath:  tlsKeyPath,
	}

	if err := server.Run(opts); err != nil {
		errLog.Printf("fatal: %v", err)
		os.Exit(1)
	}
}
