package main

import (
	"fmt"
	"os"

	"httpsd/internal/server"
	"httpsd/internal/syslogx"
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
	logs, err := syslogx.New("httpsd", false)
	if err != nil {
		os.Exit(1)
	}
	defer func() {
		_ = logs.Close()
	}()
	errLog := logs.Error

	if len(os.Args) != 1 {
		errLog.Printf("fatal: %v", fmt.Errorf("httpsd does not accept flags or subcommands; use httpsdctl for control operations"))
		os.Exit(1)
	}

	euid := os.Geteuid()
	if euid < minRuntimeUID || euid > maxRuntimeUID {
		errLog.Printf("fatal: euid=%d is outside allowed runtime range %d-%d", euid, minRuntimeUID, maxRuntimeUID)
		os.Exit(1)
	}

	for _, path := range []string{configPath, tlsCertPath, tlsKeyPath} {
		if _, err := os.ReadFile(path); err != nil {
			errLog.Printf("fatal: read required file %s failed: %v", path, err)
			os.Exit(1)
		}
	}

	opts := server.RunOptions{
		ConfigPath:  configPath,
		HTTPAddr:    httpAddr,
		HTTPSAddr:   httpsAddr,
		TLSCertPath: tlsCertPath,
		TLSKeyPath:  tlsKeyPath,
		RunUser:     "",
		Force:       true,
	}

	if err := server.Run(opts); err != nil {
		errLog.Printf("fatal: %v", err)
		os.Exit(1)
	}
}
