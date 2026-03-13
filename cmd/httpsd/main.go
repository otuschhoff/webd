package main

import (
	"fmt"
	"log"
	"os"

	"httpsd/internal/app"
	"httpsd/internal/server"
)

const (
	configPath    = "/etc/httpsd/config.yaml"
	tlsCertPath   = "/run/httpsd/tls.crt"
	tlsKeyPath    = "/run/httpsd/tls.key"
	resolvConf    = "/etc/resolv.conf"
	accessLogPath = "/var/log/httpsd/access.log"
	httpAddr      = ":80"
	httpsAddr     = ":443"
	minRuntimeUID = 500
	maxRuntimeUID = 999
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC | log.Lmicroseconds)
	if len(os.Args) != 1 {
		log.Printf("fatal: %v", fmt.Errorf("httpsd does not accept flags or subcommands; use httpsdctl for control operations"))
		os.Exit(1)
	}

	euid := os.Geteuid()
	if euid < minRuntimeUID || euid > maxRuntimeUID {
		log.Printf("fatal: euid=%d is outside allowed runtime range %d-%d", euid, minRuntimeUID, maxRuntimeUID)
		os.Exit(1)
	}

	for _, path := range []string{configPath, tlsCertPath, tlsKeyPath, resolvConf} {
		if _, err := os.ReadFile(path); err != nil {
			log.Printf("fatal: read required file %s failed: %v", path, err)
			os.Exit(1)
		}
	}

	opts := app.RunOptions{
		ConfigPath:    configPath,
		HTTPAddr:      httpAddr,
		HTTPSAddr:     httpsAddr,
		TLSCertPath:   tlsCertPath,
		TLSKeyPath:    tlsKeyPath,
		AccessLogPath: accessLogPath,
		RunUser:       "",
		Force:         true,
	}

	if err := server.Run(opts); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}
