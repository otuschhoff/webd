package main

import (
	"os"

	"httpsd/internal/cli"
	"httpsd/internal/syslogx"
)

func main() {
	logs, err := syslogx.NewForCommand("httpsdctl", false)
	if err != nil {
		os.Exit(1)
	}
	defer func() {
		_ = logs.Close()
	}()
	errLog := logs.Error

	if err := cli.ExecuteControl(); err != nil {
		errLog.Printf("fatal: %v", err)
		os.Exit(1)
	}
}
