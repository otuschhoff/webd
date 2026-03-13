package main

import (
	"os"

	"webd/internal/cli"
	"webd/internal/syslogx"
)

func main() {
	logs, err := syslogx.NewForCommand("webctl", false)
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
