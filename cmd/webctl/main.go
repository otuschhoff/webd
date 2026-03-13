package main

import (
	"os"

	"webd/internal/app"
	"webd/internal/cli"
)

func main() {
	logs, err := app.NewForCommand("webctl", false)
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
