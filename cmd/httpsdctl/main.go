package main

import (
	"log"
	"os"

	"httpsd/internal/cli"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC | log.Lmicroseconds)
	if err := cli.ExecuteControl(); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}
