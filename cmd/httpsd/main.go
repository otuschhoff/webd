package main

import (
	"fmt"
	"log"
	"os"

	"httpsd/internal/app"
	"httpsd/internal/server"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC | log.Lmicroseconds)
	if len(os.Args) != 1 {
		log.Printf("fatal: %v", fmt.Errorf("httpsd does not accept flags or subcommands; use httpsdctl for control operations"))
		os.Exit(1)
	}
	if err := server.Run(app.DefaultRunOptions()); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}
