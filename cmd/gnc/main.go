// cmd/gnc/main.go

package main

import (
	"fmt"
	"os"
	"time"

	"gnc/internal/args"
	"gnc/internal/capture"
	"gnc/internal/logger"
	"gnc/internal/storage"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	config := args.ParseFlags()

	// Print version if requested
	if config.ShowVersion {
		fmt.Printf("gocredz version %s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	log, err := logger.New(config.Verbose, config.Debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	store, err := storage.New(log, storage.Config{
		OutputPath: config.OutputPath,
		JSONOutput: config.JSONOutput,
		TTL:        5 * time.Minute,
	})
	if err != nil {
		log.Error("Failed to initialize storage: %v", err)
		os.Exit(1)
	}
	defer store.Close()

	capturer, err := capture.New(config, log, store)
	if err != nil {
		log.Error("Failed to initialize capture: %v", err)
		os.Exit(1)
	}

	if err := capturer.Start(); err != nil {
		log.Error("Capture failed: %v", err)
		os.Exit(1)
	}
}
