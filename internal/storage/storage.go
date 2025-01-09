// internal/storage/storage.go

package storage

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gnc/internal/logger"
	"gnc/pkg/types"

	"github.com/fatih/color"
)

// Storage handles credential storage and deduplication
type Storage struct {
	csvFile       *os.File
	csvWriter     *csv.Writer
	jsonFile      *os.File
	seen          map[string]time.Time
	mu            sync.RWMutex
	log           *logger.Logger
	outputPath    string
	llmnrDetected bool
	ipv6Detected  bool
}

// Config defines the storage configuration
type Config struct {
	OutputPath string
	JSONOutput bool
	TTL        time.Duration
}

// New creates a new storage instance
func New(log *logger.Logger, config Config) (*Storage, error) {
	if config.OutputPath == "" {
		config.OutputPath = "gocredz_output"
	}

	if config.TTL == 0 {
		config.TTL = 5 * time.Minute
	}

	s := &Storage{
		seen:       make(map[string]time.Time),
		log:        log,
		outputPath: config.OutputPath,
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(config.OutputPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	// Initialize CSV file
	csvFile, err := os.OpenFile(config.OutputPath+".csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open CSV file: %v", err)
	}

	s.csvFile = csvFile
	s.csvWriter = csv.NewWriter(csvFile)

	// Write CSV headers if file is new
	stat, err := csvFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat CSV file: %v", err)
	}

	if stat.Size() == 0 {
		if err := s.csvWriter.Write([]string{"timestamp", "protocol", "source_ip", "source_port", "dest_ip", "dest_port", "data"}); err != nil {
			return nil, fmt.Errorf("failed to write CSV headers: %v", err)
		}
		s.csvWriter.Flush()
	}

	// Initialize JSON file if enabled
	if config.JSONOutput {
		jsonFile, err := os.OpenFile(config.OutputPath+".json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			csvFile.Close()
			return nil, fmt.Errorf("failed to open JSON file: %v", err)
		}
		s.jsonFile = jsonFile
	}

	// Start cleanup goroutine
	go s.cleanupRoutine(config.TTL)

	return s, nil
}

func formatCredentialData(data map[string]string) string {
	var parts []string
	for k, v := range data {
		parts = append(parts, fmt.Sprintf("%s: %s", color.CyanString(k), color.GreenString(v)))
	}
	return strings.Join(parts, ", ")
}

func formatEndpoint(ip string, port uint16) string {
	return fmt.Sprintf("%s:%s",
		color.BlueString(ip),
		color.MagentaString("%d", port),
	)
}

// Save stores captured credentials
func (s *Storage) Save(creds *types.Credentials) error {
	if creds == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate unique key for deduplication
	key := fmt.Sprintf("%s-%s-%s-%d-%d",
		creds.Protocol,
		creds.Source.IP,
		creds.Destination.IP,
		creds.Source.Port,
		creds.Destination.Port,
	)

	// Check if we've seen this recently
	if lastSeen, exists := s.seen[key]; exists {
		if time.Since(lastSeen) < time.Minute {
			return nil // Skip duplicate
		}
	}

	// Update seen map
	s.seen[key] = time.Now()

	// Convert credentials data to JSON string
	dataJSON, err := json.Marshal(creds.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials data: %v", err)
	}

	// Write to CSV
	if err := s.csvWriter.Write([]string{
		creds.Timestamp.Format(time.RFC3339),
		creds.Protocol,
		creds.Source.IP,
		fmt.Sprintf("%d", creds.Source.Port),
		creds.Destination.IP,
		fmt.Sprintf("%d", creds.Destination.Port),
		string(dataJSON),
	}); err != nil {
		return fmt.Errorf("failed to write to CSV: %v", err)
	}
	s.csvWriter.Flush()

	// Write to JSON if enabled
	if s.jsonFile != nil {
		jsonEntry := struct {
			Timestamp   string            `json:"timestamp"`
			Protocol    string            `json:"protocol"`
			Source      types.Source      `json:"source"`
			Destination types.Source      `json:"destination"`
			Data        map[string]string `json:"data"`
		}{
			Timestamp:   creds.Timestamp.Format(time.RFC3339),
			Protocol:    creds.Protocol,
			Source:      creds.Source,
			Destination: creds.Destination,
			Data:        creds.Data,
		}

		jsonBytes, err := json.Marshal(jsonEntry)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON entry: %v", err)
		}

		if _, err := s.jsonFile.Write(append(jsonBytes, '\n')); err != nil {
			return fmt.Errorf("failed to write to JSON file: %v", err)
		}
	}

	// println("DEBUG: creds.Protocol: ", creds.Protocol)

	// Log the capture with protocol-specific messages
	if creds.Protocol == "LLMNR" {
		if !s.llmnrDetected {
			s.log.Success("LLMNR Protocol Detected on Network - Try using responder")
			s.llmnrDetected = true
		}
	} else if creds.Protocol == "IPV6" {
		if !s.ipv6Detected {
			s.log.Success("IPv6 Protocol Detected on Network - Try using mitm6")
			s.ipv6Detected = true
		}
	} else {
		s.log.Success("Captured %s Credentials:\n"+
			"  └─ From: %s\n"+
			"  └─ To:   %s\n"+
			"  └─ Data: %s",
			color.YellowString(strings.ToUpper(creds.Protocol)),
			formatEndpoint(creds.Source.IP, creds.Source.Port),
			formatEndpoint(creds.Destination.IP, creds.Destination.Port),
			formatCredentialData(creds.Data),
		)
	}

	return nil
}

// cleanupRoutine periodically removes old entries from the seen map
func (s *Storage) cleanupRoutine(ttl time.Duration) {
	ticker := time.NewTicker(ttl / 2)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for key, timestamp := range s.seen {
			if now.Sub(timestamp) > ttl {
				delete(s.seen, key)
			}
		}
		s.mu.Unlock()
	}
}

// Close closes all open files
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.csvWriter != nil {
		s.csvWriter.Flush()
	}

	if s.csvFile != nil {
		if err := s.csvFile.Close(); err != nil {
			return fmt.Errorf("failed to close CSV file: %v", err)
		}
	}

	if s.jsonFile != nil {
		if err := s.jsonFile.Close(); err != nil {
			return fmt.Errorf("failed to close JSON file: %v", err)
		}
	}

	return nil
}
