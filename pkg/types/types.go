// pkg/types/types.go

package types

import (
	"net"
	"time"
)

// Config holds the application configuration
type Config struct {
	Interface   string
	PcapFile    string
	Debug       bool
	Verbose     int
	Filters     []string
	Regex       string
	OutputPath  string
	JSONOutput  bool
	ShowVersion bool
	EnableMitm6 bool
	LocalDomain string
	RelayTarget string
	IPv6Prefix  string
	NoRA        bool
	IPTarget    string
}

// Source represents a network endpoint
type Source struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

// Packet represents an internal packet structure
type Packet struct {
	Timestamp   time.Time
	SrcMAC      net.HardwareAddr
	DstMAC      net.HardwareAddr
	EthType     uint16
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	Data        []byte
	Length      uint16
	Source      Source
	Destination Source
}

// Credentials represents captured credential data
type Credentials struct {
	Timestamp   time.Time         `json:"timestamp"`
	Protocol    string            `json:"protocol"`
	Source      Source            `json:"source"`
	Destination Source            `json:"destination"`
	Data        map[string]string `json:"data"`
}
