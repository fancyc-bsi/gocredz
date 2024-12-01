// internal/capture/capture.go

package capture

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"gnc/internal/logger"
	"gnc/internal/parser"
	"gnc/internal/storage"
	"gnc/pkg/types"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	snapLen = 65536
	timeout = pcap.BlockForever
)

type Capture struct {
	config *types.Config
	log    *logger.Logger
	store  *storage.Storage
	parser *parser.Parser
	handle *pcap.Handle
	seen   map[string]time.Time
	mutex  sync.RWMutex
}

func New(config *types.Config, log *logger.Logger, store *storage.Storage) (*Capture, error) {
	p, err := parser.NewParser(log, config.Filters, config.Regex)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize parser: %v", err)
	}

	return &Capture{
		config: config,
		log:    log,
		store:  store,
		parser: p,
		seen:   make(map[string]time.Time),
	}, nil
}

func (c *Capture) Start() error {
	if c.config.PcapFile != "" {
		return c.processPcapFile()
	}
	return c.startLiveCapture()
}

func (c *Capture) startLiveCapture() error {
	var err error

	// Add BPF filter for supported protocols
	filter := c.buildBPFFilter()
	c.log.Info("Using BPF filter: %s", filter)

	c.handle, err = pcap.OpenLive(c.config.Interface, snapLen, true, timeout)
	if err != nil {
		return fmt.Errorf("error opening interface: %v", err)
	}
	defer c.handle.Close()

	// Set the BPF filter
	if err := c.handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("error setting BPF filter: %v", err)
	}

	if c.config.Regex != "" {
		c.log.Info("Using custom regex pattern: %s", c.config.Regex)
	}

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	return c.processPackets(packetSource.Packets())
}

// buildBPFFilter creates a BPF filter string for the enabled protocols
func (c *Capture) buildBPFFilter() string {
	var filters []string

	for _, proto := range c.config.Filters {
		switch proto {
		case "http":
			filters = append(filters, "tcp port 80 or tcp port 8080 or tcp port 443")
		case "telnet":
			filters = append(filters, "tcp port 23")
		case "ftp":
			filters = append(filters, "tcp port 21")
		case "smtp":
			filters = append(filters, "tcp port 25 or tcp port 587 or tcp port 465")
		case "ldap":
			filters = append(filters, "tcp port 389 or tcp port 636")
		case "snmp":
			filters = append(filters, "udp port 161 or udp port 162")
		case "kerberos":
			filters = append(filters, "tcp port 88 or udp port 88")
		case "dhcpv6":
			filters = append(filters, "udp port 546 or udp port 547")
		case "llmnr":
			filters = append(filters, "udp port 5355")
		case "dnsv6":
			filters = append(filters, "udp port 53 or tcp port 53")
		}
	}

	if len(filters) == 0 {
		return "tcp or udp"
	}

	return strings.Join(filters, " or ")
}

func (c *Capture) processPcapFile() error {
	var err error
	c.handle, err = pcap.OpenOffline(c.config.PcapFile)
	if err != nil {
		return fmt.Errorf("error opening pcap file: %v", err)
	}
	defer c.handle.Close()

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	return c.processPackets(packetSource.Packets())
}

func (c *Capture) processPackets(packets chan gopacket.Packet) error {
	c.log.Info("Starting packet processing...")

	for packet := range packets {
		if packet == nil {
			continue
		}

		// Enhanced debug logging
		if c.config.Debug {
			if transportLayer := packet.TransportLayer(); transportLayer != nil {
				srcPort := uint16(0)
				dstPort := uint16(0)

				switch t := transportLayer.(type) {
				case *layers.TCP:
					srcPort = uint16(t.SrcPort)
					dstPort = uint16(t.DstPort)
					// Add payload debugging
					c.log.Debug("TCP Payload (hex): %x", t.Payload)
					c.log.Debug("TCP Payload (string): %q", string(t.Payload))
				case *layers.UDP:
					srcPort = uint16(t.SrcPort)
					dstPort = uint16(t.DstPort)
				}

				c.log.Debug("Processing packet: %s:%d -> %s:%d (Length: %d)",
					packet.NetworkLayer().NetworkFlow().Src(),
					srcPort,
					packet.NetworkLayer().NetworkFlow().Dst(),
					dstPort,
					len(transportLayer.LayerPayload()),
				)
			}
		}

		if c.isDuplicate(packet) {
			c.log.Debug("Skipping duplicate packet")
			continue
		}

		// Add debug before parsing
		c.log.Debug("Sending packet to parsers")
		creds, err := c.parser.ParsePacket(packet)
		if err != nil {
			c.log.Debug("Error parsing packet: %v", err)
			continue
		}

		if creds != nil {
			c.log.Debug("Found credentials: %+v", creds)
		}

		for _, cred := range creds {
			err = c.store.Save(cred)
			if err != nil {
				c.log.Error("Error saving credentials: %v", err)
			}
		}
	}
	return nil
}

func (c *Capture) isDuplicate(packet gopacket.Packet) bool {
	// For telnet traffic, we don't want to deduplicate
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		switch t := transportLayer.(type) {
		case *layers.TCP:
			if uint16(t.SrcPort) == 23 || uint16(t.DstPort) == 23 {
				return false // Never deduplicate telnet traffic
			}
		}
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Clean up old entries
	now := time.Now()
	for hash, timestamp := range c.seen {
		if now.Sub(timestamp) > 5*time.Second {
			delete(c.seen, hash)
		}
	}

	// For non-telnet traffic, use the original deduplication logic
	hash := packet.Data()
	hashStr := fmt.Sprintf("%x", hash)

	if _, exists := c.seen[hashStr]; exists {
		return true
	}

	c.seen[hashStr] = now
	return false
}
