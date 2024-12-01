// internal/parser/parser.go
package parser

import (
	"regexp"
	"sync"

	"gnc/internal/logger"
	"gnc/internal/parser/protocols"
	"gnc/pkg/types"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Parser struct {
	log            *logger.Logger
	protocolParser map[string]protocols.ProtocolParser
	customRegex    *regexp.Regexp
	enabledParsers map[uint16][]protocols.ProtocolParser
	ntlmParser     protocols.ProtocolParser
	registry       *protocols.ProtocolRegistry
}

// NewParser creates an optimized parser instance
func NewParser(log *logger.Logger, enabledProtocols []string, regexPattern string) (*Parser, error) {
	p := &Parser{
		log:            log,
		protocolParser: make(map[string]protocols.ProtocolParser),
		enabledParsers: make(map[uint16][]protocols.ProtocolParser),
		registry:       protocols.NewProtocolRegistry(),
	}

	// Handle regex pattern
	if regexPattern != "" {
		regex, err := regexp.Compile(regexPattern)
		if err != nil {
			return nil, err
		}
		p.customRegex = regex
	}

	// Expand "all" protocols
	if contains(enabledProtocols, "all") {
		enabledProtocols = p.registry.GetEnabledProtocols(enabledProtocols)
	}

	// Initialize parsers
	for _, proto := range enabledProtocols {
		var parser protocols.ProtocolParser

		switch proto {
		case "ntlm":
			parser = protocols.NewNTLMParser()
			p.ntlmParser = parser // Store NTLM parser separately
		case "ldap":
			parser = protocols.NewLDAPParser()
		case "http":
			parser = protocols.NewHTTPParser()
		case "smtp":
			parser = protocols.NewSMTPParser()
		case "snmp":
			parser = protocols.NewSNMPParser()
		case "telnet":
			parser = protocols.NewTelnetParser()
		case "ftp":
			parser = protocols.NewFTPParser()
		case "kerberos":
			parser = protocols.NewKerberosParser()
		case "dhcpv6":
			parser = protocols.NewDHCPv6Parser()
		case "llmnr":
			parser = protocols.NewLLMNRParser()
		default:
			continue
		}

		p.protocolParser[proto] = parser

		// Map parsers to their respective ports
		p.enabledParsers = p.registry.MapParsersToPorts(p.protocolParser)
	}

	return p, nil
}

func (p *Parser) ParsePacket(packet gopacket.Packet) ([]*types.Credentials, error) {
	if packet == nil {
		return nil, nil
	}

	internalPacket, err := p.convertPacket(packet)
	if err != nil || internalPacket == nil {
		return nil, err
	}

	var results []*types.Credentials
	var resultsMu sync.Mutex
	var wg sync.WaitGroup

	// Get relevant parsers based on ports
	parsers := make(map[protocols.ProtocolParser]bool)

	// Add port-specific parsers
	if portParsers, ok := p.enabledParsers[internalPacket.Source.Port]; ok {
		for _, parser := range portParsers {
			parsers[parser] = true
		}
	}
	if portParsers, ok := p.enabledParsers[internalPacket.Destination.Port]; ok {
		for _, parser := range portParsers {
			parsers[parser] = true
		}
	}

	// Always include NTLM parser if enabled
	if p.ntlmParser != nil {
		parsers[p.ntlmParser] = true
	}

	// Process with selected parsers
	for parser := range parsers {
		wg.Add(1)
		go func(parser protocols.ProtocolParser) {
			defer wg.Done()

			creds, err := parser.Parse(internalPacket)
			if err != nil || creds == nil {
				return
			}

			resultsMu.Lock()
			results = append(results, creds)
			resultsMu.Unlock()
		}(parser)
	}

	// Handle custom regex if configured
	if p.customRegex != nil && len(internalPacket.Data) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if matches := p.customRegex.Find(internalPacket.Data); matches != nil {
				resultsMu.Lock()
				results = append(results, &types.Credentials{
					Protocol:    "regex",
					Source:      internalPacket.Source,
					Destination: internalPacket.Destination,
					Data:        map[string]string{"match": string(matches)},
				})
				resultsMu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results, nil
}

func (p *Parser) convertPacket(packet gopacket.Packet) (*types.Packet, error) {
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	if networkLayer == nil || transportLayer == nil {
		return nil, nil
	}

	var srcPort, dstPort uint16
	var protocol uint8
	var payload []byte

	switch t := transportLayer.(type) {
	case *layers.TCP:
		srcPort = uint16(t.SrcPort)
		dstPort = uint16(t.DstPort)
		protocol = 6
		if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
			payload = applicationLayer.Payload()
		}
		if len(payload) == 0 {
			payload = t.LayerPayload()
		}
	case *layers.UDP:
		srcPort = uint16(t.SrcPort)
		dstPort = uint16(t.DstPort)
		protocol = 17
		payload = t.LayerPayload()
	default:
		return nil, nil
	}

	return &types.Packet{
		Timestamp: packet.Metadata().Timestamp,
		Source: types.Source{
			IP:   networkLayer.NetworkFlow().Src().String(),
			Port: srcPort,
		},
		Destination: types.Source{
			IP:   networkLayer.NetworkFlow().Dst().String(),
			Port: dstPort,
		},
		Protocol: protocol,
		Data:     payload,
	}, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
