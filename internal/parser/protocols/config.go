// internal/parser/protocols/config.go

package protocols

// Protocol represents a network protocol configuration
type Protocol struct {
	Name          string
	Ports         map[uint16]bool
	CanBeEmbedded bool // For protocols like NTLM
	IsSecure      bool // For protocols like HTTPS, LDAPS - currently not impliemnted but can be used for the future
}

// ProtocolRegistry holds all protocol configurations
type ProtocolRegistry struct {
	Protocols map[string]Protocol
}

// NewProtocolRegistry creates and initializes the protocol registry
func NewProtocolRegistry() *ProtocolRegistry {
	return &ProtocolRegistry{
		Protocols: map[string]Protocol{
			"http": {
				Name: "http",
				Ports: map[uint16]bool{
					80:   true,
					443:  true,
					8080: true,
					8443: true,
				},
				IsSecure: false,
			},
			"ldap": {
				Name: "ldap",
				Ports: map[uint16]bool{
					389: true,
					636: true,
				},
				IsSecure: false,
			},
			"smtp": {
				Name: "smtp",
				Ports: map[uint16]bool{
					25:  true,
					587: true,
					465: true,
				},
				IsSecure: false,
			},
			"snmp": {
				Name: "snmp",
				Ports: map[uint16]bool{
					161: true,
					162: true,
				},
				IsSecure: false,
			},
			"telnet": {
				Name: "telnet",
				Ports: map[uint16]bool{
					23: true,
				},
				IsSecure: false,
			},
			"ftp": {
				Name: "ftp",
				Ports: map[uint16]bool{
					20: true,
					21: true,
				},
				IsSecure: false,
			},
			"kerberos": {
				Name: "kerberos",
				Ports: map[uint16]bool{
					88: true,
				},
				IsSecure: true,
			},
			"dhcpv6": {
				Name: "dhcpv6",
				Ports: map[uint16]bool{
					546: true,
					547: true,
				},
				IsSecure: false,
			},
			"llmnr": {
				Name: "llmnr",
				Ports: map[uint16]bool{
					5355: true,
				},
				IsSecure: false,
			},
			"ntlm": {
				Name: "ntlm",
				Ports: map[uint16]bool{
					445: true, // SMB
				},
				CanBeEmbedded: true,
			},
		},
	}
}

// GetSupportedProtocols returns a slice of all supported protocol names
func (pr *ProtocolRegistry) GetSupportedProtocols() []string {
	protocols := make([]string, 0, len(pr.Protocols))
	for name := range pr.Protocols {
		protocols = append(protocols, name)
	}
	return protocols
}

// GetPortsForProtocol returns the ports map for a given protocol
func (pr *ProtocolRegistry) GetPortsForProtocol(protocol string) map[uint16]bool {
	if p, exists := pr.Protocols[protocol]; exists {
		return p.Ports
	}
	return nil
}

// IsProtocolEmbeddable checks if a protocol can be embedded in others
func (pr *ProtocolRegistry) IsProtocolEmbeddable(protocol string) bool {
	if p, exists := pr.Protocols[protocol]; exists {
		return p.CanBeEmbedded
	}
	return false
}

// In protocols/config.go
func (pr *ProtocolRegistry) MapParsersToPorts(parsers map[string]ProtocolParser) map[uint16][]ProtocolParser {
	portMap := make(map[uint16][]ProtocolParser)

	for protoName, parser := range parsers {
		protocol, exists := pr.Protocols[protoName]
		if !exists {
			continue
		}

		// Add parser to each port it handles
		for port := range protocol.Ports {
			portMap[port] = append(portMap[port], parser)
		}
	}

	return portMap
}

func (pr *ProtocolRegistry) GetEnabledProtocols(requested []string) []string {
	if len(requested) == 0 {
		return nil
	}

	for _, proto := range requested {
		if proto == "all" {
			return pr.GetSupportedProtocols()
		}
	}

	// Return only valid protocols from the requested list
	valid := make([]string, 0, len(requested))
	for _, proto := range requested {
		if _, exists := pr.Protocols[proto]; exists {
			valid = append(valid, proto)
		}
	}

	return valid
}
