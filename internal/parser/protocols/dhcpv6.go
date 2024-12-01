// internal/parser/protocols/dhcpv6.go

package protocols

import (
	"gnc/pkg/types"
)

type DHCPv6Parser struct{}

func NewDHCPv6Parser() *DHCPv6Parser {
	return &DHCPv6Parser{}
}

func (p *DHCPv6Parser) Protocol() string {
	return "dhcpv6"
}

func (p *DHCPv6Parser) Parse(packet *types.Packet) (*types.Credentials, error) {
	if packet == nil {
		return nil, nil
	}

	// Check for DHCPv6 traffic (ports 546 or 547)
	if packet.DstPort != 546 && packet.SrcPort != 546 &&
		packet.DstPort != 547 && packet.SrcPort != 547 {
		return nil, nil
	}

	// For DHCPv6, we're mainly interested in detecting its presence
	// as it indicates potential for mitm6 attacks
	return &types.Credentials{
		Protocol: "DHCPv6",
		Source: types.Source{
			IP:   packet.SrcIP.String(),
			Port: packet.SrcPort,
		},
		Destination: types.Source{
			IP:   packet.DstIP.String(),
			Port: packet.DstPort,
		},
		Data: map[string]string{
			"alert": "DHCPv6 traffic detected - potential mitm6 target",
		},
	}, nil
}
