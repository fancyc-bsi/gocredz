package protocols

import (
	"gnc/pkg/types"
)

type SNMPParser struct{}

func NewSNMPParser() *SNMPParser {
	return &SNMPParser{}
}

func (p *SNMPParser) Protocol() string {
	return "SNMP"
}

func (p *SNMPParser) Parse(packet *types.Packet) (*types.Credentials, error) {
	if packet == nil || len(packet.Data) < 10 {
		return nil, nil
	}

	if packet.Destination.Port != 161 && packet.Source.Port != 161 {
		return nil, nil
	}

	data := packet.Data
	if data[0] != 0x30 { // Not a sequence
		return nil, nil
	}

	// Skip sequence header
	data = data[2:]

	// Get version
	if len(data) < 3 || data[0] != 0x02 || data[1] != 0x01 {
		return nil, nil
	}
	version := data[2]
	if version > 1 {
		return nil, nil
	}

	// Skip version
	data = data[3:]

	// Get community string
	if len(data) < 2 || data[0] != 0x04 {
		return nil, nil
	}
	communityLen := int(data[1])
	if len(data) < 2+communityLen {
		return nil, nil
	}
	community := string(data[2 : 2+communityLen])

	versionStr := "v1"
	if version == 1 {
		versionStr = "v2c"
	}

	return &types.Credentials{
		Protocol:    "SNMP",
		Source:      packet.Source,
		Destination: packet.Destination,
		Data: map[string]string{
			"version":   versionStr,
			"community": community,
		},
	}, nil
}
