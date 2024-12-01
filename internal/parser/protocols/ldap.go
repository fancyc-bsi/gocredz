// internal/parser/protocols/ldap.go

package protocols

import (
	"bytes"
	"encoding/asn1"
	"fmt"

	"gnc/pkg/types"
)

type LDAPParser struct{}

func NewLDAPParser() *LDAPParser {
	return &LDAPParser{}
}

func (p *LDAPParser) Protocol() string {
	return "ldap"
}

type bindRequest struct {
	Version  int
	Name     string
	AuthData asn1.RawValue
}

func (p *LDAPParser) Parse(packet *types.Packet) (*types.Credentials, error) {
	if packet == nil || len(packet.Data) < 10 {
		return nil, nil
	}

	// Check if it's LDAP traffic (port 389 or 636)
	if packet.DstPort != 389 && packet.DstPort != 636 {
		return nil, nil
	}

	// Look for LDAP Bind Request
	// LDAP Bind Request starts with 0x30 (Sequence) followed by length
	if packet.Data[0] != 0x30 {
		return nil, nil
	}

	// Look for Simple Authentication (0x60)
	bindIndex := bytes.Index(packet.Data, []byte{0x60})
	if bindIndex == -1 {
		return nil, nil
	}

	// Try to parse the LDAP bind request
	var bind bindRequest
	_, err := asn1.Unmarshal(packet.Data[bindIndex:], &bind)
	if err != nil {
		return nil, fmt.Errorf("failed to parse LDAP bind: %v", err)
	}

	// Only process Simple Authentication
	if bind.AuthData.Tag != 0 {
		return nil, nil
	}

	// Extract the password from the authentication data
	password := string(bind.AuthData.Bytes)

	return &types.Credentials{
		Protocol: "LDAP",
		Source: types.Source{
			IP:   packet.SrcIP.String(),
			Port: packet.SrcPort,
		},
		Destination: types.Source{
			IP:   packet.DstIP.String(),
			Port: packet.DstPort,
		},
		Data: map[string]string{
			"bind_dn":  bind.Name,
			"password": password,
			"version":  fmt.Sprintf("%d", bind.Version),
		},
	}, nil
}
