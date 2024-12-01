// internal/parser/protocols/kerberos.go

package protocols

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"gnc/pkg/types"
)

type KerberosParser struct{}

func NewKerberosParser() *KerberosParser {
	return &KerberosParser{}
}

func (p *KerberosParser) Protocol() string {
	return "kerberos"
}

func (p *KerberosParser) Parse(packet *types.Packet) (*types.Credentials, error) {
	if packet == nil || len(packet.Data) < 10 {
		return nil, nil
	}

	// Check if it's Kerberos traffic (port 88)
	if packet.DstPort != 88 && packet.SrcPort != 88 {
		return nil, nil
	}

	// Look for AS-REQ message type (10) and encryption type rc4-hmac (23)
	msgType := packet.Data[19]
	if msgType != 0x0a { // AS-REQ
		return nil, nil
	}

	// Try to find encryption type and hash
	var hash []byte
	var name, domain string

	// Parse TCP Kerberos
	if packet.Protocol == 6 { // TCP
		encType := packet.Data[41]
		messageType := packet.Data[30]

		if encType == 0x17 && messageType == 0x02 { // rc4-hmac and AS-REQ
			// Extract hash based on different packet structures
			if bytes.Equal(packet.Data[49:53], []byte{0xa2, 0x36, 0x04, 0x34}) ||
				bytes.Equal(packet.Data[49:53], []byte{0xa2, 0x35, 0x04, 0x33}) {
				hash = packet.Data[53:105]
				name, domain = p.extractNameDomain(packet.Data[153:])
			} else {
				hash = packet.Data[48:100]
				name, domain = p.extractNameDomain(packet.Data[148:])
			}
		}
	} else if packet.Protocol == 17 { // UDP
		encType := packet.Data[39]
		if encType == 0x17 { // rc4-hmac
			if bytes.Equal(packet.Data[40:44], []byte{0xa2, 0x36, 0x04, 0x34}) ||
				bytes.Equal(packet.Data[40:44], []byte{0xa2, 0x35, 0x04, 0x33}) {
				hash = packet.Data[44:96]
				name, domain = p.extractNameDomain(packet.Data[144:])
			}
		}
	}

	if hash == nil || name == "" || domain == "" {
		return nil, nil
	}

	// Build Kerberos hash in crackable format
	switchedHash := append(hash[16:], hash[:16]...)
	kerberosHash := fmt.Sprintf("$krb5pa$23$%s$%s$dummy$%s",
		name, domain, hex.EncodeToString(switchedHash))

	return &types.Credentials{
		Protocol: "Kerberos",
		Source: types.Source{
			IP:   packet.SrcIP.String(),
			Port: packet.SrcPort,
		},
		Destination: types.Source{
			IP:   packet.DstIP.String(),
			Port: packet.DstPort,
		},
		Data: map[string]string{
			"hash":     kerberosHash,
			"username": name,
			"domain":   domain,
		},
	}, nil
}

func (p *KerberosParser) extractNameDomain(data []byte) (string, string) {
	if len(data) < 4 {
		return "", ""
	}

	nameLen := int(data[0])
	if len(data) < nameLen+4 {
		return "", ""
	}
	name := string(data[1 : nameLen+1])

	domainOffset := nameLen + 4
	if len(data) < domainOffset+1 {
		return "", ""
	}
	domainLen := int(data[domainOffset])
	if len(data) < domainOffset+domainLen+1 {
		return "", ""
	}
	domain := string(data[domainOffset+1 : domainOffset+domainLen+1])

	return name, domain
}
