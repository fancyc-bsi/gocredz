package protocols

import (
    "encoding/binary"
    "gnc/pkg/types"
	"net"
)

type LLMNRParser struct{}

func NewLLMNRParser() *LLMNRParser {
    return &LLMNRParser{}
}

func (p *LLMNRParser) Protocol() string {
    return "LLMNR"
}

func (p *LLMNRParser) Parse(packet *types.Packet) (*types.Credentials, error) {
	if packet == nil || len(packet.Data) < 12 {
		return nil, nil
	}
 
	// Check LLMNR port
	if packet.Destination.Port != 5355 && packet.Source.Port != 5355 {
		return nil, nil  
	}
 
	flags := binary.BigEndian.Uint16(packet.Data[2:4])
	msgType := "query"
	if (flags & 0x8000) != 0 {
		msgType = "response" 
	}
 
	name := p.extractQuery(packet.Data)
	
	creds := &types.Credentials{
		Protocol: "LLMNR",
		Source: packet.Source,
		Destination: packet.Destination,
		Data: map[string]string{
			"type": msgType,
			"name": name,
		},
	}
 
	// Extract answer if response
	if msgType == "response" {
		answers := p.extractAnswers(packet.Data) 
		if answers != "" {
			creds.Data["answers"] = answers
		}
	}
 
	return creds, nil
 }

func (p *LLMNRParser) extractQuery(data []byte) string {
    if len(data) < 13 {
        return ""
    }

    var name []byte
    pos := 12 // Skip header

    // Read name labels
    for pos < len(data) {
        length := int(data[pos])
        if length == 0 {
            break
        }
        
        pos++
        if pos+length > len(data) {
            break
        }
        
        if len(name) > 0 {
            name = append(name, '.')
        }
        name = append(name, data[pos:pos+length]...)
        pos += length
    }

    return string(name)
}

func (p *LLMNRParser) extractAnswers(data []byte) string {
    if len(data) < 12 {
        return ""
    }

    numQuestions := binary.BigEndian.Uint16(data[4:6])
    pos := 12

    // Skip questions section
    for i := uint16(0); i < numQuestions; i++ {
        // Skip name
        for pos < len(data) {
            if data[pos] == 0 {
                pos++
                break
            }
            pos++
        }
        pos += 4 // Skip QTYPE and QCLASS
    }

    // Skip name in answer section
    for pos < len(data) {
        if data[pos] == 0 {
            pos++
            break
        }
        pos++
    }

    // Skip TYPE, CLASS, TTL
    pos += 8
    
    // Read RDLENGTH
    if pos+2 > len(data) {
        return ""
    }
    rdLength := binary.BigEndian.Uint16(data[pos:pos+2])
    pos += 2

    // Read IP address
    if rdLength == 4 && pos+4 <= len(data) {
        return net.IP(data[pos:pos+4]).String()
    }

    return ""
}