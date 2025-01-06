package protocols

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"gnc/pkg/types"
	"sync"
)

type NTLMParser struct {
	challenges sync.Map
}

func NewNTLMParser() *NTLMParser {
	return &NTLMParser{}
}

func (p *NTLMParser) Protocol() string {
	return "NTLM"
}

func (p *NTLMParser) Parse(packet *types.Packet) (*types.Credentials, error) {
	if packet == nil || len(packet.Data) < 12 {
		return nil, nil
	}

	// Search for NTLM signatures anywhere in the packet
	data := packet.Data
	var ntlmMessages [][]byte

	// Look for all NTLM messages in the packet
	offset := 0
	for {
		idx := bytes.Index(data[offset:], []byte("NTLMSSP\x00"))
		if idx == -1 {
			break
		}
		messageStart := offset + idx
		if messageStart+12 <= len(data) {
			ntlmMessages = append(ntlmMessages, data[messageStart:])
		}
		offset = messageStart + 8
	}

	// Process all NTLM messages found
	for _, msgData := range ntlmMessages {
		if len(msgData) < 12 {
			continue
		}

		msgType := binary.LittleEndian.Uint32(msgData[8:12])
		var creds *types.Credentials
		var err error

		switch msgType {
		case 2: // Challenge
			creds, err = p.handleChallenge(packet, msgData)
		case 3: // Authenticate
			creds, err = p.handleAuth(packet, msgData)
		}

		if err != nil {
			continue
		}
		if creds != nil {
			return creds, nil
		}
	}

	return nil, nil
}

func (p *NTLMParser) handleChallenge(packet *types.Packet, data []byte) (*types.Credentials, error) {
	if len(data) < 32 {
		return nil, nil
	}

	challenge := data[24:32]

	// Generate multiple possible session keys
	sessionKeys := p.generateSessionKeys(packet)

	// Store challenge under all possible session key combinations
	for _, key := range sessionKeys {
		p.challenges.Store(key, challenge)
	}

	return nil, nil
}

func (p *NTLMParser) handleAuth(packet *types.Packet, data []byte) (*types.Credentials, error) {
	if len(data) < 64 {
		return nil, nil
	}

	// Extract lengths and offsets
	lmHashLen := binary.LittleEndian.Uint16(data[14:16])
	lmHashOffset := binary.LittleEndian.Uint16(data[16:18])
	ntHashLen := binary.LittleEndian.Uint16(data[22:24])
	ntHashOffset := binary.LittleEndian.Uint16(data[24:26])
	domainLen := binary.LittleEndian.Uint16(data[30:32])
	domainOffset := binary.LittleEndian.Uint16(data[32:34])
	userLen := binary.LittleEndian.Uint16(data[38:40])
	userOffset := binary.LittleEndian.Uint16(data[40:42])

	if !p.validateOffsets(data, lmHashOffset, lmHashLen, ntHashOffset, ntHashLen,
		domainOffset, domainLen, userOffset, userLen) {
		return nil, nil
	}

	// Extract fields
	lmHash := data[lmHashOffset : lmHashOffset+lmHashLen]
	ntHash := data[ntHashOffset : ntHashOffset+ntHashLen]
	domain := bytes.Replace(data[domainOffset:domainOffset+domainLen], []byte{0x00}, []byte{}, -1)
	username := bytes.Replace(data[userOffset:userOffset+userLen], []byte{0x00}, []byte{}, -1)

	// Try all possible session key combinations
	var challenge []byte
	sessionKeys := p.generateSessionKeys(packet)

	for _, key := range sessionKeys {
		if challengeI, ok := p.challenges.Load(key); ok {
			challenge = challengeI.([]byte)
			// Cleanup stored challenge
			p.challenges.Delete(key)
			break
		}
	}

	if challenge == nil {
		return nil, nil
	}

	creds := &types.Credentials{
		Protocol:    "NTLM",
		Source:      packet.Source,
		Destination: packet.Destination,
		Data:        make(map[string]string),
	}

	// Format based on hash length (NTLMv1 vs NTLMv2)
	if ntHashLen == 24 {
		creds.Data["type"] = "NTLMv1"
		creds.Data["hash"] = fmt.Sprintf("%s::%s:%s:%s:%s",
			string(username),
			string(domain),
			hex.EncodeToString(lmHash),
			hex.EncodeToString(ntHash),
			hex.EncodeToString(challenge))
	} else if ntHashLen > 60 {
		creds.Data["type"] = "NTLMv2"
		creds.Data["hash"] = fmt.Sprintf("%s::%s:%s:%s:%s",
			string(username),
			string(domain),
			hex.EncodeToString(challenge),
			hex.EncodeToString(ntHash[:16]),
			hex.EncodeToString(ntHash[16:]))
	}

	return creds, nil
}

func (p *NTLMParser) generateSessionKeys(packet *types.Packet) []string {
	// Generate all possible session key combinations
	keys := make([]string, 0, 4)

	// Standard format: src:srcport-dst:dstport
	keys = append(keys, fmt.Sprintf("%s:%d-%s:%d",
		packet.Source.IP, packet.Source.Port,
		packet.Destination.IP, packet.Destination.Port))

	// Reverse format: dst:dstport-src:srcport
	keys = append(keys, fmt.Sprintf("%s:%d-%s:%d",
		packet.Destination.IP, packet.Destination.Port,
		packet.Source.IP, packet.Source.Port))

	// Without ports
	keys = append(keys, fmt.Sprintf("%s-%s",
		packet.Source.IP, packet.Destination.IP))
	keys = append(keys, fmt.Sprintf("%s-%s",
		packet.Destination.IP, packet.Source.IP))

	return keys
}

func (p *NTLMParser) validateOffsets(data []byte, offsets ...uint16) bool {
	dataLen := len(data)
	for i := 0; i < len(offsets); i += 2 {
		offset := offsets[i]
		length := offsets[i+1]
		if offset == 0 || int(offset)+int(length) > dataLen {
			return false
		}
	}
	return true
}
