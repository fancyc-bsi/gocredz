package protocols

import (
    "bytes"
    "encoding/binary"
    "gnc/pkg/types"
	"fmt"
	"encoding/hex"
)

type NTLMParser struct {
    // Map to store NTLM challenges using session key (src:port-dst:port)
    challenges map[string][]byte  
}

func NewNTLMParser() *NTLMParser {
    return &NTLMParser{
        challenges: make(map[string][]byte),
    }
}

func (p *NTLMParser) Protocol() string {
    return "NTLM"
}

func (p *NTLMParser) Parse(packet *types.Packet) (*types.Credentials, error) {
    if packet == nil || len(packet.Data) < 12 {
        return nil, nil
    }

    data := packet.Data
    if !bytes.Contains(data, []byte("NTLMSSP\x00")) {
        return nil, nil
    }

    msgType := binary.LittleEndian.Uint32(data[8:12])
    switch msgType {
    case 1: // Negotiate
        return nil, nil
    case 2: // Challenge
        return p.handleChallenge(packet)
    case 3: // Authenticate
        return p.handleAuth(packet)
    }

    return nil, nil
}

func (p *NTLMParser) handleChallenge(packet *types.Packet) (*types.Credentials, error) {
    // Store challenge for future auth
    data := packet.Data
    challengeStart := bytes.Index(data, []byte("NTLMSSP\x00\x02\x00\x00\x00"))
    if challengeStart == -1 || len(data[challengeStart:]) < 32 {
        return nil, nil
    }

    sessionKey := fmt.Sprintf("%s:%d-%s:%d", 
        packet.Source.IP, packet.Source.Port,
        packet.Destination.IP, packet.Destination.Port)
    
    p.challenges[sessionKey] = data[challengeStart+24 : challengeStart+32]
    return nil, nil
}

func (p *NTLMParser) handleAuth(packet *types.Packet) (*types.Credentials, error) {
    data := packet.Data
    authStart := bytes.Index(data, []byte("NTLMSSP\x00\x03\x00\x00\x00"))
    if authStart == -1 || len(data[authStart:]) < 64 {
        return nil, nil
    }

    msg := data[authStart:]
    
    // Extract field lengths and offsets
    lmLen := binary.LittleEndian.Uint16(msg[12:14])
    lmOffset := binary.LittleEndian.Uint32(msg[16:20])
    ntLen := binary.LittleEndian.Uint16(msg[20:22])
    ntOffset := binary.LittleEndian.Uint32(msg[24:28])
    domainLen := binary.LittleEndian.Uint16(msg[28:30])
    domainOffset := binary.LittleEndian.Uint32(msg[32:36])
    userLen := binary.LittleEndian.Uint16(msg[36:38])
    userOffset := binary.LittleEndian.Uint32(msg[40:44])

    // Validate offsets and lengths
    msgLen := len(msg)
    if !p.validateOffset(lmOffset, lmLen, msgLen) ||
       !p.validateOffset(ntOffset, ntLen, msgLen) ||
       !p.validateOffset(domainOffset, domainLen, msgLen) ||
       !p.validateOffset(userOffset, userLen, msgLen) {
        return nil, nil
    }

    // Get associated challenge
    sessionKey := fmt.Sprintf("%s:%d-%s:%d",
        packet.Destination.IP, packet.Destination.Port,
        packet.Source.IP, packet.Source.Port)
    challenge, exists := p.challenges[sessionKey]
    
    creds := &types.Credentials{
        Protocol:    "NTLM",
        Source:      packet.Source,
        Destination: packet.Destination,
        Data: map[string]string{
            "domain": string(bytes.TrimRight(msg[domainOffset:domainOffset+uint32(domainLen)], "\x00")),
            "user":   string(bytes.TrimRight(msg[userOffset:userOffset+uint32(userLen)], "\x00")),
            "lmhash": hex.EncodeToString(msg[lmOffset:lmOffset+uint32(lmLen)]),
            "nthash": hex.EncodeToString(msg[ntOffset:ntOffset+uint32(ntLen)]),
        },
    }

    if exists {
        creds.Data["challenge"] = hex.EncodeToString(challenge)
        delete(p.challenges, sessionKey)
    }

    return creds, nil
}

func (p *NTLMParser) validateOffset(offset uint32, length uint16, msgLen int) bool {
    return offset > 0 && int(offset)+int(length) <= msgLen
}