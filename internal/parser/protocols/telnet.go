package protocols

import (
	"bytes"
	"fmt"
	"gnc/pkg/types"
	"strings"
	"sync"
	"time"
)

type TelnetParser struct {
	sessions map[string]*TelnetSession
	mu       sync.RWMutex
	// log      *logger.Logger
}

type TelnetSession struct {
	State       string
	Username    string
	Password    string
	LastUpdated time.Time
	Buffer      bytes.Buffer
}

func NewTelnetParser() ProtocolParser {
	return &TelnetParser{
		sessions: make(map[string]*TelnetSession),
	}
}

func (p *TelnetParser) Protocol() string {
	return "telnet"
}

func (p *TelnetParser) Parse(packet *types.Packet) (*types.Credentials, error) {
	if packet == nil || len(packet.Data) == 0 {
		return nil, nil
	}

	// Client is always the non-23 port end
	var sessionID string
	if packet.SrcPort == 23 {
		// From server to client
		sessionID = fmt.Sprintf("%s:%d", packet.Destination.IP, packet.Destination.Port)
	} else if packet.DstPort == 23 {
		// From client to server
		sessionID = fmt.Sprintf("%s:%d", packet.Source.IP, packet.Source.Port)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	session, exists := p.sessions[sessionID]
	if !exists {
		session = &TelnetSession{
			State:       "initial",
			LastUpdated: time.Now(),
		}
		p.sessions[sessionID] = session
	}

	session.LastUpdated = time.Now()

	// Check for "Password: " and switch state
	if strings.Contains(string(packet.Data), "Password:") {
		session.State = "collecting_password"
		session.Buffer.Reset()
		p.sessions[sessionID] = session
		return nil, nil
	}

	// Process based on state
	if session.State == "collecting_password" {
		if len(packet.Data) > 0 {
			if packet.Data[0] != '\r' && packet.Data[0] != '\n' {
				// Accumulate password characters
				session.Password += string(packet.Data)
				p.sessions[sessionID] = session
			} else if session.Password != "" {
				// We have a complete password and hit a carriage return
				if session.Username != "" {
					credentials := &types.Credentials{
						Protocol:    "Telnet",
						Source:      packet.Source,
						Destination: packet.Destination,
						Timestamp:   time.Now(),
						Data: map[string]string{
							"username": session.Username,
							"password": session.Password,
						},
					}
					delete(p.sessions, sessionID)
					return credentials, nil
				}
			}
		}
		return nil, nil
	}

	// Handle username collection in initial state
	session.Buffer.Write(packet.Data)

	if bytes.Contains(packet.Data, []byte{'\r'}) || bytes.Contains(packet.Data, []byte{'\n'}) {
		bufferContent := session.Buffer.String()
		lines := strings.Split(bufferContent, "\n")

		for _, line := range lines {
			line = strings.TrimSpace(strings.ReplaceAll(line, "\r", ""))
			if strings.Contains(line, "login:") {
				// Extract the username only if it hasn't been set
				if session.Username == "" {
					parts := strings.SplitN(line, "login:", 2)
					if len(parts) == 2 {
						session.Username = strings.TrimSpace(parts[1])
					}
				}
			}
		}

		session.Buffer.Reset()
		p.sessions[sessionID] = session
	}

	return nil, nil
}

func (p *TelnetParser) Cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute)
	for id, session := range p.sessions {
		if session.LastUpdated.Before(cutoff) {
			delete(p.sessions, id)
		}
	}
}
