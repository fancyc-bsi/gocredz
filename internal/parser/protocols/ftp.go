package protocols

import (
	"fmt"
	"gnc/pkg/types"
	"regexp"
	"strings"
	"sync"
)

type FTPParser struct {
	userRegex *regexp.Regexp
	passRegex *regexp.Regexp
	sessions  map[string]*types.Credentials
	mu        sync.Mutex
}

func NewFTPParser() *FTPParser {
	return &FTPParser{
		userRegex: regexp.MustCompile(`(?i)USER\s+([^\r\n]+)`),
		passRegex: regexp.MustCompile(`(?i)PASS\s+([^\r\n]+)`),
		sessions:  make(map[string]*types.Credentials),
	}
}

func (p *FTPParser) Protocol() string {
	return "FTP"
}

func (p *FTPParser) Parse(packet *types.Packet) (*types.Credentials, error) {
	if packet == nil || len(packet.Data) == 0 {
		return nil, nil
	}

	if packet.Destination.Port != 21 && packet.Source.Port != 21 {
		return nil, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	sessionKey := fmt.Sprintf("%s:%d-%s:%d", 
		packet.Source.IP, packet.Source.Port,
		packet.Destination.IP, packet.Destination.Port)
		
	data := string(packet.Data)

	creds, exists := p.sessions[sessionKey]
	if !exists {
		creds = &types.Credentials{
			Protocol:    "FTP",
			Source:      packet.Source,
			Destination: packet.Destination,
			Data:        make(map[string]string),
		}
		p.sessions[sessionKey] = creds
	}

	if userMatches := p.userRegex.FindStringSubmatch(data); len(userMatches) > 1 {
		creds.Data["username"] = strings.TrimSpace(userMatches[1])
	}
	if passMatches := p.passRegex.FindStringSubmatch(data); len(passMatches) > 1 {
		creds.Data["password"] = strings.TrimSpace(passMatches[1])
	}

	if creds.Data["username"] != "" && creds.Data["password"] != "" {
		delete(p.sessions, sessionKey)
		return creds, nil
	}

	return nil, nil
}