package protocols

import (
	"gnc/pkg/types"
	"regexp"
	"strings"
)

type SMTPParser struct {
	authPlainRegex *regexp.Regexp
	authLoginRegex *regexp.Regexp
	base64Regex    *regexp.Regexp
}

func NewSMTPParser() *SMTPParser {
	return &SMTPParser{
		authPlainRegex: regexp.MustCompile(`(?i)AUTH PLAIN\s+([^\r\n]+)`),
		authLoginRegex: regexp.MustCompile(`(?i)AUTH LOGIN\s*\r\n([^\r\n]+)\r\n([^\r\n]+)`),
		base64Regex:    regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`),
	}
}

func (p *SMTPParser) Protocol() string {
	return "SMTP"
}

func (p *SMTPParser) Parse(packet *types.Packet) (*types.Credentials, error) {
	if packet == nil || len(packet.Data) == 0 {
		return nil, nil
	}

	// Check if it's SMTP traffic (port 25, 587, or 465)
	if packet.Destination.Port != 25 && packet.Destination.Port != 587 &&
		packet.Destination.Port != 465 && packet.Source.Port != 25 &&
		packet.Source.Port != 587 && packet.Source.Port != 465 {
		return nil, nil
	}

	data := string(packet.Data)

	// Check for AUTH PLAIN
	if plainMatches := p.authPlainRegex.FindStringSubmatch(data); len(plainMatches) > 1 {
		return &types.Credentials{
			Protocol:    "SMTP",
			Source:      packet.Source,
			Destination: packet.Destination,
			Data: map[string]string{
				"auth_type": "PLAIN",
				"auth_data": strings.TrimSpace(plainMatches[1]),
			},
		}, nil
	}

	// Check for AUTH LOGIN
	if loginMatches := p.authLoginRegex.FindStringSubmatch(data); len(loginMatches) > 2 {
		return &types.Credentials{
			Protocol:    "SMTP",
			Source:      packet.Source,
			Destination: packet.Destination,
			Data: map[string]string{
				"auth_type": "LOGIN",
				"username":  strings.TrimSpace(loginMatches[1]),
				"password":  strings.TrimSpace(loginMatches[2]),
			},
		}, nil
	}

	return nil, nil
}
