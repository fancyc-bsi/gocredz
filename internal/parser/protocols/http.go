package protocols

import (
	"fmt"
	"gnc/pkg/types"
	"regexp"
	"strings"
)

type HTTPParser struct {
	// Precompiled regex patterns
	methodRegex    *regexp.Regexp
	hostRegex      *regexp.Regexp
	basicAuthRegex *regexp.Regexp
	negotiateRegex *regexp.Regexp
	ntlmRegex      *regexp.Regexp
	ctxRegex       *regexp.Regexp
	usernameFields []string
	passwordFields []string
}

func NewHTTPParser() *HTTPParser {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	methodPattern := fmt.Sprintf("(%s)", strings.Join(methods, "|"))

	parser := &HTTPParser{
		methodRegex:    regexp.MustCompile(fmt.Sprintf("(?m)^(%s [^\n]+)", methodPattern)),
		hostRegex:      regexp.MustCompile("(?m)^Host: ([^\n]+)"),
		basicAuthRegex: regexp.MustCompile("Authorization: Basic ([^\n]+)"),
		negotiateRegex: regexp.MustCompile("(?:Authorization: Negotiate |WWW-Authenticate: Negotiate )([^\r\n]+)"),
		ntlmRegex:      regexp.MustCompile("(?:Authorization: NTLM |WWW-Authenticate: NTLM )([^\r\n]+)"),
		ctxRegex:       regexp.MustCompile("<Username>(.*?)</Username><Password encoding=\"ctx1\">(.*?)</Password>"),
		usernameFields: []string{
			"log", "login", "wpname", "ahd_username", "unickname", "nickname", "user",
			"user_name", "alias", "pseudo", "email", "username", "_username", "userid",
			"form_loginname", "loginname", "login_id", "loginid", "session_key",
			"sessionkey", "pop_login", "uid", "id", "user_id", "screename", "uname",
			"ulogin", "acctname", "account", "member", "mailaddress", "membername",
			"login_username", "login_email", "loginusername", "loginemail", "uin",
			"sign-in", "j_username",
		},
		passwordFields: []string{
			"ahd_password", "pass", "password", "_password", "passwd", "session_password",
			"sessionpassword", "login_password", "loginpassword", "form_pw", "pw",
			"userpassword", "pwd", "upassword", "login_password", "passwort", "passwrd",
			"wppassword", "upasswd", "j_password",
		},
	}
	return parser
}

func (p *HTTPParser) Protocol() string {
	return "http"
}

func (p *HTTPParser) Parse(packet *types.Packet) (*types.Credentials, error) {
	if packet == nil || len(packet.Data) < 8 {
		return nil, nil
	}

	data := string(packet.Data)

	// Extract method and host
	method := p.methodRegex.FindString(data)
	host := p.hostRegex.FindString(data)

	// Check for form-based authentication
	if creds := p.parseFormAuth(data, method, host, packet); creds != nil {
		return creds, nil
	}

	// Check for Basic authentication
	if creds := p.parseBasicAuth(data, method, host, packet); creds != nil {
		return creds, nil
	}

	// Check for Negotiate authentication
	if creds := p.parseNegotiateAuth(data, method, host, packet); creds != nil {
		return creds, nil
	}

	// Check for NTLM authentication
	if creds := p.parseNTLMAuth(data, method, host, packet); creds != nil {
		return creds, nil
	}

	// Check for CTX authentication
	if creds := p.parseCTXAuth(data, method, host, packet); creds != nil {
		return creds, nil
	}

	return nil, nil
}

func (p *HTTPParser) parseFormAuth(data, method, host string, packet *types.Packet) *types.Credentials {
	// Only process POST requests
	if !strings.HasPrefix(strings.ToUpper(method), "POST") {
		return nil
	}

	// Split headers and body correctly
	parts := strings.Split(data, "\r\n\r\n")
	if len(parts) < 2 {
		// Try alternative line endings
		parts = strings.Split(data, "\n\n")
		if len(parts) < 2 {
			return nil
		}
	}

	// Extract body and trim any whitespace
	body := strings.TrimSpace(parts[1])

	// Verify content type
	if !strings.Contains(parts[0], "application/x-www-form-urlencoded") {
		return nil
	}

	// Parse form data
	formValues := make(map[string]string)
	pairs := strings.Split(body, "&")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			formValues[kv[0]] = kv[1]
		}
	}

	var userFields []string
	var passFields []string

	// Look for username fields
	for _, field := range p.usernameFields {
		if val, ok := formValues[field]; ok {
			userFields = append(userFields, fmt.Sprintf("%s=%s", field, val))
		}
	}

	// Look for password fields
	for _, field := range p.passwordFields {
		if val, ok := formValues[field]; ok {
			passFields = append(passFields, fmt.Sprintf("%s=%s", field, val))
		}
	}

	// Return credentials if we found any
	if len(userFields) > 0 || len(passFields) > 0 {
		return &types.Credentials{
			Protocol: "HTTP-Form",
			Source: types.Source{
				IP:   packet.Source.IP,
				Port: packet.Source.Port,
			},
			Destination: types.Source{
				IP:   packet.Destination.IP,
				Port: packet.Destination.Port,
			},
			Data: map[string]string{
				"method":    strings.TrimSpace(method),
				"host":      strings.TrimSpace(strings.TrimPrefix(host, "Host: ")),
				"usernames": strings.Join(userFields, "&"),
				"passwords": strings.Join(passFields, "&"),
				"raw_body":  body, // For debugging
			},
		}
	}

	return nil
}

func (p *HTTPParser) parseBasicAuth(data, method, host string, packet *types.Packet) *types.Credentials {
	matches := p.basicAuthRegex.FindStringSubmatch(data)
	if len(matches) > 1 {
		return &types.Credentials{
			Protocol: "HTTP-Basic",
			Source: types.Source{
				IP:   packet.Source.IP,
				Port: packet.Source.Port,
			},
			Destination: types.Source{
				IP:   packet.Destination.IP,
				Port: packet.Destination.Port,
			},
			Data: map[string]string{
				"method":    strings.TrimSpace(method),
				"host":      strings.TrimSpace(strings.TrimPrefix(host, "Host: ")),
				"auth_data": matches[1],
			},
		}
	}
	return nil
}

func (p *HTTPParser) parseNegotiateAuth(data, method, host string, packet *types.Packet) *types.Credentials {
	matches := p.negotiateRegex.FindStringSubmatch(data)
	if len(matches) > 1 {
		return &types.Credentials{
			Protocol: "HTTP-Negotiate",
			Source: types.Source{
				IP:   packet.Source.IP,
				Port: packet.Source.Port,
			},
			Destination: types.Source{
				IP:   packet.Destination.IP,
				Port: packet.Destination.Port,
			},
			Data: map[string]string{
				"method":    strings.TrimSpace(method),
				"host":      strings.TrimSpace(strings.TrimPrefix(host, "Host: ")),
				"auth_data": matches[1],
			},
		}
	}
	return nil
}

func (p *HTTPParser) parseNTLMAuth(data, method, host string, packet *types.Packet) *types.Credentials {
	matches := p.ntlmRegex.FindStringSubmatch(data)
	if len(matches) > 1 {
		return &types.Credentials{
			Protocol: "HTTP-NTLM",
			Source: types.Source{
				IP:   packet.Source.IP,
				Port: packet.Source.Port,
			},
			Destination: types.Source{
				IP:   packet.Destination.IP,
				Port: packet.Destination.Port,
			},
			Data: map[string]string{
				"method":    strings.TrimSpace(method),
				"host":      strings.TrimSpace(strings.TrimPrefix(host, "Host: ")),
				"auth_data": matches[1],
			},
		}
	}
	return nil
}

func (p *HTTPParser) parseCTXAuth(data, method, host string, packet *types.Packet) *types.Credentials {
	matches := p.ctxRegex.FindStringSubmatch(data)
	if len(matches) > 2 {
		return &types.Credentials{
			Protocol: "HTTP-CTX",
			Source: types.Source{
				IP:   packet.Source.IP,
				Port: packet.Source.Port,
			},
			Destination: types.Source{
				IP:   packet.Destination.IP,
				Port: packet.Destination.Port,
			},
			Data: map[string]string{
				"method":   strings.TrimSpace(method),
				"host":     strings.TrimSpace(strings.TrimPrefix(host, "Host: ")),
				"username": matches[1],
				"password": matches[2],
			},
		}
	}
	return nil
}
