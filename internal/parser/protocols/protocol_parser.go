// internal/parser/protocols/protocol_parser.go

package protocols

import (
	"fmt"
	"gnc/pkg/types"
	"regexp"
)

// ProtocolParser defines the interface that all protocol parsers must implement
type ProtocolParser interface {
	// Protocol returns the name of the protocol this parser handles
	Protocol() string

	// Parse attempts to extract credentials from a packet
	// Returns nil, nil if no credentials are found
	Parse(packet *types.Packet) (*types.Credentials, error)
}

// BaseProtocolParser provides common functionality for protocol parsers
type BaseProtocolParser struct {
	name     string
	patterns map[string]*regexp.Regexp
}

// NewBaseProtocolParser creates a new base parser with compiled regex patterns
func NewBaseProtocolParser(name string, patterns map[string]string) (*BaseProtocolParser, error) {
	compiledPatterns := make(map[string]*regexp.Regexp)

	for key, pattern := range patterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile pattern %s: %v", key, err)
		}
		compiledPatterns[key] = regex
	}

	return &BaseProtocolParser{
		name:     name,
		patterns: compiledPatterns,
	}, nil
}

// Protocol implements ProtocolParser interface
func (b *BaseProtocolParser) Protocol() string {
	return b.name
}

// GetPattern returns a compiled regex pattern by name
func (b *BaseProtocolParser) GetPattern(name string) *regexp.Regexp {
	return b.patterns[name]
}
