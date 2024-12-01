package protocols_test

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"gnc/internal/logger"
	"gnc/internal/parser/protocols"
	"gnc/pkg/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResults stores the results of credential captures
type TestResults struct {
	Protocol    string
	Source      string
	Destination string
	Credentials map[string]string
}

func TestParsers(t *testing.T) {
	var capturedCredentials []TestResults

	log, err := logger.New(1, true)
	require.NoError(t, err)
	require.NotNil(t, log)

	t.Run("HTTP Parser Tests", func(t *testing.T) {
		parser := protocols.NewHTTPParser()
		require.NotNil(t, parser, "HTTP Parser should not be nil")

		tests := []struct {
			name     string
			data     []byte
			dstPort  uint16
			expected *types.Credentials
		}{
			{
				name:    "Form Auth - POST credentials",
				dstPort: 80,
				data: []byte(`POST /labs/a0x01.php HTTP/1.1
Host: 192.168.2.163
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 32

username=jeremy&password=letmein`),
				expected: &types.Credentials{
					Protocol: "HTTP-Form",
					Data: map[string]string{
						"method":    "POST /labs/a0x01.php HTTP/1.1",
						"host":      "192.168.2.163",
						"usernames": "username=jeremy",
						"passwords": "password=letmein",
					},
				},
			},
			{
				name:    "Basic Auth",
				dstPort: 80,
				data: []byte(`GET /private HTTP/1.1
Host: example.com
Authorization: Basic YWRtaW46cGFzc3dvcmQ=`),
				expected: &types.Credentials{
					Protocol: "HTTP-Basic",
					Data: map[string]string{
						"method":    "GET /private HTTP/1.1",
						"host":      "example.com",
						"auth_data": "YWRtaW46cGFzc3dvcmQ=",
					},
				},
			},
			{
				name:    "NTLM Auth",
				dstPort: 80,
				data: []byte(`GET /secure HTTP/1.1
Host: example.com
Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==`),
				expected: &types.Credentials{
					Protocol: "HTTP-NTLM",
					Data: map[string]string{
						"method":    "GET /secure HTTP/1.1",
						"host":      "example.com",
						"auth_data": "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==",
					},
				},
			},
			{
				name:    "Negotiate Auth",
				dstPort: 80,
				data: []byte(`GET /secure HTTP/1.1
Host: example.com
Authorization: Negotiate YIIKXgYGKwYBBQUCoIIKUjCCCk6gJDAiBgkqhkiC9xIBAgIGCSqGSIb3`),
				expected: &types.Credentials{
					Protocol: "HTTP-Negotiate",
					Data: map[string]string{
						"method":    "GET /secure HTTP/1.1",
						"host":      "example.com",
						"auth_data": "YIIKXgYGKwYBBQUCoIIKUjCCCk6gJDAiBgkqhkiC9xIBAgIGCSqGSIb3",
					},
				},
			},
			{
				name:    "Invalid Form Data",
				dstPort: 80,
				data: []byte(`POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 12

invalid_data`),
				expected: nil,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				packet := createTestPacket(tt.data, tt.dstPort)
				creds, err := parser.Parse(packet)
				assert.NoError(t, err)

				if tt.expected == nil {
					assert.Nil(t, creds)
					return
				}

				require.NotNil(t, creds)
				assert.Equal(t, tt.expected.Protocol, creds.Protocol)
				for key, expectedValue := range tt.expected.Data {
					assert.Equal(t, expectedValue, creds.Data[key], "Mismatch in field: %s", key)
				}

				if creds != nil {
					capturedCredentials = append(capturedCredentials, TestResults{
						Protocol:    creds.Protocol,
						Source:      fmt.Sprintf("%s:%d", packet.Source.IP, packet.Source.Port),
						Destination: fmt.Sprintf("%s:%d", packet.Destination.IP, packet.Destination.Port),
						Credentials: creds.Data,
					})
				}
			})
		}
	})

	t.Run("FTP Parser Tests", func(t *testing.T) {
		parser := protocols.NewFTPParser()
		require.NotNil(t, parser, "FTP Parser should not be nil")

		tests := []struct {
			name     string
			data     []byte
			expected map[string]string
		}{
			{
				name: "Valid FTP Auth",
				data: []byte("USER admin\r\nPASS secret123\r\n"),
				expected: map[string]string{
					"username": "admin",
					"password": "secret123",
				},
			},
			{
				name: "Anonymous FTP",
				data: []byte("USER anonymous\r\nPASS email@example.com\r\n"),
				expected: map[string]string{
					"username": "anonymous",
					"password": "email@example.com",
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				packet := createTestPacket(tt.data, 21)
				creds, err := parser.Parse(packet)

				assert.NoError(t, err)
				require.NotNil(t, creds)
				assert.Equal(t, "FTP", creds.Protocol)
				for key, expectedValue := range tt.expected {
					assert.Equal(t, expectedValue, creds.Data[key])
				}

				if creds != nil {
					capturedCredentials = append(capturedCredentials, TestResults{
						Protocol:    creds.Protocol,
						Source:      fmt.Sprintf("%s:%d", packet.Source.IP, packet.Source.Port),
						Destination: fmt.Sprintf("%s:%d", packet.Destination.IP, packet.Destination.Port),
						Credentials: creds.Data,
					})
				}
			})
		}
	})

	t.Run("SMTP Parser Tests", func(t *testing.T) {
		parser := protocols.NewSMTPParser()
		require.NotNil(t, parser, "SMTP Parser should not be nil")

		tests := []struct {
			name     string
			data     []byte
			expected map[string]string
		}{
			{
				name: "PLAIN Auth",
				data: []byte("AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk\r\n"),
				expected: map[string]string{
					"auth_type": "PLAIN",
					"auth_data": "AHVzZXJuYW1lAHBhc3N3b3Jk",
				},
			},
			{
				name: "LOGIN Auth",
				data: []byte("AUTH LOGIN\r\nVXNlcm5hbWU=\r\nUGFzc3dvcmQ=\r\n"),
				expected: map[string]string{
					"auth_type": "LOGIN",
					"username":  "VXNlcm5hbWU=",
					"password":  "UGFzc3dvcmQ=",
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				packet := createTestPacket(tt.data, 25)
				creds, err := parser.Parse(packet)

				assert.NoError(t, err)
				require.NotNil(t, creds)
				assert.Equal(t, "SMTP", creds.Protocol)
				for key, expectedValue := range tt.expected {
					assert.Equal(t, expectedValue, creds.Data[key])
				}

				if creds != nil {
					capturedCredentials = append(capturedCredentials, TestResults{
						Protocol:    creds.Protocol,
						Source:      fmt.Sprintf("%s:%d", packet.Source.IP, packet.Source.Port),
						Destination: fmt.Sprintf("%s:%d", packet.Destination.IP, packet.Destination.Port),
						Credentials: creds.Data,
					})
				}
			})
		}
	})

	t.Run("SNMP Parser Tests", func(t *testing.T) {
		parser := protocols.NewSNMPParser()
		require.NotNil(t, parser, "SNMP Parser should not be nil")

		tests := []struct {
			name     string
			data     []byte
			dstPort  uint16
			expected map[string]string
		}{
			{
				name:    "SNMPv1 Community String",
				dstPort: 161,
				data: []byte{
					0x30, 0x1A, // Sequence tag and length
					0x02, 0x01, 0x00, // Version 1 (0)
					0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // Community string ("public")
					0xa0, 0x0D, // GetRequest PDU
					0x02, 0x01, 0x01, // Request ID
					0x02, 0x01, 0x00, // Error status
					0x02, 0x01, 0x00, // Error index
					0x30, 0x00, // Variable bindings
				},
				expected: map[string]string{
					"version":   "v1",
					"community": "public",
				},
			},
			{
				name:    "SNMPv2c Community String",
				dstPort: 161,
				data: []byte{
					0x30, 0x1B, // Sequence tag and length
					0x02, 0x01, 0x01, // Version 2c (1)
					0x04, 0x07, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, // Community string ("private")
					0xa0, 0x0D, // GetRequest PDU
					0x02, 0x01, 0x01, // Request ID
					0x02, 0x01, 0x00, // Error status
					0x02, 0x01, 0x00, // Error index
					0x30, 0x00, // Variable bindings
				},
				expected: map[string]string{
					"version":   "v2c",
					"community": "private",
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				packet := createTestPacket(tt.data, tt.dstPort)
				creds, err := parser.Parse(packet)

				assert.NoError(t, err)
				require.NotNil(t, creds)
				assert.Equal(t, "SNMP", creds.Protocol)
				for key, expectedValue := range tt.expected {
					assert.Equal(t, expectedValue, creds.Data[key])
				}

				if creds != nil {
					capturedCredentials = append(capturedCredentials, TestResults{
						Protocol:    creds.Protocol,
						Source:      fmt.Sprintf("%s:%d", packet.Source.IP, packet.Source.Port),
						Destination: fmt.Sprintf("%s:%d", packet.Destination.IP, packet.Destination.Port),
						Credentials: creds.Data,
					})
				}
			})
		}
	})

	t.Run("NTLM Parser Tests", func(t *testing.T) {
		parser := protocols.NewNTLMParser()
		require.NotNil(t, parser)

		challengeMsg := make([]byte, 32)
		copy(challengeMsg, []byte("NTLMSSP\x00\x02\x00\x00\x00"))
		copy(challengeMsg[24:], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})

		authMsg := make([]byte, 128)
		copy(authMsg[0:], []byte("NTLMSSP\x00\x03\x00\x00\x00"))
		// Security Buffer for LM Response
		copy(authMsg[12:], []byte{0x18, 0x00, 0x18, 0x00}) // len, maxlen
		copy(authMsg[16:], []byte{0x38, 0x00, 0x00, 0x00}) // offset
		// Security Buffer for NTLM Response
		copy(authMsg[20:], []byte{0x18, 0x00, 0x18, 0x00})
		copy(authMsg[24:], []byte{0x50, 0x00, 0x00, 0x00})
		// Security Buffer for Domain
		copy(authMsg[28:], []byte{0x06, 0x00, 0x06, 0x00})
		copy(authMsg[32:], []byte{0x68, 0x00, 0x00, 0x00})
		// Security Buffer for Username
		copy(authMsg[36:], []byte{0x08, 0x00, 0x08, 0x00})
		copy(authMsg[40:], []byte{0x6E, 0x00, 0x00, 0x00})

		// Add the payloads
		copy(authMsg[0x38:], bytes.Repeat([]byte{0xaa}, 24)) // LM hash
		copy(authMsg[0x50:], bytes.Repeat([]byte{0xbb}, 24)) // NT hash
		copy(authMsg[0x68:], []byte("DOMAIN"))
		copy(authMsg[0x6E:], []byte("testuser"))

		tests := []struct {
			name     string
			messages [][]byte
			expected *types.Credentials
		}{
			{
				name: "Complete NTLM Exchange",
				messages: [][]byte{
					challengeMsg,
					authMsg,
				},
				expected: &types.Credentials{
					Protocol: "NTLM",
					Data: map[string]string{
						"domain":    "DOMAIN",
						"user":      "testuser",
						"lmhash":    strings.Repeat("aa", 24),
						"nthash":    strings.Repeat("bb", 24),
						"challenge": "1122334455667788",
					},
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var creds *types.Credentials
				for i, msg := range tt.messages {
					packet := createTestPacket(msg, 445)
					if i == 0 {
						packet.Source, packet.Destination = packet.Destination, packet.Source
					}

					var err error
					creds, err = parser.Parse(packet)
					assert.NoError(t, err)

					if creds != nil {
						capturedCredentials = append(capturedCredentials, TestResults{
							Protocol:    creds.Protocol,
							Source:      fmt.Sprintf("%s:%d", packet.Source.IP, packet.Source.Port),
							Destination: fmt.Sprintf("%s:%d", packet.Destination.IP, packet.Destination.Port),
							Credentials: creds.Data,
						})
					}
				}

				require.NotNil(t, creds)
				assert.Equal(t, tt.expected.Protocol, creds.Protocol)
				for key, expectedValue := range tt.expected.Data {
					assert.Equal(t, expectedValue, creds.Data[key],
						"Mismatch in field %s", key)
				}
			})
		}
	})

	t.Run("LLMNR Parser Tests", func(t *testing.T) {
		parser := protocols.NewLLMNRParser()
		require.NotNil(t, parser)

		queryData := []byte{
			0x00, 0x00, // Transaction ID
			0x00, 0x00, // Flags
			0x00, 0x01, // Questions
			0x00, 0x00, // Answer RRs
			0x00, 0x00, // Authority RRs
			0x00, 0x00, // Additional RRs
			0x07, 'W', 'I', 'N', 'B', 'O', 'X', '1', // Query name
			0x00,       // Null terminator
			0x00, 0x01, // Type A
			0x00, 0x01, // Class IN
		}

		responseData := []byte{
			0x00, 0x00, // Transaction ID
			0x80, 0x00, // Flags (response)
			0x00, 0x01, // Questions
			0x00, 0x01, // Answer RRs
			0x00, 0x00, // Authority RRs
			0x00, 0x00, // Additional RRs
			0x07, 'W', 'I', 'N', 'B', 'O', 'X', '1', // Query name
			0x00,       // Null terminator
			0x00, 0x01, // Type A (1)
			0x00, 0x01, // Class IN (1)
			// Answer section
			0x07, 'W', 'I', 'N', 'B', 'O', 'X', '1', // Answer name
			0x00,       // Null terminator
			0x00, 0x01, // Type A
			0x00, 0x01, // Class IN
			0x00, 0x00, 0x00, 0x3C, // TTL (60 seconds)
			0x00, 0x04, // RDLENGTH (4 bytes)
			192, 168, 1, 100, // RDATA (IP address)
		}

		tests := []struct {
			name     string
			data     []byte
			dstPort  uint16
			expected *types.Credentials
		}{
			{
				name:    "LLMNR Query",
				dstPort: 5355,
				data:    queryData,
				expected: &types.Credentials{
					Protocol: "LLMNR",
					Data: map[string]string{
						"type": "query",
						"name": "WINBOX1",
					},
				},
			},
			{
				name:    "LLMNR Response",
				dstPort: 5355,
				data:    responseData,
				expected: &types.Credentials{
					Protocol: "LLMNR",
					Data: map[string]string{
						"type":    "response",
						"name":    "WINBOX1",
						"answers": "192.168.1.100",
					},
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				packet := createTestPacket(tt.data, tt.dstPort)
				creds, err := parser.Parse(packet)

				assert.NoError(t, err)
				require.NotNil(t, creds)
				assert.Equal(t, tt.expected.Protocol, creds.Protocol)
				for key, expectedValue := range tt.expected.Data {
					assert.Equal(t, expectedValue, creds.Data[key])
				}

				if creds != nil {
					capturedCredentials = append(capturedCredentials, TestResults{
						Protocol:    creds.Protocol,
						Source:      fmt.Sprintf("%s:%d", packet.Source.IP, packet.Source.Port),
						Destination: fmt.Sprintf("%s:%d", packet.Destination.IP, packet.Destination.Port),
						Credentials: creds.Data,
					})
				}
			})
		}
	})

	t.Run("IPV6 Parser Tests", func(t *testing.T) {
		parser := protocols.NewDHCPv6Parser()
		require.NotNil(t, parser)

		tests := []struct {
			name     string
			packet   *types.Packet
			expected *types.Credentials
		}{
			{
				name: "Valid DHCPv6 Client Port",
				packet: &types.Packet{
					SrcIP:   net.ParseIP("fe80::1"),
					DstIP:   net.ParseIP("ff02::1:2"),
					SrcPort: 546,
					DstPort: 547,
					Data:    []byte{0x01, 0x02, 0x03},
				},
				expected: &types.Credentials{
					Protocol: "DHCPv6",
					Source: types.Source{
						IP:   "fe80::1",
						Port: 546,
					},
					Destination: types.Source{
						IP:   "ff02::1:2",
						Port: 547,
					},
					Data: map[string]string{
						"alert": "DHCPv6 traffic detected - potential mitm6 target",
					},
				},
			},
			{
				name: "Valid DHCPv6 Server Port",
				packet: &types.Packet{
					SrcIP:   net.ParseIP("fe80::2"),
					DstIP:   net.ParseIP("fe80::1"),
					SrcPort: 547,
					DstPort: 546,
					Data:    []byte{0x01, 0x02, 0x03},
				},
				expected: &types.Credentials{
					Protocol: "DHCPv6",
					Source: types.Source{
						IP:   "fe80::2",
						Port: 547,
					},
					Destination: types.Source{
						IP:   "fe80::1",
						Port: 546,
					},
					Data: map[string]string{
						"alert": "DHCPv6 traffic detected - potential mitm6 target",
					},
				},
			},
			{
				name: "Invalid Port",
				packet: &types.Packet{
					SrcIP:   net.ParseIP("fe80::1"),
					DstIP:   net.ParseIP("fe80::2"),
					SrcPort: 80,
					DstPort: 80,
					Data:    []byte{0x01, 0x02, 0x03},
				},
				expected: nil,
			},
			{
				name:     "Nil Packet",
				packet:   nil,
				expected: nil,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				creds, err := parser.Parse(tt.packet)
				assert.NoError(t, err)

				if tt.expected == nil {
					assert.Nil(t, creds)
					return
				}

				require.NotNil(t, creds)
				assert.Equal(t, tt.expected.Protocol, creds.Protocol)
				assert.Equal(t, tt.expected.Source, creds.Source)
				assert.Equal(t, tt.expected.Destination, creds.Destination)
				assert.Equal(t, tt.expected.Data, creds.Data)
			})
		}
	})

	// Print capture summary at the end of all tests
	t.Run("Credential Capture Summary", func(t *testing.T) {
		if len(capturedCredentials) == 0 {
			t.Log("\n🔴 No credentials were captured during testing")
			return
		}

		t.Logf("\n🟢 Successfully captured %d credential sets:\n", len(capturedCredentials))
		for i, capture := range capturedCredentials {
			t.Logf("\n[%d] %s Capture", i+1, capture.Protocol)
			t.Logf("    Source: %s", capture.Source)
			t.Logf("    Destination: %s", capture.Destination)
			t.Log("    Credentials:")
			for k, v := range capture.Credentials {
				t.Logf("        %s: %s", k, v)
			}
			t.Log("    " + strings.Repeat("-", 40))
		}
	})
}

// Helper function to create test packets with more flexibility
func createTestPacket(data []byte, dstPort uint16) *types.Packet {
	return &types.Packet{
		Timestamp: time.Now(),
		Source: types.Source{
			IP:   "192.168.1.100",
			Port: 49152,
		},
		Destination: types.Source{
			IP:   "192.168.1.1",
			Port: dstPort,
		},
		Protocol: 6, // TCP
		Data:     data,
	}
}
