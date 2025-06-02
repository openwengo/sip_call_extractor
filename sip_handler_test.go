package main

import (
	"testing"
)

func init() {
	// Ensure the global 'debug' flag is initialized for tests
	if debug == nil {
		defaultDebugValue := false
		debug = &defaultDebugValue
	}

	if loggerDebug == nil || loggerInfo == nil {
		setupLogging()
	}
}

func TestParseSipHeaders(t *testing.T) {
	tests := []struct {
		name           string
		sipPayload     string
		expectedCallID string
		expectedFrom   string
		expectedTo     string
	}{
		{
			name: "Basic INVITE with standard headers",
			sipPayload: `INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: Bob <sip:bob@example.com>
From: Alice <sip:alice@example.com>;tag=1928301774
Call-ID: a84b4c76e66710@alice.example.com
CSeq: 314159 INVITE
Contact: <sip:alice@alice.example.com>
Content-Type: application/sdp
Content-Length: 142`,
			expectedCallID: "a84b4c76e66710@alice.example.com",
			expectedFrom:   "Alice <sip:alice@example.com>;tag=1928301774",
			expectedTo:     "Bob <sip:bob@example.com>",
		},
		{
			name: "Compact form headers",
			sipPayload: `INVITE sip:user@domain.com SIP/2.0
v: SIP/2.0/UDP proxy.domain.com:5060;branch=z9hG4bK123456
m: <sip:user@domain.com>
f: "John Doe" <sip:john@domain.com>;tag=abc123
t: <sip:user@domain.com>
i: call-id-12345@domain.com
l: 0`,
			expectedCallID: "call-id-12345@domain.com",
			expectedFrom:   `"John Doe" <sip:john@domain.com>;tag=abc123`,
			expectedTo:     "<sip:user@domain.com>",
		},
		{
			name: "Headers with extra whitespace",
			sipPayload: `INVITE sip:test@test.com SIP/2.0
Call-ID:   spaced-call-id@test.com   
From:    Test User <sip:test@test.com>  ;tag=tag123  
To:      <sip:dest@test.com>   
Content-Length: 0`,
			expectedCallID: "spaced-call-id@test.com",
			expectedFrom:   "Test User <sip:test@test.com>  ;tag=tag123",
			expectedTo:     "<sip:dest@test.com>",
		},
		{
			name: "BYE request",
			sipPayload: `BYE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bK776bye
To: Bob <sip:bob@example.com>;tag=456def
From: Alice <sip:alice@example.com>;tag=1928301774
Call-ID: a84b4c76e66710@alice.example.com
CSeq: 314160 BYE
Content-Length: 0`,
			expectedCallID: "a84b4c76e66710@alice.example.com",
			expectedFrom:   "Alice <sip:alice@example.com>;tag=1928301774",
			expectedTo:     "Bob <sip:bob@example.com>;tag=456def",
		},
		{
			name: "Response with status line",
			sipPayload: `SIP/2.0 200 OK
Via: SIP/2.0/UDP alice.example.com:5060;branch=z9hG4bK776asdhds
To: Bob <sip:bob@example.com>;tag=456def
From: Alice <sip:alice@example.com>;tag=1928301774
Call-ID: response-call-id@example.com
CSeq: 314159 INVITE
Contact: <sip:bob@bob.example.com>
Content-Type: application/sdp
Content-Length: 131`,
			expectedCallID: "response-call-id@example.com",
			expectedFrom:   "Alice <sip:alice@example.com>;tag=1928301774",
			expectedTo:     "Bob <sip:bob@example.com>;tag=456def",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callID, sipMethod, from, to, sdpPayload, err := parseSipHeaders([]byte(tt.sipPayload))

			if err != nil {
				t.Errorf("parseSipHeaders() unexpected error: %v", err)
				return
			}

			if callID != tt.expectedCallID {
				t.Errorf("parseSipHeaders() Call-ID = %v, want %v", callID, tt.expectedCallID)
			}
			if from != tt.expectedFrom {
				t.Errorf("parseSipHeaders() From = %v, want %v", from, tt.expectedFrom)
			}
			if to != tt.expectedTo {
				t.Errorf("parseSipHeaders() To = %v, want %v", to, tt.expectedTo)
			}

			// Log additional info for debugging
			t.Logf("SIP Method: %s, SDP Length: %d", sipMethod, len(sdpPayload))
		})
	}
}

func TestParseSIPPortsRange(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedMin uint16
		expectedMax uint16
		expectError bool
	}{
		{
			name:        "Single port (should fail - range required)",
			input:       "5060",
			expectedMin: 0,
			expectedMax: 0,
			expectError: true,
		},
		{
			name:        "Port range",
			input:       "5060-5080",
			expectedMin: 5060,
			expectedMax: 5080,
			expectError: false,
		},
		{
			name:        "Same start and end port",
			input:       "5060-5060",
			expectedMin: 5060,
			expectedMax: 5060,
			expectError: false,
		},
		{
			name:        "Wide port range",
			input:       "10000-20000",
			expectedMin: 10000,
			expectedMax: 20000,
			expectError: false,
		},
		{
			name:        "Invalid format - letters",
			input:       "abc",
			expectedMin: 0,
			expectedMax: 0,
			expectError: true,
		},
		{
			name:        "Invalid format - too many dashes",
			input:       "5060-5070-5080",
			expectedMin: 0,
			expectedMax: 0,
			expectError: true,
		},
		{
			name:        "Invalid range - min > max",
			input:       "5080-5060",
			expectedMin: 0,
			expectedMax: 0,
			expectError: true,
		},
		{
			name:        "Port out of range - too high",
			input:       "70000",
			expectedMin: 0,
			expectedMax: 0,
			expectError: true,
		},
		{
			name:        "Empty string",
			input:       "",
			expectedMin: 0,
			expectedMax: 0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			min, max, err := parseSIPPortsRange(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("parseSIPPortsRange() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("parseSIPPortsRange() unexpected error: %v", err)
				}
				if min != tt.expectedMin {
					t.Errorf("parseSIPPortsRange() min = %v, want %v", min, tt.expectedMin)
				}
				if max != tt.expectedMax {
					t.Errorf("parseSIPPortsRange() max = %v, want %v", max, tt.expectedMax)
				}
			}
		})
	}
}