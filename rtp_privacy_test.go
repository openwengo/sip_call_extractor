package main

import (
	"regexp"
	"testing"
)

func TestShouldClearPayloadForCall(t *testing.T) {
	// Save original values
	origNoRtpDump := noRtpDump
	origNoRtpDumpForCallIdPattern := noRtpDumpForCallIdPattern
	origNoRtpDumpExceptForCallIdPattern := noRtpDumpExceptForCallIdPattern
	origNoRtpDumpForFromPattern := noRtpDumpForFromPattern
	origNoRtpDumpExceptForFromPattern := noRtpDumpExceptForFromPattern
	origNoRtpDumpForToPattern := noRtpDumpForToPattern
	origNoRtpDumpExceptForToPattern := noRtpDumpExceptForToPattern
	
	origNoRtpDumpForCallIdRegexp := noRtpDumpForCallIdRegexp
	origNoRtpDumpExceptForCallIdRegexp := noRtpDumpExceptForCallIdRegexp
	origNoRtpDumpForFromRegexp := noRtpDumpForFromRegexp
	origNoRtpDumpExceptForFromRegexp := noRtpDumpExceptForFromRegexp
	origNoRtpDumpForToRegexp := noRtpDumpForToRegexp
	origNoRtpDumpExceptForToRegexp := noRtpDumpExceptForToRegexp

	// Restore original values after test
	defer func() {
		noRtpDump = origNoRtpDump
		noRtpDumpForCallIdPattern = origNoRtpDumpForCallIdPattern
		noRtpDumpExceptForCallIdPattern = origNoRtpDumpExceptForCallIdPattern
		noRtpDumpForFromPattern = origNoRtpDumpForFromPattern
		noRtpDumpExceptForFromPattern = origNoRtpDumpExceptForFromPattern
		noRtpDumpForToPattern = origNoRtpDumpForToPattern
		noRtpDumpExceptForToPattern = origNoRtpDumpExceptForToPattern
		
		noRtpDumpForCallIdRegexp = origNoRtpDumpForCallIdRegexp
		noRtpDumpExceptForCallIdRegexp = origNoRtpDumpExceptForCallIdRegexp
		noRtpDumpForFromRegexp = origNoRtpDumpForFromRegexp
		noRtpDumpExceptForFromRegexp = origNoRtpDumpExceptForFromRegexp
		noRtpDumpForToRegexp = origNoRtpDumpForToRegexp
		noRtpDumpExceptForToRegexp = origNoRtpDumpExceptForToRegexp
	}()

	testCall := &Call{
		CallID:  "test-call-123",
		SIPFrom: "sip:alice@example.com",
		SIPTo:   "sip:bob@example.com",
	}

	tests := []struct {
		name                              string
		noRtpDumpFlag                     bool
		noRtpDumpForCallIdPattern         string
		noRtpDumpExceptForCallIdPattern   string
		noRtpDumpForFromPattern           string
		noRtpDumpExceptForFromPattern     string
		noRtpDumpForToPattern             string
		noRtpDumpExceptForToPattern       string
		expectedClear                     bool
	}{
		{
			name:          "No flags set - should not clear",
			expectedClear: false,
		},
		{
			name:          "Global no-rtp-dump flag - should clear",
			noRtpDumpFlag: true,
			expectedClear: true,
		},
		{
			name:                      "CallID pattern matches - should clear",
			noRtpDumpForCallIdPattern: "test-call-.*",
			expectedClear:             true,
		},
		{
			name:                      "CallID pattern doesn't match - should not clear",
			noRtpDumpForCallIdPattern: "other-call-.*",
			expectedClear:             false,
		},
		{
			name:                    "From pattern matches - should clear",
			noRtpDumpForFromPattern: ".*alice.*",
			expectedClear:           true,
		},
		{
			name:                  "To pattern matches - should clear",
			noRtpDumpForToPattern: ".*bob.*",
			expectedClear:         true,
		},
		{
			name:                            "Except-for CallID matches - should not clear (preservation rule)",
			noRtpDumpFlag:                   true,
			noRtpDumpExceptForCallIdPattern: "test-call-.*",
			expectedClear:                   false,
		},
		{
			name:                          "Except-for From matches - should not clear (preservation rule)",
			noRtpDumpFlag:                 true,
			noRtpDumpExceptForFromPattern: ".*alice.*",
			expectedClear:                 false,
		},
		{
			name:                        "Except-for To matches - should not clear (preservation rule)",
			noRtpDumpFlag:               true,
			noRtpDumpExceptForToPattern: ".*bob.*",
			expectedClear:               false,
		},
		{
			name:                            "Except-for CallID provided but doesn't match - should clear (implicit dump)",
			noRtpDumpExceptForCallIdPattern: "other-call-.*",
			expectedClear:                   true,
		},
		{
			name:                          "Except-for From provided but doesn't match - should clear (implicit dump)",
			noRtpDumpExceptForFromPattern: ".*charlie.*",
			expectedClear:                 true,
		},
		{
			name:                        "Except-for To provided but doesn't match - should clear (implicit dump)",
			noRtpDumpExceptForToPattern: ".*charlie.*",
			expectedClear:               true,
		},
		{
			name:                            "Multiple patterns - except-for takes precedence",
			noRtpDumpFlag:                   true,
			noRtpDumpForCallIdPattern:       "test-call-.*",
			noRtpDumpExceptForCallIdPattern: "test-call-.*",
			expectedClear:                   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset all flags and regexes
			falseFlag := false
			trueFlag := true
			emptyString := ""
			
			noRtpDump = &falseFlag
			if tt.noRtpDumpFlag {
				noRtpDump = &trueFlag
			}
			
			noRtpDumpForCallIdPattern = &emptyString
			noRtpDumpExceptForCallIdPattern = &emptyString
			noRtpDumpForFromPattern = &emptyString
			noRtpDumpExceptForFromPattern = &emptyString
			noRtpDumpForToPattern = &emptyString
			noRtpDumpExceptForToPattern = &emptyString
			
			noRtpDumpForCallIdRegexp = nil
			noRtpDumpExceptForCallIdRegexp = nil
			noRtpDumpForFromRegexp = nil
			noRtpDumpExceptForFromRegexp = nil
			noRtpDumpForToRegexp = nil
			noRtpDumpExceptForToRegexp = nil

			// Set up patterns and compile regexes
			if tt.noRtpDumpForCallIdPattern != "" {
				pattern := tt.noRtpDumpForCallIdPattern
				noRtpDumpForCallIdPattern = &pattern
				noRtpDumpForCallIdRegexp = regexp.MustCompile(pattern)
			}
			if tt.noRtpDumpExceptForCallIdPattern != "" {
				pattern := tt.noRtpDumpExceptForCallIdPattern
				noRtpDumpExceptForCallIdPattern = &pattern
				noRtpDumpExceptForCallIdRegexp = regexp.MustCompile(pattern)
			}
			if tt.noRtpDumpForFromPattern != "" {
				pattern := tt.noRtpDumpForFromPattern
				noRtpDumpForFromPattern = &pattern
				noRtpDumpForFromRegexp = regexp.MustCompile(pattern)
			}
			if tt.noRtpDumpExceptForFromPattern != "" {
				pattern := tt.noRtpDumpExceptForFromPattern
				noRtpDumpExceptForFromPattern = &pattern
				noRtpDumpExceptForFromRegexp = regexp.MustCompile(pattern)
			}
			if tt.noRtpDumpForToPattern != "" {
				pattern := tt.noRtpDumpForToPattern
				noRtpDumpForToPattern = &pattern
				noRtpDumpForToRegexp = regexp.MustCompile(pattern)
			}
			if tt.noRtpDumpExceptForToPattern != "" {
				pattern := tt.noRtpDumpExceptForToPattern
				noRtpDumpExceptForToPattern = &pattern
				noRtpDumpExceptForToRegexp = regexp.MustCompile(pattern)
			}

			result := shouldClearPayloadForCall(testCall)
			if result != tt.expectedClear {
				t.Errorf("shouldClearPayloadForCall() = %v, want %v", result, tt.expectedClear)
			}
		})
	}
}

func TestClearRtpPayload(t *testing.T) {
	// Save original debug flag
	origDebug := debug
	defer func() {
		debug = origDebug
	}()
	
	// Set debug to false for cleaner test output
	falseFlag := false
	debug = &falseFlag

	tests := []struct {
		name           string
		rtpPayload     []byte
		expectedCleared bool
		description    string
	}{
		{
			name:            "Too short packet",
			rtpPayload:      []byte{0x80, 0x00, 0x00, 0x01}, // Only 4 bytes
			expectedCleared: false,
			description:     "Packet too short for RTP header",
		},
		{
			name: "Basic RTP packet with payload",
			rtpPayload: []byte{
				0x80, 0x00, 0x00, 0x01, // V=2, P=0, X=0, CC=0, M=0, PT=0, Seq=1
				0x00, 0x00, 0x00, 0x64, // Timestamp=100
				0x12, 0x34, 0x56, 0x78, // SSRC=0x12345678
				0xAA, 0xBB, 0xCC, 0xDD, // Payload (should be cleared)
			},
			expectedCleared: true,
			description:     "Basic RTP packet payload should be cleared",
		},
		{
			name: "RTP packet with CSRC",
			rtpPayload: []byte{
				0x81, 0x00, 0x00, 0x01, // V=2, P=0, X=0, CC=1, M=0, PT=0, Seq=1
				0x00, 0x00, 0x00, 0x64, // Timestamp=100
				0x12, 0x34, 0x56, 0x78, // SSRC=0x12345678
				0x11, 0x22, 0x33, 0x44, // CSRC[0]=0x11223344
				0xAA, 0xBB, 0xCC, 0xDD, // Payload (should be cleared)
			},
			expectedCleared: true,
			description:     "RTP packet with CSRC payload should be cleared",
		},
		{
			name: "RTP packet with extension",
			rtpPayload: []byte{
				0x90, 0x00, 0x00, 0x01, // V=2, P=0, X=1, CC=0, M=0, PT=0, Seq=1
				0x00, 0x00, 0x00, 0x64, // Timestamp=100
				0x12, 0x34, 0x56, 0x78, // SSRC=0x12345678
				0xAB, 0xCD, 0x00, 0x01, // Extension: ID=0xABCD, Length=1 word
				0x11, 0x22, 0x33, 0x44, // Extension data (1 word = 4 bytes)
				0xAA, 0xBB, 0xCC, 0xDD, // Payload (should be cleared)
			},
			expectedCleared: true,
			description:     "RTP packet with extension payload should be cleared",
		},
		{
			name: "RTP packet with padding",
			rtpPayload: []byte{
				0xA0, 0x00, 0x00, 0x01, // V=2, P=1, X=0, CC=0, M=0, PT=0, Seq=1
				0x00, 0x00, 0x00, 0x64, // Timestamp=100
				0x12, 0x34, 0x56, 0x78, // SSRC=0x12345678
				0xAA, 0xBB, 0xCC, 0xDD, // Payload (should be cleared)
				0x00, 0x00, 0x00, 0x04, // Padding (4 bytes, last byte indicates padding length)
			},
			expectedCleared: true,
			description:     "RTP packet with padding payload should be cleared",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy of the original payload to compare
			originalPayload := make([]byte, len(tt.rtpPayload))
			copy(originalPayload, tt.rtpPayload)

			clearRtpPayload(tt.rtpPayload, "test-call")

			if tt.expectedCleared {
				// Check if payload was actually cleared (find the payload portion and verify it's zeroed)
				if len(tt.rtpPayload) > 12 {
					// For basic RTP packet, payload starts at byte 12
					payloadStart := 12
					
					// Adjust for CSRC
					if len(originalPayload) > 0 {
						csrcCount := int(originalPayload[0] & 0x0F)
						payloadStart += csrcCount * 4
					}
					
					// Adjust for extension
					if len(originalPayload) > 0 && (originalPayload[0]>>4)&0x01 == 1 {
						if len(originalPayload) >= payloadStart+4 {
							extensionLengthInWords := uint16(originalPayload[payloadStart+2])<<8 | uint16(originalPayload[payloadStart+3])
							payloadStart += (int(extensionLengthInWords) + 1) * 4
						}
					}
					
					// Check if we have payload to verify
					payloadEnd := len(tt.rtpPayload)
					if len(originalPayload) > 0 && (originalPayload[0]>>5)&0x01 == 1 { // Has padding
						if payloadEnd > 0 {
							paddingLength := int(originalPayload[len(originalPayload)-1])
							if paddingLength > 0 && paddingLength <= (payloadEnd-payloadStart) {
								payloadEnd -= paddingLength
							}
						}
					}
					
					if payloadStart < payloadEnd {
						// Verify payload is cleared (all zeros)
						for i := payloadStart; i < payloadEnd; i++ {
							if tt.rtpPayload[i] != 0 {
								t.Errorf("Payload byte at index %d was not cleared: got %02x, want 00", i, tt.rtpPayload[i])
							}
						}
						
						// Verify header is unchanged
						for i := 0; i < payloadStart; i++ {
							if tt.rtpPayload[i] != originalPayload[i] {
								t.Errorf("Header byte at index %d was modified: got %02x, want %02x", i, tt.rtpPayload[i], originalPayload[i])
							}
						}
					}
				}
			} else {
				// Verify payload was not modified
				for i := 0; i < len(tt.rtpPayload); i++ {
					if tt.rtpPayload[i] != originalPayload[i] {
						t.Errorf("Byte at index %d was modified when it shouldn't be: got %02x, want %02x", i, tt.rtpPayload[i], originalPayload[i])
					}
				}
			}
		})
	}
}