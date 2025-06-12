package main

import (
	"reflect"
	"testing"
	// "github.com/google/gopacket/layers" // Not directly needed for parseSDP test, but Call struct might evolve
)

// Mocking logger for tests if needed, or ensure *debug can be set
func init() {
	// Setup a discard logger for tests to avoid noisy output,
	// or allow configuring it via test flags if verbose output is desired.
	// For simplicity, we'll assume *debug is false or loggers are handled.
	// If *debug is directly used in parseSDP, we might need to control it.
	// The current sdp_handler.go uses *debug, which is a global var from cli.go.
	// This can make testing tricky. Consider passing logger/debug status as a parameter.

	// Ensure the global 'debug' flag (from cli.go) is initialized for tests,
	// as initFlags() from cli.go won't be called automatically.
	if debug == nil {
		defaultDebugValue := false // Or true if verbose test logging is desired by default
		debug = &defaultDebugValue
	}

	if loggerDebug == nil || loggerInfo == nil { // Ensure loggers are set up
		setupLogging() // This will set loggerDebug based on the 'debug' var we just set.
	}
}

func TestParseSDP(t *testing.T) {
	// Make *debug true for verbose test logging if desired
	// originalDebugState := *debug
	// *debug = true // or false
	// defer func() { *debug = originalDebugState }()


	tests := []struct {
		name             string
		sdpPayload       string
		isAnswer         bool
		expectedCall     *Call // Only MediaSessions and SDPPtime are checked
		initialSessions  []MediaSession // For testing offer/answer logic with pre-existing sessions
	}{
		{
			name: "Simple Offer with Audio and Video",
			sdpPayload: `v=0
o=- 12345 67890 IN IP4 192.0.2.1
s=SIP Call
c=IN IP4 192.0.2.1
t=0 0
m=audio 10000 RTP/AVP 0 8 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=ptime:20
m=video 10002 RTP/AVP 96
c=IN IP4 192.0.2.2
a=rtpmap:96 H264/90000
a=inactive
`,
			isAnswer: false,
			expectedCall: &Call{
				MediaSessions: []MediaSession{
					{IPAddress: "192.0.2.1", Port: 10000},
					// Video is inactive, so not expected
				},
				SDPPtime: 20,
			},
		},
		{
			name: "Simple Answer with Audio active, Video inactive",
			sdpPayload: `v=0
o=- 67890 12345 IN IP4 192.0.2.5
s=SIP Call
c=IN IP4 192.0.2.5
t=0 0
m=audio 20000 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=ptime:30
m=video 20002 RTP/AVP 96
a=rtpmap:96 H264/90000
a=inactive
`,
			isAnswer: true,
			expectedCall: &Call{
				MediaSessions: []MediaSession{
					{IPAddress: "192.0.2.5", Port: 20000},
				},
				SDPPtime: 30,
			},
		},
		{
			name: "Offer with media-level c-line and ptime",
			sdpPayload: `v=0
o=- 111 222 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 30000 RTP/AVP 0
c=IN IP4 10.0.0.100 
a=rtpmap:0 PCMU/8000
a=ptime:40
m=video 30002 RTP/AVP 100
c=IN IP4 10.0.0.200
a=rtpmap:100 VP8/90000
`,
			isAnswer: false,
			expectedCall: &Call{
				MediaSessions: []MediaSession{
					{IPAddress: "10.0.0.100", Port: 30000},
					{IPAddress: "10.0.0.200", Port: 30002},
				},
				SDPPtime: 40,
			},
		},
		{
			name: "Answer appending new unique sessions to existing sessions",
			sdpPayload: `v=0
c=IN IP4 192.168.1.10
m=audio 5000 RTP/AVP 0
a=ptime:20
`,
			isAnswer: true,
			initialSessions: []MediaSession{{IPAddress: "10.0.0.1", Port: 1234}}, // Should be kept
			expectedCall: &Call{
				MediaSessions: []MediaSession{
					{IPAddress: "10.0.0.1", Port: 1234},     // Original session
					{IPAddress: "192.168.1.10", Port: 5000}, // New session from answer
				},
				SDPPtime: 20,
			},
		},
		{
			name: "Answer with duplicate session (should not add duplicates)",
			sdpPayload: `v=0
c=IN IP4 10.0.0.1
m=audio 1234 RTP/AVP 0
a=ptime:20
`,
			isAnswer: true,
			initialSessions: []MediaSession{{IPAddress: "10.0.0.1", Port: 1234}}, // Same as in SDP
			expectedCall: &Call{
				MediaSessions: []MediaSession{ // Should remain the same (no duplicate)
					{IPAddress: "10.0.0.1", Port: 1234},
				},
				SDPPtime: 20,
			},
		},
		{
			name: "Offer appending new unique sessions to existing sessions",
			sdpPayload: `v=0
c=IN IP4 192.168.1.20
m=audio 6000 RTP/AVP 0
a=ptime:20
`,
			isAnswer: false,
			initialSessions: []MediaSession{{IPAddress: "10.0.0.2", Port: 5678}}, // Should be kept
			expectedCall: &Call{
				MediaSessions: []MediaSession{ // Expecting both initial and new sessions
					{IPAddress: "10.0.0.2", Port: 5678}, // Original session
					{IPAddress: "192.168.1.20", Port: 6000}, // New session from offer
				},
				SDPPtime: 20, // ptime from current SDP should still be parsed
			},
		},
		{
			name: "Offer with duplicate session (should not add duplicates)",
			sdpPayload: `v=0
c=IN IP4 10.0.0.2
m=audio 5678 RTP/AVP 0
a=ptime:20
`,
			isAnswer: false,
			initialSessions: []MediaSession{{IPAddress: "10.0.0.2", Port: 5678}}, // Same as in SDP
			expectedCall: &Call{
				MediaSessions: []MediaSession{ // Should remain the same (no duplicate)
					{IPAddress: "10.0.0.2", Port: 5678},
				},
				SDPPtime: 20,
			},
		},
		{
			name: "Offer populating empty sessions",
			sdpPayload: `v=0
c=IN IP4 192.168.1.30
m=audio 7000 RTP/AVP 0
a=ptime:20
`,
			isAnswer: false,
			initialSessions: []MediaSession{}, // Empty
			expectedCall: &Call{
				MediaSessions: []MediaSession{
					{IPAddress: "192.168.1.30", Port: 7000},
				},
				SDPPtime: 20,
			},
		},
		{
			name: "All media inactive",
			sdpPayload: `v=0
c=IN IP4 192.0.2.1
m=audio 10000 RTP/AVP 0
a=inactive
m=video 10002 RTP/AVP 96
a=inactive
a=ptime:60
`,
			isAnswer: false,
			expectedCall: &Call{
				MediaSessions: []MediaSession{}, // Expect empty
				SDPPtime:      60,
			},
		},
		{
			name: "No media lines",
			sdpPayload: `v=0
c=IN IP4 192.0.2.1
a=ptime:20
`,
			isAnswer: false,
			expectedCall: &Call{
				MediaSessions: []MediaSession{},
				SDPPtime:      20,
			},
		},
		{
			name: "Media line with no IP (should be skipped)",
			sdpPayload: `v=0
o=- 123 456 IN IP4 0.0.0.0 
s=-
t=0 0
m=audio 1234 RTP/AVP 0 
a=ptime:20
`, // No c-line at session or media level
			isAnswer: false,
			expectedCall: &Call{
				MediaSessions: []MediaSession{},
				SDPPtime:      20,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize call with a unique CallID for logging purposes if *debug is true
			call := &Call{CallID: "test-" + tt.name, SDPPtime: 20} // Default ptime
			if tt.initialSessions != nil {
				call.MediaSessions = make([]MediaSession, len(tt.initialSessions))
				copy(call.MediaSessions, tt.initialSessions)
			} else {
				call.MediaSessions = []MediaSession{}
			}


			parseSDP([]byte(tt.sdpPayload), call, tt.isAnswer)

			if !reflect.DeepEqual(call.MediaSessions, tt.expectedCall.MediaSessions) {
				t.Errorf("parseSDP() MediaSessions got = %v, want %v", call.MediaSessions, tt.expectedCall.MediaSessions)
			}
			if call.SDPPtime != tt.expectedCall.SDPPtime {
				t.Errorf("parseSDP() SDPPtime got = %v, want %v", call.SDPPtime, tt.expectedCall.SDPPtime)
			}
		})
	}
}