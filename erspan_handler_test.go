package main

import (
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)


func TestERSPANType2Parsing(t *testing.T) {
	// Create a mock ERSPAN Type II header (8 bytes)
	// Version=1, VLAN=100, COS=0, Encap=0, T=0, SpanID=5, Reserved=0, Index=1
	erspanHeader := []byte{
		0x10, 0x64, // Version(4)=1, VLAN(12)=100
		0x00, 0x05, // COS(3)=0, Encap(2)=0, T(1)=0, SpanID(10)=5
		0x00, 0x00, 0x00, 0x01, // Reserved(12)=0, Index(20)=1
	}

	// Add a minimal Ethernet frame after ERSPAN header
	ethernetFrame := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // Dst MAC
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // Src MAC
		0x08, 0x00, // EtherType (IPv4)
		// Minimal IPv4 header would follow...
	}

	payload := append(erspanHeader, ethernetFrame...)

	innerPacket, metadata := parseERSPANType2(payload)

	if innerPacket == nil {
		t.Fatal("Expected inner packet to be parsed, got nil")
	}

	if metadata == nil {
		t.Fatal("Expected metadata to be parsed, got nil")
	}

	// Verify metadata
	if metadata.Version != 1 {
		t.Errorf("Expected version 1, got %d", metadata.Version)
	}

	if metadata.VLAN != 100 {
		t.Errorf("Expected VLAN 100, got %d", metadata.VLAN)
	}

	if metadata.SpanID != 5 {
		t.Errorf("Expected SpanID 5, got %d", metadata.SpanID)
	}

	if metadata.Direction != 0 {
		t.Errorf("Expected Direction 0 for Type II, got %d", metadata.Direction)
	}

	if metadata.Timestamp != 0 {
		t.Errorf("Expected Timestamp 0 for Type II, got %d", metadata.Timestamp)
	}
}

func TestERSPANType3Parsing(t *testing.T) {
	// Create a mock ERSPAN Type III header (12 bytes)
	// Version=2, VLAN=200, COS=1, BSO=0, T=0, SpanID=10
	erspanHeader := []byte{
		0x20, 0xC8, // Version(4)=2, VLAN(12)=200
		0x20, 0x0A, // COS(3)=1, BSO(2)=0, T(1)=0, SpanID(10)=10
		0x12, 0x34, 0x56, 0x78, // Timestamp=0x12345678
		0x00, 0x64, // SGT=100
		0x05, 0x00, // P(1)=0, FT(5)=2, HW(6)=20, D(1)=0, GRA(2)=0, O(1)=0
	}

	// Add a minimal Ethernet frame after ERSPAN header
	ethernetFrame := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // Dst MAC
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // Src MAC
		0x08, 0x00, // EtherType (IPv4)
		// Minimal IPv4 header would follow...
	}

	payload := append(erspanHeader, ethernetFrame...)

	innerPacket, metadata := parseERSPANType3(payload)

	if innerPacket == nil {
		t.Fatal("Expected inner packet to be parsed, got nil")
	}

	if metadata == nil {
		t.Fatal("Expected metadata to be parsed, got nil")
	}

	// Verify metadata
	if metadata.Version != 2 {
		t.Errorf("Expected version 2, got %d", metadata.Version)
	}

	if metadata.VLAN != 200 {
		t.Errorf("Expected VLAN 200, got %d", metadata.VLAN)
	}

	if metadata.SpanID != 10 {
		t.Errorf("Expected SpanID 10, got %d", metadata.SpanID)
	}

	if metadata.Direction != 0 {
		t.Errorf("Expected Direction 0, got %d", metadata.Direction)
	}

	if metadata.Timestamp != 0x12345678 {
		t.Errorf("Expected Timestamp 0x12345678, got %d", metadata.Timestamp)
	}
}

func TestGREProtocolDetection(t *testing.T) {
	// Test ERSPAN protocol detection
	erspanPayload := []byte{0x10, 0x64, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01} // Mock ERSPAN Type II header
	
	// Create a mock GRE layer with ERSPAN protocol
	gre := &layers.GRE{
		Protocol: 0x88BE, // ERSPAN protocol
	}
	// Manually set the payload using reflection or direct field access
	gre.BaseLayer.Payload = erspanPayload

	// Create a mock packet
	packet := gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet, gopacket.Default)

	innerPacket, metadata := handleGREPacket(packet, gre)

	if innerPacket != nil || metadata != nil {
		// This should fail because we don't have a complete Ethernet frame in the payload
		// But the function should at least attempt to parse it
		t.Log("GRE packet processing attempted (expected to fail due to incomplete payload)")
	}

	// Test non-ERSPAN GRE packet
	greNonERSPAN := &layers.GRE{
		Protocol: 0x0800, // IPv4 protocol (not ERSPAN)
	}
	greNonERSPAN.BaseLayer.Payload = []byte{0x45, 0x00} // Mock IPv4 header start

	innerPacket, metadata = handleGREPacket(packet, greNonERSPAN)

	if innerPacket != nil || metadata != nil {
		t.Error("Expected non-ERSPAN GRE packet to be ignored")
	}
}

func TestERSPANConfigValidation(t *testing.T) {
	// Test the validation logic directly without relying on global flags
	tests := []struct {
		name           string
		erspanEnabled  bool
		bpfFilter      string
		expectError    bool
	}{
		{"Valid config - ERSPAN disabled", false, "udp", false},
		{"Valid config - ERSPAN with default filter", true, "udp", false},
		{"Invalid config - ERSPAN with custom filter", true, "tcp", true},
		{"Valid config - ERSPAN with empty filter", true, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the global variables for this test
			oldERSPAN := enableERSPAN
			oldFilter := bpfFilter
			
			// Create temporary variables
			tempERSPAN := tt.erspanEnabled
			tempFilter := tt.bpfFilter
			enableERSPAN = &tempERSPAN
			bpfFilter = &tempFilter
			
			err := validateERSPANConfig()
			
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			
			// Restore original values
			enableERSPAN = oldERSPAN
			bpfFilter = oldFilter
		})
	}
}

func TestBPFFilterGeneration(t *testing.T) {
	tests := []struct {
		name           string
		erspanEnabled  bool
		bpfFilter      string
		expectedFilter string
	}{
		{"Normal mode", false, "udp", "udp"},
		{"ERSPAN mode", true, "udp", "proto gre"},
		{"ERSPAN mode with custom filter", true, "tcp", "proto gre"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the global variables for this test
			oldERSPAN := enableERSPAN
			oldFilter := bpfFilter
			
			// Create temporary variables
			tempERSPAN := tt.erspanEnabled
			tempFilter := tt.bpfFilter
			enableERSPAN = &tempERSPAN
			bpfFilter = &tempFilter
			
			filter := generateBPFFilter()
			
			if filter != tt.expectedFilter {
				t.Errorf("Expected '%s' filter, got '%s'", tt.expectedFilter, filter)
			}
			
			// Restore original values
			enableERSPAN = oldERSPAN
			bpfFilter = oldFilter
		})
	}
}

func TestShouldProcessERSPANPacket(t *testing.T) {
	metadata := &ERSPANMetadata{
		Version: 1,
		SpanID:  5,
		VLAN:    100,
	}

	tests := []struct {
		name        string
		spanIDs     string
		vlans       string
		shouldPass  bool
	}{
		{"No filters", "", "", true},
		{"Matching SPAN ID", "1,5,10", "", true},
		{"Non-matching SPAN ID", "1,2,10", "", false},
		{"Matching VLAN", "", "50,100,200", true},
		{"Non-matching VLAN", "", "50,200,300", false},
		{"Both matching", "1,5,10", "50,100,200", true},
		{"SPAN ID matches, VLAN doesn't", "1,5,10", "50,200,300", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the global variables for this test
			oldSpanIDs := erspanSpanIDs
			oldVLANs := erspanVLANs
			
			// Create temporary variables
			tempSpanIDs := tt.spanIDs
			tempVLANs := tt.vlans
			erspanSpanIDs = &tempSpanIDs
			erspanVLANs = &tempVLANs
			
			result := shouldProcessERSPANPacket(metadata)
			
			if result != tt.shouldPass {
				t.Errorf("Expected %v, got %v", tt.shouldPass, result)
			}
			
			// Restore original values
			erspanSpanIDs = oldSpanIDs
			erspanVLANs = oldVLANs
		})
	}
}

func TestParseCommaSeparatedUint16(t *testing.T) {
	// Test empty string
	result := parseCommaSeparatedUint16("")
	if len(result) != 0 {
		t.Errorf("Expected empty result for empty string, got %v", result)
	}

	// Test single value
	result = parseCommaSeparatedUint16("100")
	if len(result) != 1 || result[0] != 100 {
		t.Errorf("Expected [100], got %v", result)
	}

	// Test multiple values
	result = parseCommaSeparatedUint16("1,5,10,100")
	expected := []uint16{1, 5, 10, 100}
	if len(result) != len(expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
	for i, v := range expected {
		if result[i] != v {
			t.Errorf("Expected %v, got %v", expected, result)
			break
		}
	}

	// Test with spaces
	result = parseCommaSeparatedUint16(" 1 , 5 , 10 ")
	expected = []uint16{1, 5, 10}
	if len(result) != len(expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
	for i, v := range expected {
		if result[i] != v {
			t.Errorf("Expected %v, got %v", expected, result)
			break
		}
	}

	// Test hex values
	result = parseCommaSeparatedUint16("0x10,0x20,0x30")
	expected = []uint16{16, 32, 48}
	if len(result) != len(expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
	for i, v := range expected {
		if result[i] != v {
			t.Errorf("Expected %v, got %v", expected, result)
			break
		}
	}
}

func TestTrackERSPANSession(t *testing.T) {
	// Create a mock call
	call := &Call{
		CallID:         "test-call-123",
		ERSPANSessions: make(map[uint16]*ERSPANSessionInfo),
	}

	metadata := &ERSPANMetadata{
		Version: 1,
		SpanID:  5,
		VLAN:    100,
	}

	timestamp := time.Now()

	// Mock the global variables for this test
	oldLogERSPANStats := logERSPANStats
	oldDebug := debug
	
	tempLogERSPANStats := false
	tempDebug := false
	logERSPANStats = &tempLogERSPANStats
	debug = &tempDebug

	// Test creating new session
	trackERSPANSession(call, metadata, timestamp)

	if len(call.ERSPANSessions) != 1 {
		t.Errorf("Expected 1 ERSPAN session, got %d", len(call.ERSPANSessions))
	}

	session, exists := call.ERSPANSessions[5]
	if !exists {
		t.Fatal("Expected ERSPAN session 5 to exist")
	}

	if session.SpanID != 5 {
		t.Errorf("Expected SpanID 5, got %d", session.SpanID)
	}

	if session.VLAN != 100 {
		t.Errorf("Expected VLAN 100, got %d", session.VLAN)
	}

	if session.Version != 1 {
		t.Errorf("Expected Version 1, got %d", session.Version)
	}

	if session.PacketCount != 1 {
		t.Errorf("Expected PacketCount 1, got %d", session.PacketCount)
	}

	// Test updating existing session
	trackERSPANSession(call, metadata, timestamp)

	if session.PacketCount != 2 {
		t.Errorf("Expected PacketCount 2, got %d", session.PacketCount)
	}

	// Test with nil metadata
	trackERSPANSession(call, nil, timestamp)

	if session.PacketCount != 2 {
		t.Errorf("Expected PacketCount to remain 2 with nil metadata, got %d", session.PacketCount)
	}
	
	// Restore original values
	logERSPANStats = oldLogERSPANStats
	debug = oldDebug
}