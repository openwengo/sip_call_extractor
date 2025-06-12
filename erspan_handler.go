package main

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ERSPANMetadata holds metadata extracted from ERSPAN headers
type ERSPANMetadata struct {
	Version   uint8
	SpanID    uint16
	VLAN      uint16
	Direction uint8  // For Type III (0=ingress, 1=egress)
	Timestamp uint32
}

// ERSPANType1Header represents ERSPAN Type I header (4 bytes)
type ERSPANType1Header struct {
	Version   uint8  // 4 bits: Version (0 for Type I)
	VLAN      uint16 // 12 bits: VLAN ID
	COS       uint8  // 3 bits: Class of Service
	Encap     uint8  // 2 bits: Encapsulation type
	Truncated bool   // 1 bit: Truncated frame
	SpanID    uint16 // 10 bits: SPAN session ID
}

// ERSPANType2Header represents ERSPAN Type II header (8 bytes)
type ERSPANType2Header struct {
	Version   uint8  // 4 bits: Version (1 for Type II)
	VLAN      uint16 // 12 bits: VLAN ID
	COS       uint8  // 3 bits: Class of Service
	Encap     uint8  // 2 bits: Encapsulation type
	Truncated bool   // 1 bit: Truncated frame
	SpanID    uint16 // 10 bits: SPAN session ID
	Reserved  uint8  // 12 bits: Reserved
	Index     uint32 // 20 bits: Port index
}

// ERSPANType3Header represents ERSPAN Type III header (12 bytes)
type ERSPANType3Header struct {
	Version   uint8  // 4 bits: Version (2 for Type III)
	VLAN      uint16 // 12 bits: VLAN ID
	COS       uint8  // 3 bits: Class of Service
	BSO       uint8  // 2 bits: Bad/Short/Oversized
	Truncated bool   // 1 bit: Truncated frame
	SpanID    uint16 // 10 bits: SPAN session ID
	Timestamp uint32 // 32 bits: Timestamp
	SGT       uint16 // 16 bits: Security Group Tag
	P         bool   // 1 bit: Platform specific info present
	FT        uint8  // 5 bits: Frame type
	HW        uint8  // 6 bits: Hardware ID
	Direction uint8  // 1 bit: Direction (0=ingress, 1=egress)
	GRA       uint8  // 2 bits: Granularity
	Options   uint8  // 1 bit: Optional subheaders present
}

// handleGREPacket processes GRE packets and extracts ERSPAN data
func handleGREPacket(originalPacket gopacket.Packet, greLayer gopacket.Layer) (gopacket.Packet, *ERSPANMetadata) {
	gre, ok := greLayer.(*layers.GRE)
	if !ok {
		if *debug {
			loggerDebug.Println("Failed to cast GRE layer")
		}
		return nil, nil
	}

	// Check if this is ERSPAN (Protocol Type 0x88BE for Type I/II, 0x22EB for Type III)
	switch gre.Protocol {
	case 0x22EB: // ERSPAN Type III
		if *debug {
			loggerDebug.Printf("Processing GRE packet as ERSPAN Type III (Protocol: 0x%X), payload length: %d", gre.Protocol, len(gre.Payload))
		}
		return parseERSPANType3(gre.Payload, originalPacket)

	case 0x88BE: // ERSPAN Type I or II
		// Type II has a sequence number, Type I does not.
		if gre.SeqPresent { // ERSPAN Type II
			if *debug {
				loggerDebug.Printf("Processing GRE packet as ERSPAN Type II (Protocol: 0x%X), payload length: %d", gre.Protocol, len(gre.Payload))
			}
			return parseERSPANType2(gre.Payload, originalPacket)
		} else { // ERSPAN Type I
			if *debug {
				loggerDebug.Printf("Processing GRE packet as ERSPAN Type I (Protocol: 0x%X), payload length: %d", gre.Protocol, len(gre.Payload))
			}
			// Type I has no ERSPAN header. The payload is the mirrored frame.
			if len(gre.Payload) == 0 {
				if *debug {
					loggerDebug.Println("No inner payload for ERSPAN Type I")
				}
				return nil, nil
			}

			// For Type I, we can't get SpanID or VLAN from a header.
			// We create minimal metadata.
			metadata := &ERSPANMetadata{
				Version:   1, // Representing Type I
				SpanID:    0, // Not available
				VLAN:      0, // Not available
				Direction: 0, // Not applicable
				Timestamp: 0, // Not available
			}

			// Create inner packet with proper CaptureInfo
			innerPacket := gopacket.NewPacket(gre.Payload, layers.LayerTypeEthernet, gopacket.Default)
			if innerPacket.ErrorLayer() != nil {
				if *debug {
					loggerDebug.Printf("Error parsing inner packet for ERSPAN Type I: %v", innerPacket.ErrorLayer().Error())
				}
				return nil, nil
			}
			
			// Fix CaptureInfo to match actual data length and preserve timestamp
			payloadLen := len(gre.Payload)
			innerPacket.Metadata().CaptureInfo.CaptureLength = payloadLen
			innerPacket.Metadata().CaptureInfo.Length = payloadLen
			innerPacket.Metadata().Timestamp = originalPacket.Metadata().Timestamp
			
			if *debug {
				loggerDebug.Printf("Successfully parsed ERSPAN Type I packet, inner payload: %d bytes", payloadLen)
				loggerDebug.Printf("ERSPAN Type I - Fixed CaptureInfo: CaptureLength=%d, Length=%d, DataLength=%d",
					innerPacket.Metadata().CaptureInfo.CaptureLength,
					innerPacket.Metadata().CaptureInfo.Length,
					len(innerPacket.Data()))
			}
			return innerPacket, metadata
		}
	default:
		if *debug {
			loggerDebug.Printf("Non-ERSPAN GRE packet (Protocol: 0x%X), payload length: %d", gre.Protocol, len(gre.Payload))
		}
		return nil, nil
	}
}

// parseERSPANType2 parses ERSPAN Type II header (8 bytes)
func parseERSPANType2(payload []byte, originalPacket gopacket.Packet) (gopacket.Packet, *ERSPANMetadata) {
	if len(payload) < 8 {
		if *debug {
			loggerDebug.Printf("ERSPAN Type II payload too short: %d bytes", len(payload))
		}
		return nil, nil
	}

	// Parse ERSPAN Type II header
	// Byte 0-1: Version(4) + VLAN(12)
	word0 := binary.BigEndian.Uint16(payload[0:2])
	version := uint8((word0 >> 12) & 0x0F)
	if version != 1 {
		if *debug {
			loggerDebug.Printf("Invalid ERSPAN Type II version: %d", version)
		}
		return nil, nil
	}
	vlan := word0 & 0x0FFF

	// Byte 2-3: COS(3) + Encap(2) + T(1) + Session ID(10)
	word1 := binary.BigEndian.Uint16(payload[2:4])
	cos := uint8((word1 >> 13) & 0x07)
	encap := uint8((word1 >> 11) & 0x03)
	truncated := (word1 & 0x0400) != 0
	spanID := word1 & 0x03FF

	// Byte 4-7: Reserved(12) + Index(20)
	word2 := binary.BigEndian.Uint32(payload[4:8])
	reserved := uint8((word2 >> 20) & 0x0FFF)
	index := word2 & 0x0FFFFF

	if *debug {
		loggerDebug.Printf("ERSPAN Type II - Version: %d, VLAN: %d, COS: %d, Encap: %d, Truncated: %t, SpanID: %d, Reserved: %d, Index: %d",
			version, vlan, cos, encap, truncated, spanID, reserved, index)
	}

	// Create metadata
	metadata := &ERSPANMetadata{
		Version:   version,
		SpanID:    spanID,
		VLAN:      vlan,
		Direction: 0, // Type II doesn't have direction info
		Timestamp: 0, // Type II doesn't have timestamp in header
	}

	// Extract inner packet (skip 8-byte ERSPAN header)
	innerPayload := payload[8:]
	if len(innerPayload) == 0 {
		if *debug {
			loggerDebug.Println("No inner payload after ERSPAN Type II header")
		}
		return nil, nil
	}

	// Parse inner packet as Ethernet frame
	innerPacket := gopacket.NewPacket(innerPayload, layers.LayerTypeEthernet, gopacket.Default)
	if innerPacket.ErrorLayer() != nil {
		if *debug {
			loggerDebug.Printf("Error parsing inner packet: %v", innerPacket.ErrorLayer().Error())
		}
		return nil, nil
	}

	// Fix CaptureInfo to match actual data length and preserve timestamp
	payloadLen := len(innerPayload)
	innerPacket.Metadata().CaptureInfo.CaptureLength = payloadLen
	innerPacket.Metadata().CaptureInfo.Length = payloadLen
	innerPacket.Metadata().Timestamp = originalPacket.Metadata().Timestamp

	if *debug {
		loggerDebug.Printf("Successfully parsed ERSPAN Type II packet, inner payload: %d bytes", payloadLen)
	}

	return innerPacket, metadata
}

// parseERSPANType3 parses ERSPAN Type III header (12 bytes)
func parseERSPANType3(payload []byte, originalPacket gopacket.Packet) (gopacket.Packet, *ERSPANMetadata) {
	if len(payload) < 12 {
		if *debug {
			loggerDebug.Printf("ERSPAN Type III payload too short: %d bytes", len(payload))
		}
		return nil, nil
	}

	// Parse ERSPAN Type III header
	// Byte 0-1: Version(4) + VLAN(12)
	word0 := binary.BigEndian.Uint16(payload[0:2])
	version := uint8((word0 >> 12) & 0x0F)
	if version != 2 {
		if *debug {
			loggerDebug.Printf("Invalid ERSPAN Type III version: %d", version)
		}
		return nil, nil
	}
	vlan := word0 & 0x0FFF

	// Byte 2-3: COS(3) + BSO(2) + T(1) + Session ID(10)
	word1 := binary.BigEndian.Uint16(payload[2:4])
	cos := uint8((word1 >> 13) & 0x07)
	bso := uint8((word1 >> 11) & 0x03)
	truncated := (word1 & 0x0400) != 0
	spanID := word1 & 0x03FF

	// Byte 4-7: Timestamp(32)
	timestamp := binary.BigEndian.Uint32(payload[4:8])

	// Byte 8-9: SGT(16)
	sgt := binary.BigEndian.Uint16(payload[8:10])

	// Byte 10-11: P(1) + FT(5) + HW(6) + D(1) + GRA(2) + O(1)
	word3 := binary.BigEndian.Uint16(payload[10:12])
	p := (word3 & 0x8000) != 0
	ft := uint8((word3 >> 10) & 0x1F)
	hw := uint8((word3 >> 4) & 0x3F)
	direction := uint8((word3 >> 3) & 0x01)
	gra := uint8((word3 >> 1) & 0x03)
	options := uint8(word3 & 0x01)

	if *debug {
		loggerDebug.Printf("ERSPAN Type III - Version: %d, VLAN: %d, COS: %d, BSO: %d, Truncated: %t, SpanID: %d",
			version, vlan, cos, bso, truncated, spanID)
		loggerDebug.Printf("ERSPAN Type III - Timestamp: %d, SGT: %d, P: %t, FT: %d, HW: %d, Direction: %d, GRA: %d, Options: %d",
			timestamp, sgt, p, ft, hw, direction, gra, options)
	}

	// Create metadata
	metadata := &ERSPANMetadata{
		Version:   version,
		SpanID:    spanID,
		VLAN:      vlan,
		Direction: direction,
		Timestamp: timestamp,
	}

	// Extract inner packet (skip 12-byte ERSPAN header and optional subheader)
	headerSize := 12
	if options == 1 {
		headerSize += 8
		if len(payload) < headerSize {
			if *debug {
				loggerDebug.Printf("ERSPAN Type III payload with optional subheader too short: %d bytes, expected at least %d", len(payload), headerSize)
			}
			return nil, nil
		}
	}
	innerPayload := payload[headerSize:]
	if len(innerPayload) == 0 {
		if *debug {
			loggerDebug.Println("No inner payload after ERSPAN Type III header")
		}
		return nil, nil
	}

	// Parse inner packet as Ethernet frame
	innerPacket := gopacket.NewPacket(innerPayload, layers.LayerTypeEthernet, gopacket.Default)
	if innerPacket.ErrorLayer() != nil {
		if *debug {
			loggerDebug.Printf("Error parsing inner packet: %v", innerPacket.ErrorLayer().Error())
		}
		return nil, nil
	}

	// Fix CaptureInfo to match actual data length and preserve timestamp
	payloadLen := len(innerPayload)
	innerPacket.Metadata().CaptureInfo.CaptureLength = payloadLen
	innerPacket.Metadata().CaptureInfo.Length = payloadLen
	innerPacket.Metadata().Timestamp = originalPacket.Metadata().Timestamp

	if *debug {
		loggerDebug.Printf("Successfully parsed ERSPAN Type III packet, inner payload: %d bytes", payloadLen)
	}

	return innerPacket, metadata
}

// shouldProcessERSPANPacket checks if ERSPAN packet should be processed based on filters
func shouldProcessERSPANPacket(metadata *ERSPANMetadata) bool {
	// Check SPAN ID filter
	if *erspanSpanIDs != "" {
		allowedSpanIDs := parseCommaSeparatedUint16(*erspanSpanIDs)
		if len(allowedSpanIDs) > 0 {
			found := false
			for _, allowedID := range allowedSpanIDs {
				if metadata.SpanID == allowedID {
					found = true
					break
				}
			}
			if !found {
				if *debug {
					loggerDebug.Printf("ERSPAN packet filtered out by SPAN ID filter (SpanID: %d)", metadata.SpanID)
				}
				return false
			}
		}
	}

	// Check VLAN filter
	if *erspanVLANs != "" {
		allowedVLANs := parseCommaSeparatedUint16(*erspanVLANs)
		if len(allowedVLANs) > 0 {
			found := false
			for _, allowedVLAN := range allowedVLANs {
				if metadata.VLAN == allowedVLAN {
					found = true
					break
				}
			}
			if !found {
				if *debug {
					loggerDebug.Printf("ERSPAN packet filtered out by VLAN filter (VLAN: %d)", metadata.VLAN)
				}
				return false
			}
		}
	}

	return true
}

// parseCommaSeparatedUint16 parses comma-separated uint16 values
func parseCommaSeparatedUint16(input string) []uint16 {
	if input == "" {
		return nil
	}

	parts := splitAndTrim(input, ",")
	result := make([]uint16, 0, len(parts))

	for _, part := range parts {
		if part == "" {
			continue
		}
		
		// Parse as uint16
		var value uint64
		var err error
		if len(part) > 2 && part[:2] == "0x" {
			// Hex format
			value, err = parseUint(part[2:], 16, 16)
		} else {
			// Decimal format
			value, err = parseUint(part, 10, 16)
		}
		
		if err != nil {
			loggerInfo.Printf("Warning: Invalid number '%s' in comma-separated list, skipping", part)
			continue
		}
		
		result = append(result, uint16(value))
	}

	return result
}

// Helper function to parse uint (avoiding strconv import conflicts)
func parseUint(s string, base int, bitSize int) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty string")
	}
	
	var result uint64
	var err error
	
	switch base {
	case 10:
		for _, r := range s {
			if r < '0' || r > '9' {
				return 0, fmt.Errorf("invalid decimal digit")
			}
			result = result*10 + uint64(r-'0')
			if bitSize == 16 && result > 65535 {
				return 0, fmt.Errorf("value out of range")
			}
		}
	case 16:
		for _, r := range s {
			var digit uint64
			if r >= '0' && r <= '9' {
				digit = uint64(r - '0')
			} else if r >= 'a' && r <= 'f' {
				digit = uint64(r - 'a' + 10)
			} else if r >= 'A' && r <= 'F' {
				digit = uint64(r - 'A' + 10)
			} else {
				return 0, fmt.Errorf("invalid hex digit")
			}
			result = result*16 + digit
			if bitSize == 16 && result > 65535 {
				return 0, fmt.Errorf("value out of range")
			}
		}
	default:
		return 0, fmt.Errorf("unsupported base")
	}
	
	return result, err
}

// Helper function to split and trim strings
func splitAndTrim(s, sep string) []string {
	if s == "" {
		return nil
	}
	
	parts := make([]string, 0)
	current := ""
	
	for _, r := range s {
		if string(r) == sep {
			trimmed := trimSpace(current)
			if trimmed != "" {
				parts = append(parts, trimmed)
			}
			current = ""
		} else {
			current += string(r)
		}
	}
	
	// Add the last part
	trimmed := trimSpace(current)
	if trimmed != "" {
		parts = append(parts, trimmed)
	}
	
	return parts
}

// Helper function to trim whitespace
func trimSpace(s string) string {
	start := 0
	end := len(s)
	
	// Trim leading whitespace
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	
	// Trim trailing whitespace
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	
	return s[start:end]
}