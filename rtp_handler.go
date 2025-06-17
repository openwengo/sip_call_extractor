package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/google/gopacket"
)

// shouldClearPayloadForCall determines whether RTP payload should be cleared
// for the given call based on CLI flags and regex patterns.
func shouldClearPayloadForCall(call *Call) bool {

	// Priority 1: Global Dump Rule - if --no-rtp-dump is true, CLEAR
	if *noRtpDump {
		return true
	}
	
	// Priority 2: "Except-For" (Preservation) Rule - if any except-for pattern matches, DO NOT clear
	if noRtpDumpExceptForCallIdRegexp != nil && noRtpDumpExceptForCallIdRegexp.MatchString(call.CallID) {
		loggerDebug.Printf("Dump rtp for call %s because %s matches %s", call.CallID,noRtpDumpExceptForCallIdRegexp.String(),call.CallID)
		return false
	}
	if noRtpDumpExceptForFromRegexp != nil && noRtpDumpExceptForFromRegexp.MatchString(call.SIPFrom) {
		loggerDebug.Printf("Dump rtp for call %s because %s matches %s", call.CallID,noRtpDumpExceptForFromRegexp.String(),call.SIPFrom)
		return false
	}
	if noRtpDumpExceptForToRegexp != nil && noRtpDumpExceptForToRegexp.MatchString(call.SIPTo) {
		loggerDebug.Printf("Dump rtp for call %s because %s matches %s", call.CallID,noRtpDumpExceptForToRegexp.String(),call.SIPTo)
		return false
	}
	
	// Priority 3: "For" (Targeted Dump) Rule - if any for pattern matches, CLEAR
	if noRtpDumpForCallIdRegexp != nil && noRtpDumpForCallIdRegexp.MatchString(call.CallID) {
		return true
	}
	if noRtpDumpForFromRegexp != nil && noRtpDumpForFromRegexp.MatchString(call.SIPFrom) {
		loggerDebug.Printf("Don't dump rtp for call %s because %s  matches %s", call.CallID,noRtpDumpForFromRegexp.String(),call.SIPFrom)
		return true
	}
	if noRtpDumpForToRegexp != nil && noRtpDumpForToRegexp.MatchString(call.SIPTo) {
		loggerDebug.Printf("Don't dump rtp for call %s because %s  matches %s", call.CallID,noRtpDumpForToRegexp.String(),call.SIPTo)
		return true
	}
	
	// Priority 4: "Except-For" (Implicit Dump) Rule - if except-for pattern was provided but NOT matched, CLEAR
	if *noRtpDumpExceptForCallIdPattern != "" && (noRtpDumpExceptForCallIdRegexp == nil || !noRtpDumpExceptForCallIdRegexp.MatchString(call.CallID)) {
		return true
	}
	if *noRtpDumpExceptForFromPattern != "" && (noRtpDumpExceptForFromRegexp == nil || !noRtpDumpExceptForFromRegexp.MatchString(call.SIPFrom)) {
		loggerDebug.Printf("Don't dump rtp for call %s because %s  does not matches %s", call.CallID,noRtpDumpExceptForFromRegexp.String(),call.SIPFrom)
		return true
	}
	if *noRtpDumpExceptForToPattern != "" && (noRtpDumpExceptForToRegexp == nil || !noRtpDumpExceptForToRegexp.MatchString(call.SIPTo)) {
		loggerDebug.Printf("Don't dump rtp for call %s because %s  does not matches %s", call.CallID,noRtpDumpExceptForToRegexp.String(),call.SIPTo)		
		return true
	}
	
	// Priority 5: Default - DO NOT clear
	return false
}

// clearRtpPayload clears the media payload from an RTP packet while preserving headers
func clearRtpPayload(rtpPayload []byte, callID string) {
	if len(rtpPayload) < 12 { // Minimum RTP header size
		if *debug {
			loggerDebug.Printf("CallID: %s - RTP packet too short (%d bytes) for payload clearing", callID, len(rtpPayload))
		}
		return
	}
	
	// Parse RTP header
	csrcCount := int(rtpPayload[0] & 0x0F)
	hasPadding := (rtpPayload[0]>>5)&0x01 == 1
	hasExtension := (rtpPayload[0]>>4)&0x01 == 1
	
	rtpHeaderBaseSize := 12 + csrcCount*4
	payloadOffset := rtpHeaderBaseSize
	
	if len(rtpPayload) < payloadOffset {
		if *debug {
			loggerDebug.Printf("CallID: %s - RTP packet too short (%d bytes) for header size %d", callID, len(rtpPayload), rtpHeaderBaseSize)
		}
		return
	}
	
	// Handle extension header if present
	if hasExtension {
		if len(rtpPayload) < payloadOffset+4 {
			if *debug {
				loggerDebug.Printf("CallID: %s - RTP packet too short for extension header", callID)
			}
			return
		}
		// Extension header: 2 bytes for ID, 2 bytes for length (in 32-bit words)
		extensionLengthInWords := uint16(rtpPayload[payloadOffset+2])<<8 | uint16(rtpPayload[payloadOffset+3])
		totalExtensionLengthBytes := (int(extensionLengthInWords) + 1) * 4 // +1 because length is N words *following* the first word
		payloadOffset += totalExtensionLengthBytes
	}
	
	if payloadOffset > len(rtpPayload) {
		if *debug {
			loggerDebug.Printf("CallID: %s - RTP payload offset (%d) is beyond packet length (%d) after processing headers", callID, payloadOffset, len(rtpPayload))
		}
		return
	}
	
	// Determine actual payload start and end, considering padding
	actualMediaPayloadEnd := len(rtpPayload)
	if hasPadding {
		if actualMediaPayloadEnd > 0 {
			paddingLength := int(rtpPayload[len(rtpPayload)-1])
			if paddingLength > 0 && paddingLength <= (actualMediaPayloadEnd-payloadOffset) {
				actualMediaPayloadEnd -= paddingLength
			} else if *debug {
				loggerDebug.Printf("CallID: %s - Invalid RTP padding length: %d", callID, paddingLength)
			}
		}
	}
	
	if payloadOffset < actualMediaPayloadEnd {
		actualMediaPayload := rtpPayload[payloadOffset:actualMediaPayloadEnd]
		for i := range actualMediaPayload {
			actualMediaPayload[i] = 0
		}
		if *debug {
			loggerDebug.Printf("CallID: %s - Cleared RTP payload (%d bytes) due to privacy rules", callID, len(actualMediaPayload))
		}
	} else if *debug && payloadOffset == actualMediaPayloadEnd {
		loggerDebug.Printf("CallID: %s - RTP packet has no media payload to clear (offset %d, end %d)", callID, payloadOffset, actualMediaPayloadEnd)
	} else if *debug {
		loggerDebug.Printf("CallID: %s - RTP payload offset (%d) is beyond actual payload end (%d) after processing headers/padding", callID, payloadOffset, actualMediaPayloadEnd)
	}
}

// trackERSPANSessionRTP tracks ERSPAN session information for RTP packets
func trackERSPANSessionRTP(call *Call, erspanMeta *ERSPANMetadata, timestamp time.Time) {
	if erspanMeta == nil {
		return
	}
	
	spanID := erspanMeta.SpanID
	if session, exists := call.ERSPANSessions[spanID]; exists {
		// Update existing session
		session.PacketCount++
		if *logERSPANStats && *debug {
			loggerDebug.Printf("Updated ERSPAN session %d for call %s (RTP): PacketCount=%d",
				spanID, call.CallID, session.PacketCount)
		}
	} else {
		// Create new session
		call.ERSPANSessions[spanID] = &ERSPANSessionInfo{
			SpanID:      spanID,
			VLAN:        erspanMeta.VLAN,
			Version:     erspanMeta.Version,
			FirstSeen:   timestamp,
			PacketCount: 1,
		}
		if *logERSPANStats {
			loggerInfo.Printf("New ERSPAN session %d for call %s (RTP): Version=%d, VLAN=%d",
				spanID, call.CallID, erspanMeta.Version, erspanMeta.VLAN)
		}
	}
}

// handleRtpPacket processes a packet identified as UDP and potentially RTP.
func handleRtpPacket(packet gopacket.Packet, rtpPayload []byte, ipSrc, ipDst string, srcPort, dstPort uint16, erspanMeta *ERSPANMetadata) {
	activeCallsMutex.RLock() // Start with a read lock to find the call

	var matchedCall *Call
	var rtpDestIPMatched, rtpDestPortMatchedStr string

	// Efficiently find the call using the global media session map
	lookupKeyDst := fmt.Sprintf("%s:%d", ipDst, dstPort)
	lookupKeySrc := fmt.Sprintf("%s:%d", ipSrc, srcPort)

	activeMediaSessionsMutex.RLock()
	call, found := activeMediaSessions[lookupKeyDst]
	if found {
		matchedCall = call
		rtpDestIPMatched = ipDst
		rtpDestPortMatchedStr = strconv.Itoa(int(dstPort))
	} else {
		call, found = activeMediaSessions[lookupKeySrc]
		if found {
			matchedCall = call
			rtpDestIPMatched = ipSrc
			rtpDestPortMatchedStr = strconv.Itoa(int(srcPort))
		}
	}
	activeMediaSessionsMutex.RUnlock()
	activeCallsMutex.RUnlock() // Release read lock after iteration

	if matchedCall == nil {
		return // No call matched
	}

	// Acquire a write lock to modify the matched call's state
	activeCallsMutex.Lock()
	// Re-check if the call still exists after acquiring the write lock
	currentCallState, stillExists := activeCalls[matchedCall.CallID]
	if !stillExists {
		activeCallsMutex.Unlock() // Release write lock if call is gone
		if *debug {               // *debug is from cli.go
			loggerDebug.Printf("CallID: %s - Matched RTP but call disappeared before write lock.", matchedCall.CallID)
		}
		return
	}
	// Ensure the write lock is released when this function scope exits
	defer activeCallsMutex.Unlock()


	// --- Process RTP for currentCallState ---
	
	if currentCallState.ShouldClearPayload {
		loggerDebug.Printf("Do not dump rtp for call %s", currentCallState.CallID)
	} else {
		loggerDebug.Printf("Dump rtp for call %s", currentCallState.CallID)
	}

	// Check if RTP payload should be cleared for privacy before writing packet
	if !currentCallState.ShouldClearPayload && currentCallState.PcapWriter != nil { // Check PcapWriter, not PcapFile, as PcapFile might be closed by SIP BYE
		errWrite := currentCallState.PcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if errWrite != nil {
			loggerInfo.Printf("Error writing RTP packet to PCAP for call %s (file %s): %v", currentCallState.CallID, currentCallState.OutputFilename, errWrite)
		}
	}
	currentCallState.LastActivityTime = packet.Metadata().Timestamp
	
	// Track ERSPAN session if metadata is available
	//trackERSPANSessionRTP(currentCallState, erspanMeta, packet.Metadata().Timestamp)

	if len(rtpPayload) < 12 { // Basic RTP header is 12 bytes
		if *debug {
			loggerDebug.Printf("CallID: %s - RTP payload too short (%d bytes)", currentCallState.CallID, len(rtpPayload))
		}
		return // Mutex will be unlocked by defer
	}

	version := (rtpPayload[0] >> 6) & 0x03
	if version != 2 {
		if *debug {
			loggerDebug.Printf("CallID: %s - Not RTP version 2 (version: %d)", currentCallState.CallID, version)
		}
		return // Mutex will be unlocked by defer
	}

	seqNum := uint16(rtpPayload[2])<<8 | uint16(rtpPayload[3])
	// rtpTimestamp := uint32(rtpPayload[4])<<24 | uint32(rtpPayload[5])<<16 | uint32(rtpPayload[6])<<8 | uint32(rtpPayload[7])
	ssrc := uint32(rtpPayload[8])<<24 | uint32(rtpPayload[9])<<16 | uint32(rtpPayload[10])<<8 | uint32(rtpPayload[11])

	if *debug {
		loggerDebug.Printf("CallID: %s - RTP Packet: %s:%d -> %s:%d (Matched Media: %s:%s) SSRC:0x%x, Seq:%d",
			currentCallState.CallID, ipSrc, srcPort, ipDst, dstPort, rtpDestIPMatched, rtpDestPortMatchedStr, ssrc, seqNum)
	}

	streamStats, statsExists := currentCallState.RTPStreams[ssrc]
	if !statsExists {
		streamStats = &RTPStreamStats{
			SrcRTPEndpoint:    fmt.Sprintf("%s:%d", ipSrc, srcPort),
			DstRTPEndpoint:    fmt.Sprintf("%s:%d", ipDst, dstPort),
			MinDeltaMs:        -1.0, 
			LastSeqNum:        -1,   
			MaxSeqNumSeen:     -1,   
			ExpectedMinSeqNum: -1,   
			ReceivedSeqNums:   make(map[uint16]struct{}),
			DeltasMs:          make([]float64, 0, 1024), 
		}
		currentCallState.RTPStreams[ssrc] = streamStats
		if *debug {
			loggerDebug.Printf("CallID: %s - New RTP stream SSRC: 0x%x (%s -> %s)", currentCallState.CallID, ssrc, streamStats.SrcRTPEndpoint, streamStats.DstRTPEndpoint)
		}
	}

	streamStats.RTPPacketCount++
	currentTime := packet.Metadata().Timestamp

	if !streamStats.LastArrivalTime.IsZero() {
		delta := currentTime.Sub(streamStats.LastArrivalTime).Seconds() * 1000 // ms
		streamStats.DeltasMs = append(streamStats.DeltasMs, delta)
		if streamStats.MinDeltaMs == -1.0 || delta < streamStats.MinDeltaMs {
			streamStats.MinDeltaMs = delta
		}
		if delta > streamStats.MaxDeltaMs { 
			streamStats.MaxDeltaMs = delta
		}
	}
	streamStats.LastArrivalTime = currentTime

	isFirstPacketForSSRC := (streamStats.ExpectedMinSeqNum == -1)
	if isFirstPacketForSSRC {
		streamStats.ExpectedMinSeqNum = int16(seqNum)
		streamStats.MaxSeqNumSeen = int16(seqNum) 
	}

	if _, isDuplicate := streamStats.ReceivedSeqNums[seqNum]; isDuplicate {
		streamStats.DuplicateCount++
	} else {
		streamStats.ReceivedSeqNums[seqNum] = struct{}{}
		if !isFirstPacketForSSRC && int16(seqNum) < streamStats.MaxSeqNumSeen && (streamStats.MaxSeqNumSeen-int16(seqNum) < 0x7FFF) { 
			streamStats.OutOfOrderCount++
		}
	}
	
	// Update MaxSeqNumSeen to track the "latest" sequence number cyclically
	if streamStats.MaxSeqNumSeen == -1 { // First packet for this SSRC
		streamStats.MaxSeqNumSeen = int16(seqNum)
	} else {
		// Cast to int32 for subtraction to handle wrap-around correctly over int16
		diff := int32(seqNum) - int32(streamStats.MaxSeqNumSeen)
		const halfUint16Range int32 = 0x7FFF // MaxInt16 / 2 roughly, or 32767

		if diff > 0 {
			// seqNum is numerically greater than MaxSeqNumSeen.
			// This covers normal advancement (e.g., 100 -> 101)
			// AND wrap-around from a low MaxSeqNumSeen to a high seqNum (e.g., MaxSeqNumSeen=100, seqNum=65000).
			// In both these "forward progress" scenarios, update MaxSeqNumSeen.
			streamStats.MaxSeqNumSeen = int16(seqNum)
		} else if diff < 0 {
			// seqNum is numerically smaller than MaxSeqNumSeen.
			// This could be an out-of-order packet or a wrap-around from high MaxSeqNumSeen to low seqNum.
			// If -diff > halfUint16Range, it's a wrap (e.g., MaxSeqNumSeen=65000, seqNum=100).
			if -diff > halfUint16Range {
				streamStats.MaxSeqNumSeen = int16(seqNum)
			}
			// Else (it's a smaller, out-of-order packet, not a wrap), MaxSeqNumSeen remains unchanged.
		}
		// If diff == 0 (duplicate sequence number), MaxSeqNumSeen remains unchanged.
	}
	streamStats.LastSeqNum = int16(seqNum)
}