package main

import (
	"fmt"
	"strconv"

	"github.com/google/gopacket"
)

// handleRtpPacket processes a packet identified as UDP and potentially RTP.
func handleRtpPacket(packet gopacket.Packet, rtpPayload []byte, ipSrc, ipDst string, srcPort, dstPort uint16) {
	activeCallsMutex.RLock() // Start with a read lock to find the call

	var matchedCall *Call
	var rtpDestIPMatched, rtpDestPortMatchedStr string

	for _, call := range activeCalls {
		for _, mediaSession := range call.MediaSessions {
			if (ipDst == mediaSession.IPAddress && dstPort == mediaSession.Port) ||
				(ipSrc == mediaSession.IPAddress && srcPort == mediaSession.Port) {
				matchedCall = call
				rtpDestIPMatched = mediaSession.IPAddress
				rtpDestPortMatchedStr = strconv.Itoa(int(mediaSession.Port))
				goto FoundCallForRTP // Break out of both loops
			}
		}
	}
FoundCallForRTP:
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
	if currentCallState.PcapWriter != nil { // Check PcapWriter, not PcapFile, as PcapFile might be closed by SIP BYE
		errWrite := currentCallState.PcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if errWrite != nil {
			loggerInfo.Printf("Error writing RTP packet to PCAP for call %s (file %s): %v", currentCallState.CallID, currentCallState.OutputFilename, errWrite)
		}
	}
	currentCallState.LastActivityTime = packet.Metadata().Timestamp

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