package main

import (
	"fmt"
	"math"
	"strconv"
	"time"
)

// calculateAndWriteRTPStats calculates derived RTP statistics and writes them to the stats CSV.
func calculateAndWriteRTPStats(call *Call, callEndTime time.Time) {
	if statsCSV == nil { // statsCSV is from csv_handler.go
		loggerInfo.Printf("CallID: %s - Statistics CSV writer not initialized. Skipping stats.", call.CallID)
		return
	}

	if call.StartTime.IsZero() {
		loggerInfo.Printf("CallID: %s - Call start_time missing. Cannot calculate duration-based stats.", call.CallID)
		return
	}

	callDurationSeconds := callEndTime.Sub(call.StartTime).Seconds()
	if callDurationSeconds < 0 {
		callDurationSeconds = 0 // Should not happen, but as a safeguard
	}

	if len(call.RTPStreams) == 0 && *debug {
		loggerDebug.Printf("CallID: %s - No RTP streams recorded for this call.", call.CallID)
	}

	for ssrc, streamStats := range call.RTPStreams {
		if streamStats.RTPPacketCount == 0 {
			if *debug {
				loggerDebug.Printf("CallID: %s, SSRC: 0x%x - No RTP packets. Skipping stats row for this SSRC.", call.CallID, ssrc)
			}
			continue
		}

		// Calculate Min/Max/Avg Delta
		if len(streamStats.DeltasMs) > 0 {
			// Min/Max are already tracked during packet processing if MinDeltaMs was initialized correctly
			// If MinDeltaMs was -1 and MaxDeltaMs was 0, they'd be updated.
			// Let's re-calculate Avg here.
			var sumDeltaMs float64
			for _, delta := range streamStats.DeltasMs {
				sumDeltaMs += delta
			}
			streamStats.AvgDeltaMs = sumDeltaMs / float64(len(streamStats.DeltasMs))
		} else {
			streamStats.MinDeltaMs = 0.0 // If no deltas (e.g. 1 packet), set to 0
			streamStats.MaxDeltaMs = 0.0
			streamStats.AvgDeltaMs = 0.0
		}
		// Ensure MinDelta is not -1 if there were packets but no deltas (1 packet case)
		if streamStats.RTPPacketCount > 0 && streamStats.MinDeltaMs == -1.0 {
		    streamStats.MinDeltaMs = 0.0
		}


		// Calculate Expected RTP Packets
		ptimeMs := call.SDPPtime // Default is 20ms, updated from SDP
		if ptimeMs <= 0 {    // Prevent division by zero or negative ptime
			ptimeMs = 20 // Fallback to default if invalid ptime from SDP
		}
		if callDurationSeconds > 0 {
			streamStats.ExpectedRTPPackets = uint64(math.Round((callDurationSeconds * 1000) / float64(ptimeMs)))
		} else {
			streamStats.ExpectedRTPPackets = 0
		}

		// Calculate Lost Packets (based on sequence numbers)
		// This is a simplified calculation. More advanced methods consider jitter buffer and reordering tolerance.
		numUniqueReceived := uint64(len(streamStats.ReceivedSeqNums))
		if numUniqueReceived > 0 && streamStats.MaxSeqNumSeen != -1 && streamStats.ExpectedMinSeqNum != -1 {
			var expectedRangeCount uint64
			// Handle wrap-around for sequence numbers (uint16)
			if streamStats.MaxSeqNumSeen >= streamStats.ExpectedMinSeqNum {
				expectedRangeCount = uint64(streamStats.MaxSeqNumSeen - streamStats.ExpectedMinSeqNum + 1)
			} else { // Wrapped around
				expectedRangeCount = uint64((math.MaxUint16 - uint16(streamStats.ExpectedMinSeqNum) + 1) + uint16(streamStats.MaxSeqNumSeen) + 1)
			}
			
			if expectedRangeCount > numUniqueReceived {
				streamStats.LostPackets = expectedRangeCount - numUniqueReceived
			} else {
				streamStats.LostPackets = 0 // Can happen if duplicates fill gaps or seq numbers are very sparse
			}
		} else {
			streamStats.LostPackets = 0
		}
		
		// Out-of-order and duplicate counts are accumulated during packet processing.

		record := []string{
			call.CallID,
			call.StartTime.Format(time.RFC3339),
			call.OutputFilename,
			call.SIPFrom,
			call.SIPTo,
			fmt.Sprintf("0x%08x", ssrc),
			streamStats.SrcRTPEndpoint,
			streamStats.DstRTPEndpoint,
			strconv.FormatUint(streamStats.RTPPacketCount, 10),
			strconv.FormatUint(streamStats.ExpectedRTPPackets, 10),
			strconv.FormatUint(streamStats.LostPackets, 10),
			strconv.FormatUint(streamStats.OutOfOrderCount, 10),
			strconv.FormatUint(streamStats.DuplicateCount, 10),
			fmt.Sprintf("%.2f", streamStats.MaxDeltaMs),
			fmt.Sprintf("%.2f", streamStats.MinDeltaMs),
			fmt.Sprintf("%.2f", streamStats.AvgDeltaMs),
			strconv.Itoa(ptimeMs),
		}
		if err := statsCSV.Write(record); err != nil {
			loggerInfo.Printf("CallID: %s, SSRC: 0x%x - Error writing stats to CSV: %v", call.CallID, ssrc, err)
		}
	}
	statsCSV.Flush() // Flush after processing all SSRCs for a call
}