package main

import (
	"time"
)

// removeMediaSessionsFromGlobalMap removes all media sessions of a call from the global map
func removeMediaSessionsFromGlobalMap(call *Call) {
	activeMediaSessionsMutex.Lock()
	defer activeMediaSessionsMutex.Unlock()
	for _, session := range call.MediaSessions {
		lookupKey := MediaSessionKey{IP: session.IPAddress, Port: session.Port}
		delete(activeMediaSessions, lookupKey)
		if *debug {
			loggerDebug.Printf("CallID: %s - Removed media session from global map: %s:%d", call.CallID, session.IPAddress, session.Port)
		}
	}
}

// monitorInactiveCalls periodically checks for calls that have timed out.
func monitorInactiveCalls() {
	if globalCallTimeout <= 0 {
		loggerInfo.Println("Call timeout monitoring is disabled (timeout <= 0).")
		return
	}
	loggerInfo.Printf("Starting inactive call monitor with timeout: %s", globalCallTimeout.String())
	
	// Ticker for periodic checks. Adjust the interval as needed.
	// A shorter interval means more responsive cleanup but more frequent locking.
	ticker := time.NewTicker(globalCallTimeout / 2) // Check at half the timeout duration
	defer ticker.Stop()

	for range ticker.C {
		activeCallsMutex.Lock() // Need a write lock to potentially delete calls
		now := time.Now()
		
		if *debug && len(activeCalls) > 0 {
			loggerDebug.Printf("Call Timeout Monitor: Checking %d active calls for inactivity...", len(activeCalls))
		}

		for callID, call := range activeCalls {
			if now.Sub(call.LastActivityTime) > globalCallTimeout {
				loggerInfo.Printf("CallID: %s - Timed out after %s of inactivity. Last activity: %s",
					callID, globalCallTimeout.String(), call.LastActivityTime.Format(time.RFC3339))

				// Calculate stats before closing
				calculateAndWriteRTPStats(call, call.LastActivityTime) // Use LastActivityTime as call end time for timeout

				// Update database with timeout state and final RTP stats
				rtpStatsJSON := ConvertRTPStreamsToJSON(call.RTPStreams, call)
				var s3Location string
				if s3ParamsProvidedForCsv && *autoUploadToS3 {
					s3Location = constructS3Location(*s3URI, call.OutputFilename)
				}
				UpdateCallInDatabase(call.CallID, call.SIPFrom, call.SIPTo, s3Location, rtpStatsJSON, &call.LastActivityTime, CallStateTimedOut)

				// Close PCAP file
				if call.PcapFile != nil {
					if err := call.PcapFile.Close(); err != nil {
						loggerInfo.Printf("CallID: %s - Error closing PCAP file on timeout: %v", callID, err)
					} else {
						loggerDebug.Printf("CallID: %s - Closed PCAP file on timeout: %s", callID, call.OutputFilename)
					}
					call.PcapWriter = nil
					call.PcapFile = nil
					
					// Handle S3 upload and local file cleanup
					processS3UploadAndCleanup(call.OutputFilename, *outputDir)
				}
				removeMediaSessionsFromGlobalMap(call) // Clean up media sessions from global map
				delete(activeCalls, callID)
				loggerInfo.Printf("CallID: %s - Removed due to inactivity.", callID)
			}
		}
		activeCallsMutex.Unlock()
	}
}