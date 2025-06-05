package main

import (
	"time"
)

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
				delete(activeCalls, callID)
				loggerInfo.Printf("CallID: %s - Removed due to inactivity.", callID)
			}
		}
		activeCallsMutex.Unlock()
	}
}