package main

import (
	"strconv"
	"strings"
)

// isDuplicateMediaSession checks if a media session already exists in the slice
func isDuplicateMediaSession(sessions []MediaSession, newSession MediaSession) bool {
	for _, existing := range sessions {
		if existing.IPAddress == newSession.IPAddress && existing.Port == newSession.Port {
			return true
		}
	}
	return false
}

// addMediaSessionToGlobalMap adds a media session to the global activeMediaSessions map
func addMediaSessionToGlobalMap(session MediaSession, call *Call) {
	lookupKey := MediaSessionKey{IP: session.IPAddress, Port: session.Port}
	activeMediaSessionsMutex.Lock()
	defer activeMediaSessionsMutex.Unlock()
	activeMediaSessions[lookupKey] = call
	if *debug {
		loggerDebug.Printf("CallID: %s - Added media session to global map: %s:%d", call.CallID, session.IPAddress, session.Port)
	}
}

// processMediaBlock parses a collected block of SDP lines (starting with m=)
// to extract media information, considering media-level c-lines and a=inactive.
// It updates newMediaSessions if an active media stream is found.
func processMediaBlock(blockLines []string, sessionIP string, newMediaSessions *[]MediaSession, call *Call) {
	if len(blockLines) == 0 {
		return
	}

	mLine := blockLines[0]
	mParts := strings.Fields(mLine)
	if len(mParts) < 2 {
		if *debug {
			loggerDebug.Printf("CallID: %s - SDP: Could not parse m-line: %s", call.CallID, mLine)
		}
		return
	}
	// mediaType := strings.Split(mParts[0], "=")[1] // e.g., "audio", useful for more detailed logging if needed
	portStr := mParts[1]
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		if *debug {
			loggerDebug.Printf("CallID: %s - SDP: Could not parse port from m-line: %s. Error: %v", call.CallID, mLine, err)
		}
		return
	}

	var mediaIP string // IP address specific to this media block
	isInactive := false

	// Iterate attributes and media-level c-line within the block (lines after m=)
	for _, line := range blockLines[1:] {
		if strings.HasPrefix(line, "c=IN IP4 ") {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) == 3 {
				mediaIP = strings.TrimSpace(parts[2])
				if *debug {
					loggerDebug.Printf("CallID: %s - SDP: Found media-level IP: %s for m-line: %s", call.CallID, mediaIP, mLine)
				}
			}
		} else if strings.HasPrefix(line, "a=inactive") {
			isInactive = true
			if *debug {
				loggerDebug.Printf("CallID: %s - SDP: Media stream is inactive (a=inactive found) for m-line: %s", call.CallID, mLine)
			}
			break // Stop processing attributes for this block if marked inactive
		}
	}

	if isInactive {
		return // Do not add inactive media sessions
	}

	effectiveIP := mediaIP
	if effectiveIP == "" { // If no media-level IP, use session-level IP
		effectiveIP = sessionIP
	}

	if effectiveIP == "" { // If still no IP, cannot proceed for this media stream
		if *debug {
			loggerDebug.Printf("CallID: %s - SDP: Skipping media session from m-line %s, no effective IP address found (sessionIP: '%s', mediaIP: '%s').", call.CallID, mLine, sessionIP, mediaIP)
		}
		return
	}

	newSession := MediaSession{IPAddress: effectiveIP, Port: uint16(port)}
	*newMediaSessions = append(*newMediaSessions, newSession)
	if *debug {
		loggerDebug.Printf("CallID: %s - SDP: Added active media session. IP: %s, Port: %d (from m-line: %s)", call.CallID, effectiveIP, port, mLine)
	}
}

// parseSDP parses SDP payload to extract media session information and ptime.
// It updates the call.MediaSessions and call.SDPPtime fields.
// This version processes SDP in blocks to correctly handle a=inactive.
func parseSDP(sdpPayload []byte, call *Call, isAnswer bool) {
	payloadStr := string(sdpPayload)
	// Normalize line endings to \n then split
	lines := strings.Split(strings.ReplaceAll(payloadStr, "\r\n", "\n"), "\n")

	var currentSessionIP string
	var newMediaSessions []MediaSession
	var mediaBlockBuffer []string // Buffer for lines of the current m-block

	// First pass: Identify session-level IP and collect/process media blocks
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		if strings.HasPrefix(trimmedLine, "m=") {
			// If a media block was being buffered, process it now before starting a new one
			if len(mediaBlockBuffer) > 0 {
				processMediaBlock(mediaBlockBuffer, currentSessionIP, &newMediaSessions, call)
			}
			mediaBlockBuffer = []string{trimmedLine} // Start new block with the m-line
		} else if len(mediaBlockBuffer) > 0 {
			// If we are inside a media block (m-line has been seen), add current line to it
			mediaBlockBuffer = append(mediaBlockBuffer, trimmedLine)
		} else if strings.HasPrefix(trimmedLine, "c=IN IP4 ") {
			// This is a session-level c-line (occurs before any m-line or outside any m-block context)
			parts := strings.SplitN(trimmedLine, " ", 3)
			if len(parts) == 3 {
				currentSessionIP = strings.TrimSpace(parts[2])
				if *debug {
					loggerDebug.Printf("CallID: %s - SDP: Found session-level IP: %s", call.CallID, currentSessionIP)
				}
			}
		}
		// Note: ptime is handled in a separate pass for clarity, as it's session-level.
	}

	// Process the last media block, if any lines are still in the buffer
	if len(mediaBlockBuffer) > 0 {
		processMediaBlock(mediaBlockBuffer, currentSessionIP, &newMediaSessions, call)
	}

	// Second pass for session-level attributes like ptime (similar to Python script's approach)
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "a=ptime:") {
			parts := strings.SplitN(trimmedLine, ":", 2)
			if len(parts) == 2 {
				ptimeStr := strings.TrimSpace(parts[1])
				ptime, err := strconv.Atoi(ptimeStr)
				if err == nil {
					call.SDPPtime = ptime
					if *debug {
						loggerDebug.Printf("CallID: %s - SDP: Found ptime: %dms", call.CallID, ptime)
					}
					// Typically, one ptime per SDP is dominant.
					// If multiple, last one parsed wins or logic to prioritize answer's ptime could be added.
					// For now, any valid ptime updates call.SDPPtime.
				} else {
					if *debug {
						loggerDebug.Printf("CallID: %s - SDP: Could not parse ptime line: '%s'. Error: %v", call.CallID, trimmedLine, err)
					}
				}
			}
		}
	}

	// Update call's media sessions based on whether this SDP is an offer or answer
	if len(newMediaSessions) > 0 {
		if isAnswer {
			if len(call.MediaSessions) == 0 {
				// No existing sessions, set the new ones
				if *debug {
					loggerDebug.Printf("CallID: %s - SDP Answer: Setting initial media sessions to new (%d sessions: %+v)",
						call.CallID, len(newMediaSessions), newMediaSessions)
				}
				call.MediaSessions = newMediaSessions
				for _, newSession := range newMediaSessions {
					addMediaSessionToGlobalMap(newSession, call)
				}
			} else {
				// Append new unique media sessions to existing ones
				var addedSessions []MediaSession
				for _, newSession := range newMediaSessions {
					if !isDuplicateMediaSession(call.MediaSessions, newSession) {
						call.MediaSessions = append(call.MediaSessions, newSession)
						addMediaSessionToGlobalMap(newSession, call)
						addedSessions = append(addedSessions, newSession)
					}
				}
				if *debug {
					if len(addedSessions) > 0 {
						loggerDebug.Printf("CallID: %s - SDP Answer: Appended %d new unique media sessions (%+v) to existing %d sessions. Total now: %d sessions (%+v)",
							call.CallID, len(addedSessions), addedSessions, len(call.MediaSessions)-len(addedSessions), len(call.MediaSessions), call.MediaSessions)
					} else {
						loggerDebug.Printf("CallID: %s - SDP Answer: No new unique sessions to append. All %d sessions from answer already exist in current %d sessions (%+v)",
							call.CallID, len(newMediaSessions), len(call.MediaSessions), call.MediaSessions)
					}
				}
			}
		} else { // Offer
			if len(call.MediaSessions) == 0 { // Only set if no media sessions exist yet (e.g. from a prior answer)
				if *debug {
					loggerDebug.Printf("CallID: %s - SDP Offer: Setting initial media sessions to new (%d sessions: %+v)",
						call.CallID, len(newMediaSessions), newMediaSessions)
				}
				call.MediaSessions = newMediaSessions
				for _, newSession := range newMediaSessions {
					addMediaSessionToGlobalMap(newSession, call)
				}
			} else {
				// Append new unique media sessions to existing ones
				var addedSessions []MediaSession
				for _, newSession := range newMediaSessions {
					if !isDuplicateMediaSession(call.MediaSessions, newSession) {
						call.MediaSessions = append(call.MediaSessions, newSession)
						addMediaSessionToGlobalMap(newSession, call)
						addedSessions = append(addedSessions, newSession)
					}
				}
				if *debug {
					if len(addedSessions) > 0 {
						loggerDebug.Printf("CallID: %s - SDP Offer: Appended %d new unique media sessions (%+v) to existing %d sessions. Total now: %d sessions (%+v)",
							call.CallID, len(addedSessions), addedSessions, len(call.MediaSessions)-len(addedSessions), len(call.MediaSessions), call.MediaSessions)
					} else {
						loggerDebug.Printf("CallID: %s - SDP Offer: No new unique sessions to append. All %d sessions from offer already exist in current %d sessions (%+v)",
							call.CallID, len(newMediaSessions), len(call.MediaSessions), call.MediaSessions)
					}
				}
			}
		}
	} else if *debug {
		loggerDebug.Printf("CallID: %s - SDP: No media sessions found or all were inactive.", call.CallID)
	}
}