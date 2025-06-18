package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var (
	reCallID        = regexp.MustCompile(`(?i)^\s*(?:Call-ID|i):\s*(.*)`)
	reFrom          = regexp.MustCompile(`(?i)^\s*(?:From|f):\s*(.*)`)
	reTo            = regexp.MustCompile(`(?i)^\s*(?:To|t):\s*(.*)`)
	reCSeq          = regexp.MustCompile(`(?i)^\s*CSeq:\s*\d+\s+([A-Z_]+)`)
	reContentType   = regexp.MustCompile(`(?i)^\s*(?:Content-Type|c):\s*(.*)`)
	reContentLength = regexp.MustCompile(`(?i)^\s*(?:Content-Length|l):\s*(\d+)`)
)

// trackERSPANSession tracks ERSPAN session information for a call
func trackERSPANSession(call *Call, erspanMeta *ERSPANMetadata, timestamp time.Time) {
	if erspanMeta == nil {
		return
	}
	
	spanID := erspanMeta.SpanID
	if session, exists := call.ERSPANSessions[spanID]; exists {
		// Update existing session
		session.PacketCount++
		if *logERSPANStats && *debug {
			loggerDebug.Printf("Updated ERSPAN session %d for call %s: PacketCount=%d",
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
			loggerInfo.Printf("New ERSPAN session %d for call %s: Version=%d, VLAN=%d",
				spanID, call.CallID, erspanMeta.Version, erspanMeta.VLAN)
		}
	}
}

// parseSipHeaders extracts key SIP headers and the SDP payload.
func parseSipHeaders(payload []byte) (callID, sipMethod, fromHeader, toHeader string, sdpPayload []byte, err error) {
	payloadStr := string(payload)
	lines := strings.Split(strings.ReplaceAll(payloadStr, "\r\n", "\n"), "\n")

	if len(lines) == 0 {
		return "", "", "", "", nil, fmt.Errorf("empty SIP payload")
	}

	firstLine := strings.TrimSpace(lines[0])
	if strings.HasPrefix(firstLine, "SIP/2.0") {
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 2 {
			sipMethod = "STATUS_" + parts[1]
		} else {
			sipMethod = "STATUS_UNKNOWN"
		}
	} else {
		parts := strings.SplitN(firstLine, " ", 2)
		if len(parts) >= 1 {
			sipMethod = strings.ToUpper(parts[0])
		} else {
			return "", "", "", "", nil, fmt.Errorf("malformed SIP request line: %s", firstLine)
		}
	}

	var currentContentLength = -1
	headerPartEnd := -1

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			headerPartEnd = i
			break 
		}

		if callID == "" {
			match := reCallID.FindStringSubmatch(trimmedLine)
			if len(match) > 1 {
				callID = strings.TrimSpace(match[1])
			}
		}
		if fromHeader == "" {
			match := reFrom.FindStringSubmatch(trimmedLine)
			if len(match) > 1 {
				fromHeader = strings.TrimSpace(match[1])
			}
		}
		if toHeader == "" {
			match := reTo.FindStringSubmatch(trimmedLine)
			if len(match) > 1 {
				toHeader = strings.TrimSpace(match[1])
			}
		}
		matchCL := reContentLength.FindStringSubmatch(trimmedLine)
		if len(matchCL) > 1 {
			cl, convErr := strconv.Atoi(matchCL[1])
			if convErr == nil {
				currentContentLength = cl
			}
		}
	}

	if callID == "" {
		return "", "", "", "", nil, fmt.Errorf("Call-ID not found in SIP message")
	}

	if currentContentLength > 0 && headerPartEnd != -1 {
		bodyStartIndex := 0
		for i := 0; i <= headerPartEnd; i++ {
			bodyStartIndex += len(lines[i]) + 1 
		}
		if bodyStartIndex <= len(payloadStr) {
			actualBody := payloadStr[bodyStartIndex:]
			if len(actualBody) >= currentContentLength {
				sdpPayload = []byte(actualBody[:currentContentLength])
			} else {
				sdpPayload = []byte(actualBody)
				if *debug {
					loggerDebug.Printf("CallID: %s - Content-Length %d > actual body %d. Using actual body.", callID, currentContentLength, len(actualBody))
				}
			}
		}
	} else if currentContentLength == 0 {
		sdpPayload = []byte{}
	}

	return callID, sipMethod, fromHeader, toHeader, sdpPayload, nil
}

// generateCallFilename creates a unique filename for a call's PCAP.
func generateCallFilename(callID string) string {
	if callID == "" {
		callID = fmt.Sprintf("unknown_call_%d", time.Now().UnixNano())
	}
	hasher := sha256.New()
	hasher.Write([]byte(callID))
	return hex.EncodeToString(hasher.Sum(nil))[:16] + ".pcap"
}

// handleSipPacket processes a packet identified as SIP.
func handleSipPacket(packet gopacket.Packet, sipMsgPayload []byte, ipSrc, ipDst string, srcPort, dstPort uint16, linkType layers.LinkType, erspanMeta *ERSPANMetadata) {
	callID, sipMethod, fromHeader, toHeader, sdpData, err := parseSipHeaders(sipMsgPayload)
	if ((err != nil) || ( len(fromHeader) == 0 ) || ( len(toHeader) ==0 )) {
		if *debug {
			loggerDebug.Printf("Error parsing SIP headers (Src: %s:%d, Dst: %s:%d): %v. Payload: %s", ipSrc, srcPort, ipDst, dstPort, err, string(sipMsgPayload[:min(len(sipMsgPayload), 200)]))
		}
		return
	}

	if *debug {
		loggerDebug.Printf("Successfully parsed SIP: Call-ID=%s, Method=%s, From=%s, To=%s, SDP_Length=%d",
			callID, sipMethod, fromHeader, toHeader, len(sdpData))
		if erspanMeta != nil {
			loggerDebug.Printf("ERSPAN metadata: Version=%d, SpanID=%d, VLAN=%d, Direction=%d, Timestamp=%d",
				erspanMeta.Version, erspanMeta.SpanID, erspanMeta.VLAN, erspanMeta.Direction, erspanMeta.Timestamp)
		}
	}

	activeCallsMutex.Lock()
	defer activeCallsMutex.Unlock()

	call, exists := activeCalls[callID]

	if !exists {
		if sipMethod == "INVITE" {
			outputFilename := generateCallFilename(callID)
			fullOutputPath := filepath.Join(*outputDir, outputFilename) // *outputDir from cli.go

			pcapFile, errCreate := os.Create(fullOutputPath)
			if errCreate != nil {
				loggerInfo.Printf("Error creating PCAP file %s for call %s: %v", fullOutputPath, callID, errCreate)
				return 
			}
			pcapWriter := pcapgo.NewWriter(pcapFile)
			errWriteHeader := pcapWriter.WriteFileHeader(65536, linkType) 
			if errWriteHeader != nil {
				loggerInfo.Printf("Error writing PCAP file header for %s: %v", fullOutputPath, errWriteHeader)
				pcapFile.Close() 
				return           
			}

			call = &Call{
				CallID:         callID,
				StartTime:      packet.Metadata().Timestamp,
				OutputFilename: outputFilename,
				SIPFrom:        fromHeader,
				SIPTo:          toHeader,
				SDPPtime:       20, // Default
				LastActivityTime: packet.Metadata().Timestamp,
				PcapWriter:     pcapWriter,
				PcapFile:       pcapFile,
				MediaSessions:  make([]MediaSession, 0),
				RTPStreams:     make(map[uint32]*RTPStreamStats),
				ERSPANSessions: make(map[uint16]*ERSPANSessionInfo),
			}
			call.ShouldClearPayload = shouldClearPayloadForCall(call)
			activeCalls[callID] = call
			loggerInfo.Printf("New call initiated: Call-ID=%s, From=%s, To=%s. Output PCAP: %s", callID, fromHeader, toHeader, fullOutputPath)

			if detectedCallsCSV != nil { // detectedCallsCSV from csv_handler.go
				record := []string{callID, call.StartTime.Format(time.RFC3339), outputFilename, fromHeader, toHeader}
				
				// Always add s3_location column
				var s3Location string
				if s3ParamsProvidedForCsv && *autoUploadToS3 {
					s3Location = constructS3Location(*s3URI, outputFilename)
				}
				record = append(record, s3Location)
				
				if err := detectedCallsCSV.Write(record); err != nil {
					loggerInfo.Printf("Error writing to detected_calls.csv for %s: %v", callID, err)
				}
				detectedCallsCSV.Flush()
			}
		} else {
			if *debug {
				loggerDebug.Printf("Non-INVITE SIP packet for unknown Call-ID %s (Method: %s). Ignoring.", callID, sipMethod)
			}
			return
		}
	}

	if call != nil { 
		if call.PcapWriter != nil { 
			errWrite := call.PcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if errWrite != nil {
				loggerInfo.Printf("Error writing SIP packet to PCAP for call %s (file %s): %v", callID, call.OutputFilename, errWrite)
			}
		}
		call.LastActivityTime = packet.Metadata().Timestamp
		
		// Track ERSPAN session if metadata is available
		trackERSPANSession(call, erspanMeta, packet.Metadata().Timestamp)

		if len(sdpData) > 0 {
			isSdpAnswer := strings.HasPrefix(sipMethod, "STATUS_200") 
			parseSDP(sdpData, call, isSdpAnswer) // parseSDP will be in sdp_handler.go
			if *debug {
				loggerDebug.Printf("Call-ID: %s - Parsed SDP. Media Sessions: %+v, PTime: %d", call.CallID, call.MediaSessions, call.SDPPtime)
			}
		}

		if sipMethod == "BYE" || sipMethod == "CANCEL" {
			loggerInfo.Printf("%s detected for call %s. Calculating stats and closing call.", sipMethod, callID)
			calculateAndWriteRTPStats(call, packet.Metadata().Timestamp) // Call the stats function
			if call.PcapFile != nil {
				if err := call.PcapFile.Close(); err != nil {
					loggerInfo.Printf("Error closing PCAP file for call %s on %s: %v", callID, sipMethod, err)
				} else {
					loggerDebug.Printf("Closed PCAP file for call %s: %s", callID, call.OutputFilename)
				}
				call.PcapWriter = nil
				call.PcapFile = nil
				
				// Handle S3 upload and local file cleanup
				processS3UploadAndCleanup(call.OutputFilename, *outputDir)
			}
			removeMediaSessionsFromGlobalMap(call) // Clean up media sessions from global map
			delete(activeCalls, callID)
		}
	}
}

// min is a helper function, currently only used here.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}