package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	// pcapgo is used in sip_handler.go and potentially rtp_handler.go if writing RTP to separate files
)

// Global variables that remain in main or are widely used
var (
	activeCalls      = make(map[string]*Call)
	activeCallsMutex = &sync.RWMutex{}

	globalCallTimeout time.Duration

	loggerInfo  *log.Logger
	loggerDebug *log.Logger
)

func setupLogging() {
	loggerInfo = log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)

	// In test environments, *debug might not be initialized by flag parsing.
	// Default to false (discard debug logs) if debug pointer is nil.
	enableDebugLogs := false
	if debug != nil && *debug {
		enableDebugLogs = true
	}

	if enableDebugLogs {
		loggerDebug = log.New(os.Stderr, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
	} else {
		loggerDebug = log.New(io.Discard, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
	}
}

func parseSIPPortsRange(portRangeStr string) (startPort, endPort uint16, err error) {
	parts := strings.Split(portRangeStr, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid SIP port range format '%s'. Expected START-END", portRangeStr)
	}

	start, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port '%s': %w", parts[0], err)
	}

	end, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port '%s': %w", parts[1], err)
	}

	if start > end {
		return 0, 0, fmt.Errorf("start port %d cannot be greater than end port %d", start, end)
	}
	if start == 0 || end == 0 {
		return 0, 0, fmt.Errorf("ports cannot be 0")
	}
	if end > 65535 {
		return 0, 0, fmt.Errorf("port %d exceeds maximum value of 65535", end)
	}
	return uint16(start), uint16(end), nil
}

func main() {
	initFlags()           // From cli.go
	validateArgs()        // From cli.go
	compileRegexPatterns() // From cli.go - compile RTP payload clearing regex patterns
	setupLogging()

	loggerInfo.Println("SIP Call Extractor - Go Version - Starting...")
	if *debug { // *debug from cli.go
		loggerDebug.Println("Debug logging enabled.")
	}

	parsedStartSipPort, parsedEndSipPort, err := parseSIPPortsRange(*sipPortsRange) // *sipPortsRange from cli.go
	if err != nil {
		loggerInfo.Fatalf("Error parsing SIP port range: %v", err)
	}

	loggerInfo.Printf("Input File: %s", *inputFile) // from cli.go
	loggerInfo.Printf("Interface: %s", *ifaceName) // from cli.go
	loggerInfo.Printf("BPF Filter: %s", generateBPFFilter()) // from cli.go
	loggerInfo.Printf("ERSPAN Mode: %t", *enableERSPAN) // from cli.go
	if *enableERSPAN {
		loggerInfo.Printf("ERSPAN SPAN IDs: %s", *erspanSpanIDs) // from cli.go
		loggerInfo.Printf("ERSPAN VLANs: %s", *erspanVLANs) // from cli.go
		loggerInfo.Printf("ERSPAN Stats Logging: %t", *logERSPANStats) // from cli.go
	}
	loggerInfo.Printf("Effective SIP Ports Range: %d-%d", parsedStartSipPort, parsedEndSipPort)
	loggerInfo.Printf("Output Directory: %s", *outputDir) // from cli.go
	loggerInfo.Printf("Detected Calls Filename: %s", *detectedCallsFilename) // from cli.go
	loggerInfo.Printf("Stats Filename: %s", *statsFilename)                   // from cli.go
	loggerInfo.Printf("Call Timeout: %s", (*callTimeout).String())             // from cli.go

	err = initializeCSVs() // From csv_handler.go
	if err != nil {
		loggerInfo.Fatalf("Failed to initialize CSV files: %v", err)
	}
	defer closeCSVs() // From csv_handler.go
	globalCallTimeout = *callTimeout // *callTimeout from cli.go

	// Start monitoring for inactive calls in a separate goroutine
	if globalCallTimeout > 0 {
		go monitorInactiveCalls() // From call_manager.go
	} else {
		loggerInfo.Println("Inactive call monitoring is disabled as timeout is set to 0 or less.")
	}

	// Graceful shutdown handling
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		loggerInfo.Printf("Received signal: %s. Shutting down gracefully...", sig)
		// Perform cleanup before exiting
		closeAllActiveCalls(time.Now()) // Ensure stats are written for calls active at shutdown
		closeCSVs()                     // Ensure CSVs are flushed
		loggerInfo.Println("Cleanup complete. Exiting.")
		os.Exit(0)
	}()

	var packetSource *gopacket.PacketSource
	var handle *pcap.Handle
	var linkType layers.LinkType

	if *inputFile != "" {
		loggerInfo.Printf("Opening PCAP file: %s", *inputFile)
		var errOpenOffline error
		handle, errOpenOffline = pcap.OpenOffline(*inputFile)
		if errOpenOffline != nil {
			loggerInfo.Fatalf("Error opening PCAP file '%s': %v", *inputFile, errOpenOffline)
		}
		defer handle.Close()
		linkType = handle.LinkType()
		packetSource = gopacket.NewPacketSource(handle, linkType)
		loggerInfo.Printf("Successfully opened PCAP file: %s with LinkType: %s", *inputFile, linkType.String())
	} else if *ifaceName != "" {
		loggerInfo.Printf("Starting live capture on interface: %s with filter: %s", *ifaceName, *bpfFilter)
		var errOpenLive error
		handle, errOpenLive = pcap.OpenLive(*ifaceName, 1600, true, pcap.BlockForever)
		if errOpenLive != nil {
			loggerInfo.Fatalf("Error opening live capture on interface '%s': %v", *ifaceName, errOpenLive)
		}
		defer handle.Close()

		// Generate appropriate BPF filter based on ERSPAN mode
		effectiveFilter := generateBPFFilter()
		if effectiveFilter != "" {
			loggerInfo.Printf("Applying BPF filter: %s", effectiveFilter)
			if err := handle.SetBPFFilter(effectiveFilter); err != nil {
				loggerInfo.Fatalf("Error applying BPF filter '%s': %v", effectiveFilter, err)
			}
		}
		linkType = handle.LinkType()
		packetSource = gopacket.NewPacketSource(handle, linkType)
		loggerInfo.Printf("Live capture started on interface: %s with LinkType: %s", *ifaceName, linkType.String())
	} else {
		loggerInfo.Fatal("No input source specified (file or interface). Exiting.")
	}

	loggerInfo.Println("Starting packet processing...")
	packetCount := 0
	for packet := range packetSource.Packets() {
		packetCount++
		processPacket(packet, parsedStartSipPort, parsedEndSipPort, linkType)
		if packetCount%1000 == 0 {
			if *debug {
				loggerDebug.Printf("Processed %d packets...", packetCount)
			} else if packetCount%10000 == 0 {
				loggerInfo.Printf("Processed %d packets...", packetCount)
			}
		}
	}

	loggerInfo.Printf("Finished processing. Total packets processed: %d", packetCount)
	closeAllActiveCalls(time.Now()) // Definition will be in call_management.go or similar
}

func processPacket(packet gopacket.Packet, startSipPort, endSipPort uint16, linkType layers.LinkType) {
	// First check for GRE encapsulation if ERSPAN is enabled
	greLayer := packet.Layer(layers.LayerTypeGRE)
	var innerPacket gopacket.Packet
	var erspanMeta *ERSPANMetadata
	
	if greLayer != nil && *enableERSPAN {
		innerPacket, erspanMeta = handleGREPacket(packet, greLayer)
		if innerPacket == nil {
			return // Not ERSPAN or parsing failed
		}
		
		// Check ERSPAN filters
		if !shouldProcessERSPANPacket(erspanMeta) {
			return // Filtered out by ERSPAN configuration
		}
		
		if *debug {
			loggerDebug.Printf("Processing ERSPAN packet - Version: %d, SpanID: %d, VLAN: %d",
				erspanMeta.Version, erspanMeta.SpanID, erspanMeta.VLAN)
		}
	} else {
		innerPacket = packet
	}
	
	// Continue with existing IP layer processing on inner packet
	processInnerPacket(innerPacket, startSipPort, endSipPort, linkType, erspanMeta)
}

func processInnerPacket(packet gopacket.Packet, startSipPort, endSipPort uint16, linkType layers.LinkType, erspanMeta *ERSPANMetadata) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	var ipSrc, ipDst string
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		ipSrc = ip.SrcIP.String()
		ipDst = ip.DstIP.String()
	} else {
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer != nil {
			ipv6, _ := ipv6Layer.(*layers.IPv6)
			ipSrc = ipv6.SrcIP.String()
			ipDst = ipv6.DstIP.String()
		} else {
			if *debug {
				loggerDebug.Println("Non-IP packet encountered, skipping.")
			}
			return
		}
	}

	var srcPort, dstPort uint16
	var transportPayload []byte
	isTCP := false
	isUDP := false

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		transportPayload = tcp.Payload
		isTCP = true
	} else {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)
			transportPayload = udp.Payload
			isUDP = true
		} else {
			if *debug {
				loggerDebug.Printf("Packet is not TCP or UDP (SrcIP: %s, DstIP: %s), skipping SIP/RTP logic.", ipSrc, ipDst)
			}
			return
		}
	}

	if len(transportPayload) == 0 {
		if *debug {
			loggerDebug.Printf("Packet (SrcIP: %s, DstIP: %s, SrcPort: %d, DstPort: %d) has no transport payload, skipping.", ipSrc, ipDst, srcPort, dstPort)
		}
		return
	}

	isSipPacket := false
	if (srcPort >= startSipPort && srcPort <= endSipPort) || (dstPort >= startSipPort && dstPort <= endSipPort) {
		isSipPacket = true
	}

	if isSipPacket {
		if *debug {
			protocol := "UDP"
			if isTCP {
				protocol = "TCP"
			}
			loggerDebug.Printf("Potential SIP packet detected (%s %s:%d -> %s:%d). Payload length: %d",
				protocol, ipSrc, srcPort, ipDst, dstPort, len(transportPayload))
		}
		handleSipPacket(packet, transportPayload, ipSrc, ipDst, srcPort, dstPort, linkType, erspanMeta) // From sip_handler.go
		return
	}

	if isUDP { // RTP is typically over UDP
		handleRtpPacket(packet, transportPayload, ipSrc, ipDst, srcPort, dstPort, erspanMeta) // From rtp_handler.go
	}
}

func closeAllActiveCalls(endTime time.Time) {
	activeCallsMutex.Lock()
	defer activeCallsMutex.Unlock()

	if len(activeCalls) > 0 {
		loggerInfo.Printf("Closing %d active call(s) at the end of processing...", len(activeCalls))
		for callID, callData := range activeCalls {
			calculateAndWriteRTPStats(callData, endTime) // Call the stats function from stats_handler.go
			if callData.PcapFile != nil {
				if err := callData.PcapFile.Close(); err != nil {
					loggerInfo.Printf("Error closing PCAP file for call %s (%s): %v", callID, callData.OutputFilename, err)
				} else {
					loggerDebug.Printf("Closed PCAP file for call %s: %s", callID, callData.OutputFilename)
				}
				callData.PcapWriter = nil
				callData.PcapFile = nil
				
				// Handle S3 upload and local file cleanup
				processS3UploadAndCleanup(callData.OutputFilename, *outputDir)
			}
			loggerInfo.Printf("Call %s (From: %s, To: %s) considered ended.", callID, callData.SIPFrom, callData.SIPTo)
		}
		activeCalls = make(map[string]*Call) // Clear the map
	} else {
		loggerInfo.Println("No active calls to close at the end of processing.")
	}
}