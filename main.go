package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime/pprof"
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

	// Global media session map for efficient RTP packet lookup
	activeMediaSessions      = make(map[string]*Call)
	activeMediaSessionsMutex = &sync.RWMutex{}

	globalCallTimeout time.Duration

	loggerInfo  *log.Logger
	loggerDebug *log.Logger

	globalFragmentManager *FragmentManager

	// Capture statistics tracking
	globalCaptureStats *CaptureStats
	captureStatsTimer  *time.Timer
)

// CaptureStats tracks packet capture statistics
type CaptureStats struct {
	PacketsReceived  uint64
	PacketsDropped   uint64
	PacketsIfDropped uint64
	PacketsTruncated uint64
	StartTime        time.Time
	LastReportTime   time.Time
	mutex            sync.RWMutex
}

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

// resolveSnapshotLength converts 0 to default 262144, validates range
func resolveSnapshotLength(snaplen int) int {
	if snaplen == 0 {
		return 262144 // Default maximum
	}
	return snaplen
}

// initCaptureStats initializes capture statistics tracking
func initCaptureStats() {
	if *captureStats && *ifaceName != "" {
		globalCaptureStats = &CaptureStats{
			StartTime:      time.Now(),
			LastReportTime: time.Now(),
		}
		
		// Start periodic reporting every 10 seconds
		captureStatsTimer = time.NewTimer(10 * time.Second)
		go captureStatsReporter()
	}
}

// captureStatsReporter handles periodic statistics reporting
func captureStatsReporter() {
	for {
		select {
		case <-captureStatsTimer.C:
			if globalCaptureStats != nil {
				reportCaptureStats(false)
				captureStatsTimer.Reset(10 * time.Second)
			}
		}
	}
}

// reportCaptureStats reports current capture statistics
func reportCaptureStats(final bool) {
	if globalCaptureStats == nil {
		return
	}
	
	globalCaptureStats.mutex.RLock()
	defer globalCaptureStats.mutex.RUnlock()
	
	now := time.Now()
	duration := now.Sub(globalCaptureStats.StartTime)
	
	prefix := "CAPTURE STATS"
	if final {
		prefix = "FINAL CAPTURE STATS"
	}
	
	fmt.Fprintf(os.Stderr, "%s: Duration=%v, Received=%d, Dropped=%d, IfDropped=%d, Truncated=%d\n",
		prefix,
		duration.Round(time.Second),
		globalCaptureStats.PacketsReceived,
		globalCaptureStats.PacketsDropped,
		globalCaptureStats.PacketsIfDropped,
		globalCaptureStats.PacketsTruncated,
	)
}

// updateCaptureStats updates statistics from pcap handle and packet processing
func updateCaptureStats(handle *pcap.Handle, packetTruncated bool) {
	if globalCaptureStats == nil {
		return
	}
	
	// Get current stats from pcap handle
	stats, err := handle.Stats()
	if err != nil {
		if *debug {
			loggerDebug.Printf("Error getting capture stats: %v", err)
		}
		return
	}
	
	globalCaptureStats.mutex.Lock()
	defer globalCaptureStats.mutex.Unlock()
	
	globalCaptureStats.PacketsReceived = uint64(stats.PacketsReceived)
	globalCaptureStats.PacketsDropped = uint64(stats.PacketsDropped)
	globalCaptureStats.PacketsIfDropped = uint64(stats.PacketsIfDropped)
	
	if packetTruncated {
		globalCaptureStats.PacketsTruncated++
	}
}

// stopCaptureStats stops statistics reporting and prints final stats
func stopCaptureStats(handle *pcap.Handle) {
	if globalCaptureStats != nil {
		if captureStatsTimer != nil {
			captureStatsTimer.Stop()
		}
		
		// Final update and report
		updateCaptureStats(handle, false)
		reportCaptureStats(true)
	}
}

func main() {
	initFlags()           // From cli.go
	validateArgs()        // From cli.go
	compileRegexPatterns() // From cli.go - compile RTP payload clearing regex patterns
	setupLogging()

setupSignalHandlers()
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
	loggerInfo.Printf("Call Timeout: %s", (*callTimeout).String()) // from cli.go
	if *enableFragmentation {
		loggerInfo.Printf("Fragmentation Handling Enabled: Timeout=%s, MaxFragments=%d", (*fragmentTimeout).String(), *maxFragments)
	}

	err = initializeCSVs() // From csv_handler.go
	if err != nil {
		loggerInfo.Fatalf("Failed to initialize CSV files: %v", err)
	}
	defer closeCSVs() // From csv_handler.go
	globalCallTimeout = *callTimeout // *callTimeout from cli.go

	if *enableFragmentation {
		globalFragmentManager = NewFragmentManager(*fragmentTimeout, *maxFragments)
		globalFragmentManager.Start()
	}

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
		if *enableFragmentation {
			globalFragmentManager.Stop()
			writeFragmentStats()
		}
		
		// Final capture statistics for live capture
		if *captureStats && *ifaceName != "" {
			// Note: handle may not be available in graceful shutdown context
			if globalCaptureStats != nil {
				if captureStatsTimer != nil {
					captureStatsTimer.Stop()
				}
				reportCaptureStats(true)
			}
		}
		
		closeCSVs() // Ensure CSVs are flushed
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
		effectiveSnaplen := resolveSnapshotLength(*snapshotLength)
		
		loggerInfo.Printf("Starting live capture on interface: %s with filter: %s", *ifaceName, *bpfFilter)
		loggerInfo.Printf("Capture parameters: snaplen=%d bytes%s, buffer=%s, stats=%t",
			effectiveSnaplen,
			func() string { if *snapshotLength == 0 { return " (default)" } else { return "" } }(),
			func() string { if *bufferSize == 0 { return "system default" } else { return fmt.Sprintf("%d KiB", *bufferSize) } }(),
			*captureStats)
		
		// Create inactive handle for advanced configuration
		inactiveHandle, err := pcap.NewInactiveHandle(*ifaceName)
		if err != nil {
			loggerInfo.Fatalf("Could not create inactive handle for interface '%s': %v\nPossible causes:\n- Interface does not exist\n- Insufficient privileges (try running as root)\n- Interface is not available for capture", *ifaceName, err)
		}
		defer func() {
			inactiveHandle.CleanUp()
		}()
		
		// Set snapshot length
		if err := inactiveHandle.SetSnapLen(effectiveSnaplen); err != nil {
			loggerInfo.Fatalf("Could not set snapshot length to %d: %v", effectiveSnaplen, err)
		}
		loggerInfo.Printf("Set snapshot length to %d bytes", effectiveSnaplen)
		
		// Set promiscuous mode
		if err := inactiveHandle.SetPromisc(true); err != nil {
			loggerInfo.Fatalf("Could not set promiscuous mode: %v", err)
		}
		
		// Set timeout
		if err := inactiveHandle.SetTimeout(pcap.BlockForever); err != nil {
			loggerInfo.Fatalf("Could not set timeout: %v", err)
		}
		
		// Set buffer size if specified
		if *bufferSize > 0 {
			bufferSizeBytes := *bufferSize * 1024 // Convert KiB to bytes
			if err := inactiveHandle.SetBufferSize(bufferSizeBytes); err != nil {
				loggerInfo.Fatalf("Could not set buffer size to %d KiB (%d bytes): %v",
					*bufferSize, bufferSizeBytes, err)
			}
			loggerInfo.Printf("Set capture buffer size to %d KiB (%d bytes)", *bufferSize, bufferSizeBytes)
		} else {
			loggerInfo.Printf("Using system default capture buffer size")
		}
		
		// Activate the handle
		var errOpenLive error
		handle, errOpenLive = inactiveHandle.Activate()
		if errOpenLive != nil {
			loggerInfo.Fatalf("Error activating live capture on interface '%s': %v\nPossible causes:\n- Insufficient privileges (try running as root)\n- Interface is busy or unavailable\n- Invalid capture parameters", *ifaceName, errOpenLive)
		}
		defer handle.Close()
		
		// Generate and apply BPF filter
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
		
		// Initialize capture statistics if enabled
		initCaptureStats()
	} else {
		loggerInfo.Fatal("No input source specified (file or interface). Exiting.")
	}

	loggerInfo.Println("Starting packet processing...")
	packetCount := 0
	for packet := range packetSource.Packets() {
		packetCount++
		
		// Check if packet was truncated (only for live capture)
		packetTruncated := false
		if *ifaceName != "" && packet.Metadata() != nil {
			packetTruncated = packet.Metadata().Truncated
		}
		
		processPacket(packet, parsedStartSipPort, parsedEndSipPort, linkType)
		
		// Update capture statistics if enabled (no other logging here)
		if *captureStats && *ifaceName != "" && handle != nil {
			updateCaptureStats(handle, packetTruncated)
		}
	}

	loggerInfo.Printf("Finished processing. Total packets processed: %d", packetCount)

	// Final capture statistics for live capture
	if *captureStats && *ifaceName != "" && handle != nil {
		stopCaptureStats(handle)
	}

	closeAllActiveCalls(time.Now()) // Definition will be in call_management.go or similar
	if *enableFragmentation {
		globalFragmentManager.Stop()
		writeFragmentStats()
	}
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
	// Handle IPv4 fragmentation first
	if *enableFragmentation {
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			if isFragmented(ip) {
				reassembledPacket := globalFragmentManager.ProcessFragment(packet, ip, erspanMeta)
				if reassembledPacket != nil {
					// Recursively process the reassembled packet
					processInnerPacket(reassembledPacket, startSipPort, endSipPort, linkType, erspanMeta)
				}
				return // Don't process individual fragments further
			}
		}
	}

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
func setupSignalHandlers() {
	profSigs := make(chan os.Signal, 1)
	signal.Notify(profSigs, syscall.SIGUSR1, syscall.SIGUSR2)

	go func() {
		for sig := range profSigs {
			switch sig {
			case syscall.SIGUSR1:
				dumpCPUProfile()
			case syscall.SIGUSR2:
				dumpMemoryAndGoroutineProfiles()
			}
		}
	}()
}

func dumpCPUProfile() {
	cpuProfilePath := "cpu.prof"
	f, err := os.Create(cpuProfilePath)
	if err != nil {
		loggerInfo.Printf("Could not create CPU profile file: %v", err)
		return
	}
	defer f.Close()

	loggerInfo.Println("Starting CPU profile...")
	if err := pprof.StartCPUProfile(f); err != nil {
		loggerInfo.Printf("Could not start CPU profile: %v", err)
		return
	}

	time.Sleep(30 * time.Second)
	pprof.StopCPUProfile()
	loggerInfo.Printf("CPU profile written to %s", cpuProfilePath)
}

func dumpMemoryAndGoroutineProfiles() {
	// Memory profile
	memProfilePath := "mem.prof"
	f, err := os.Create(memProfilePath)
	if err != nil {
		loggerInfo.Printf("Could not create memory profile file: %v", err)
		return
	}
	defer f.Close()

	if err := pprof.WriteHeapProfile(f); err != nil {
		loggerInfo.Printf("Could not write memory profile: %v", err)
		return
	}
	loggerInfo.Printf("Memory profile written to %s", memProfilePath)

	// Goroutine profile
	goroutineProfilePath := "goroutine.prof"
	fg, err := os.Create(goroutineProfilePath)
	if err != nil {
		loggerInfo.Printf("Could not create goroutine profile file: %v", err)
		return
	}
	defer fg.Close()

	if p := pprof.Lookup("goroutine"); p != nil {
		if err := p.WriteTo(fg, 1); err != nil {
			loggerInfo.Printf("Could not write goroutine profile: %v", err)
		} else {
			loggerInfo.Printf("Goroutine profile written to %s", goroutineProfilePath)
		}
	}
}