package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// CLI arguments
var (
	inputFile             *string
	ifaceName             *string
	bpfFilter             *string
	sipPortsRange         *string
	outputDir             *string
	detectedCallsFilename *string
	statsFilename         *string
	callTimeout           *time.Duration
	debug                 *bool
)

func initFlags() {
	inputFile = flag.String("input-file", "", "Path to the source PCAP file (alternative to live capture)")
	ifaceName = flag.String("interface", "", "Network interface name for live capture (e.g., \"eth0\")")
	bpfFilter = flag.String("filter", "udp", "BPF filter string for live capture (default: \"udp\")")
	sipPortsRange = flag.String("sip-ports-range", "", "SIP port range (e.g., \"5060-5200\") (Required)")
	outputDir = flag.String("output-dir", ".", "Directory to save extracted PCAP files and CSV log")
	detectedCallsFilename = flag.String("detected-calls-filename", "detected_calls.csv", "Filename for the CSV index of detected calls")
	statsFilename = flag.String("stats-filename", "calls_statistics.csv", "Filename for the CSV of call RTP statistics")
	callTimeout = flag.Duration("call-timeout", 5*time.Minute, "Duration for inactive call timeout (e.g., \"5m\", \"300s\")")
	debug = flag.Bool("debug", false, "Enable debug logging")

	flag.Parse()
}

func validateArgs() {
	if *sipPortsRange == "" {
		// Logger might not be initialized yet, so use fmt for critical early errors
		fmt.Fprintln(os.Stderr, "Error: --sip-ports-range is required.")
		flag.Usage()
		os.Exit(1)
	}

	if *inputFile != "" && *ifaceName != "" {
		fmt.Fprintln(os.Stderr, "Error: --input-file and --interface are mutually exclusive. Provide one or the other.")
		flag.Usage()
		os.Exit(1)
	}

	if *inputFile == "" && *ifaceName == "" {
		fmt.Fprintln(os.Stderr, "Error: Either --input-file or --interface must be provided.")
		flag.Usage()
		os.Exit(1)
	}
}