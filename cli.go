package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
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
	
	// RTP payload clearing flags
	noRtpDump                        *bool
	noRtpDumpForCallIdPattern        *string
	noRtpDumpExceptForCallIdPattern  *string
	noRtpDumpForFromPattern          *string
	noRtpDumpExceptForFromPattern    *string
	noRtpDumpForToPattern            *string
	noRtpDumpExceptForToPattern      *string
	
	// S3 upload flags
	autoUploadToS3 *bool
	s3URI          *string
	s3Region       *string
	
	// ERSPAN flags
	enableERSPAN     *bool
	erspanSpanIDs    *string
	erspanVLANs      *string
	logERSPANStats   *bool

	// Fragmentation flags
	enableFragmentation *bool
	fragmentTimeout     *time.Duration
	maxFragments        *int
)

// Global variable to control CSV s3_location column
var s3ParamsProvidedForCsv bool

// Compiled regex patterns for RTP payload clearing
var (
	noRtpDumpForCallIdRegexp        *regexp.Regexp
	noRtpDumpExceptForCallIdRegexp  *regexp.Regexp
	noRtpDumpForFromRegexp          *regexp.Regexp
	noRtpDumpExceptForFromRegexp    *regexp.Regexp
	noRtpDumpForToRegexp            *regexp.Regexp
	noRtpDumpExceptForToRegexp      *regexp.Regexp
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
	
	// RTP payload clearing flags
	noRtpDump = flag.Bool("no-rtp-dump", false, "Clear RTP payload for all calls")
	noRtpDumpForCallIdPattern = flag.String("no-rtp-dump-for-callid-pattern", "", "Regex to clear RTP payload if Call-ID matches")
	noRtpDumpExceptForCallIdPattern = flag.String("no-rtp-dump-except-for-callid-pattern", "", "Regex to preserve RTP payload if Call-ID matches (clears otherwise if this rule is active)")
	noRtpDumpForFromPattern = flag.String("no-rtp-dump-for-from-pattern", "", "Regex to clear RTP payload if SIP From header matches")
	noRtpDumpExceptForFromPattern = flag.String("no-rtp-dump-except-for-from-pattern", "", "Regex to preserve RTP payload if SIP From header matches (clears otherwise if this rule is active)")
	noRtpDumpForToPattern = flag.String("no-rtp-dump-for-to-pattern", "", "Regex to clear RTP payload if SIP To header matches")
	noRtpDumpExceptForToPattern = flag.String("no-rtp-dump-except-for-to-pattern", "", "Regex to preserve RTP payload if SIP To header matches (clears otherwise if this rule is active)")

	// S3 upload flags
	autoUploadToS3 = flag.Bool("auto-upload-to-s3", false, "Automatically upload PCAP files to S3 and delete local files")
	s3URI = flag.String("s3-uri", "", "S3 URI prefix for uploads (e.g., s3://bucket/prefix/)")
	s3Region = flag.String("s3-region", "", "AWS region for S3 bucket")

	// ERSPAN flags
	enableERSPAN = flag.Bool("enable-erspan", false, "Enable ERSPAN/GRE packet processing")
	erspanSpanIDs = flag.String("erspan-span-ids", "", "Comma-separated list of SPAN IDs to process (empty = all)")
	erspanVLANs = flag.String("erspan-vlans", "", "Comma-separated list of VLANs to process (empty = all)")
	logERSPANStats = flag.Bool("log-erspan-stats", false, "Log ERSPAN session statistics")

	// Fragmentation flags
	enableFragmentation = flag.Bool("enable-fragmentation", true, "Enable IP fragmentation reassembly")
	fragmentTimeout = flag.Duration("fragment-timeout", 30*time.Second, "Timeout for IP fragment reassembly")
	maxFragments = flag.Int("max-fragments", 1000, "Maximum number of concurrent fragment reassembly operations")

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

	// S3 validation
	if *autoUploadToS3 {
		if *s3URI == "" {
			fmt.Fprintln(os.Stderr, "Error: --s3-uri is required when --auto-upload-to-s3 is enabled.")
			flag.Usage()
			os.Exit(1)
		}
		if *s3Region == "" {
			fmt.Fprintln(os.Stderr, "Error: --s3-region is required when --auto-upload-to-s3 is enabled.")
			flag.Usage()
			os.Exit(1)
		}
		if !strings.HasPrefix(*s3URI, "s3://") {
			fmt.Fprintln(os.Stderr, "Error: --s3-uri must start with 's3://'.")
			flag.Usage()
			os.Exit(1)
		}
	}

	// Set global variable for CSV column management
	s3ParamsProvidedForCsv = (*s3URI != "" && *s3Region != "")
	
	// ERSPAN validation
	if err := validateERSPANConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}
}

// validateERSPANConfig validates ERSPAN-related configuration
func validateERSPANConfig() error {
	if *enableERSPAN && *bpfFilter != "" && *bpfFilter != "udp" {
		return fmt.Errorf("BPF filters are not supported with ERSPAN mode. Please configure filtering using Cisco ACLs on the switch")
	}
	return nil
}

// generateBPFFilter generates the appropriate BPF filter based on ERSPAN mode
func generateBPFFilter() string {
	if *enableERSPAN {
		// ERSPAN mode - capture all GRE traffic, ignore user filter
		if *bpfFilter != "" && *bpfFilter != "udp" {
			// This should have been caught in validation, but log a warning just in case
			fmt.Fprintf(os.Stderr, "Warning: BPF filter '%s' ignored in ERSPAN mode. Use Cisco ACLs to filter ERSPAN traffic at source.\n", *bpfFilter)
		}
		return "proto gre"
	}
	
	// Normal mode - use user filter as-is
	return *bpfFilter
}

// compileRegexPatterns compiles the regex patterns provided via CLI flags
// and stores them in global variables. Should be called after flag.Parse().
func compileRegexPatterns() {
	var err error
	
	if *noRtpDumpForCallIdPattern != "" {
		noRtpDumpForCallIdRegexp, err = regexp.Compile(*noRtpDumpForCallIdPattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid regex for --no-rtp-dump-for-callid-pattern: %v\n", err)
			os.Exit(1)
		}
	}
	
	if *noRtpDumpExceptForCallIdPattern != "" {
		noRtpDumpExceptForCallIdRegexp, err = regexp.Compile(*noRtpDumpExceptForCallIdPattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid regex for --no-rtp-dump-except-for-callid-pattern: %v\n", err)
			os.Exit(1)
		}
	}
	
	if *noRtpDumpForFromPattern != "" {
		noRtpDumpForFromRegexp, err = regexp.Compile(*noRtpDumpForFromPattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid regex for --no-rtp-dump-for-from-pattern: %v\n", err)
			os.Exit(1)
		}
	}
	
	if *noRtpDumpExceptForFromPattern != "" {
		noRtpDumpExceptForFromRegexp, err = regexp.Compile(*noRtpDumpExceptForFromPattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid regex for --no-rtp-dump-except-for-from-pattern: %v\n", err)
			os.Exit(1)
		}
	}
	
	if *noRtpDumpForToPattern != "" {
		noRtpDumpForToRegexp, err = regexp.Compile(*noRtpDumpForToPattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid regex for --no-rtp-dump-for-to-pattern: %v\n", err)
			os.Exit(1)
		}
	}
	
	if *noRtpDumpExceptForToPattern != "" {
		noRtpDumpExceptForToRegexp, err = regexp.Compile(*noRtpDumpExceptForToPattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid regex for --no-rtp-dump-except-for-to-pattern: %v\n", err)
			os.Exit(1)
		}
	}
}