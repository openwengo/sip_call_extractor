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
	configFile            *string
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

	// Live capture flags
	snapshotLength *int
	bufferSize     *int
	captureStats   *bool
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
	// Load configuration first by doing a preliminary parse to get the config file path
	var configPath string
	
	// Create a temporary flag set to parse only the config flag
	tempFlagSet := flag.NewFlagSet("temp", flag.ContinueOnError)
	tempFlagSet.Usage = func() {} // Suppress usage output for temp parsing
	tempConfigFile := tempFlagSet.String("config", "", "Path to configuration file")
	
	// Parse only to get the config file path, ignore errors for unknown flags
	tempFlagSet.Parse(os.Args[1:])
	configPath = *tempConfigFile
	
	// Load configuration from file
	config, err := LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}
	
	// Now define all flags using config values as defaults
	configFile = flag.String("config", "", "Path to configuration file")
	inputFile = flag.String("input-file", config.InputFile, "Path to the source PCAP file (alternative to live capture)")
	ifaceName = flag.String("interface", config.Interface, "Network interface name for live capture (e.g., \"eth0\")")
	bpfFilter = flag.String("filter", config.Filter, "BPF filter string for live capture (default: \"udp\")")
	sipPortsRange = flag.String("sip-ports-range", config.SipPortsRange, "SIP port range (e.g., \"5060-5200\") (Required)")
	outputDir = flag.String("output-dir", config.OutputDir, "Directory to save extracted PCAP files and CSV log")
	detectedCallsFilename = flag.String("detected-calls-filename", config.DetectedCallsFilename, "Filename for the CSV index of detected calls")
	statsFilename = flag.String("stats-filename", config.StatsFilename, "Filename for the CSV of call RTP statistics")
	callTimeout = flag.Duration("call-timeout", config.CallTimeout, "Duration for inactive call timeout (e.g., \"5m\", \"300s\")")
	debug = flag.Bool("debug", config.Debug, "Enable debug logging")
	
	// RTP payload clearing flags
	noRtpDump = flag.Bool("no-rtp-dump", config.NoRtpDump, "Clear RTP payload for all calls")
	noRtpDumpForCallIdPattern = flag.String("no-rtp-dump-for-callid-pattern", config.NoRtpDumpForCallIdPattern, "Regex to clear RTP payload if Call-ID matches")
	noRtpDumpExceptForCallIdPattern = flag.String("no-rtp-dump-except-for-callid-pattern", config.NoRtpDumpExceptForCallIdPattern, "Regex to preserve RTP payload if Call-ID matches (clears otherwise if this rule is active)")
	noRtpDumpForFromPattern = flag.String("no-rtp-dump-for-from-pattern", config.NoRtpDumpForFromPattern, "Regex to clear RTP payload if SIP From header matches")
	noRtpDumpExceptForFromPattern = flag.String("no-rtp-dump-except-for-from-pattern", config.NoRtpDumpExceptForFromPattern, "Regex to preserve RTP payload if SIP From header matches (clears otherwise if this rule is active)")
	noRtpDumpForToPattern = flag.String("no-rtp-dump-for-to-pattern", config.NoRtpDumpForToPattern, "Regex to clear RTP payload if SIP To header matches")
	noRtpDumpExceptForToPattern = flag.String("no-rtp-dump-except-for-to-pattern", config.NoRtpDumpExceptForToPattern, "Regex to preserve RTP payload if SIP To header matches (clears otherwise if this rule is active)")

	// S3 upload flags
	autoUploadToS3 = flag.Bool("auto-upload-to-s3", config.AutoUploadToS3, "Automatically upload PCAP files to S3 and delete local files")
	s3URI = flag.String("s3-uri", config.S3URI, "S3 URI prefix for uploads (e.g., s3://bucket/prefix/)")
	s3Region = flag.String("s3-region", config.S3Region, "AWS region for S3 bucket")

	// ERSPAN flags
	enableERSPAN = flag.Bool("enable-erspan", config.EnableERSPAN, "Enable ERSPAN/GRE packet processing")
	erspanSpanIDs = flag.String("erspan-span-ids", config.ErspanSpanIDs, "Comma-separated list of SPAN IDs to process (empty = all)")
	erspanVLANs = flag.String("erspan-vlans", config.ErspanVLANs, "Comma-separated list of VLANs to process (empty = all)")
	logERSPANStats = flag.Bool("log-erspan-stats", config.LogERSPANStats, "Log ERSPAN session statistics")

	// Fragmentation flags
	enableFragmentation = flag.Bool("enable-fragmentation", config.EnableFragmentation, "Enable IP fragmentation reassembly")
	fragmentTimeout = flag.Duration("fragment-timeout", config.FragmentTimeout, "Timeout for IP fragment reassembly")
	maxFragments = flag.Int("max-fragments", config.MaxFragments, "Maximum number of concurrent fragment reassembly operations")

	// Live capture flags
	snapshotLength = flag.Int("s", config.SnapshotLength, "Snapshot length in bytes (0=262144, max=262144)")
	flag.IntVar(snapshotLength, "snapshot-length", config.SnapshotLength, "Snapshot length in bytes (0=262144, max=262144)")
	bufferSize = flag.Int("B", config.BufferSize, "OS capture buffer size in KiB (0=system default)")
	flag.IntVar(bufferSize, "buffer-size", config.BufferSize, "OS capture buffer size in KiB (0=system default)")
	captureStats = flag.Bool("capture-stats", config.CaptureStats, "Enable periodic capture statistics reporting")

	// Parse all flags with the new defaults
	flag.Parse()
	
	// Apply hostname macro expansion to s3URI if provided via CLI
	if *s3URI != "" {
		expandedURI, err := expandHostnameMacros(*s3URI)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to expand hostname macro in s3-uri: %v\n", err)
		} else {
			*s3URI = expandedURI
		}
	}
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

	// Live capture validation (only for interface mode)
	if *ifaceName != "" {
		if *snapshotLength < 0 || *snapshotLength > 262144 {
			fmt.Fprintln(os.Stderr, "Error: --snapshot-length must be between 0 and 262144 bytes (0=default 262144).")
			flag.Usage()
			os.Exit(1)
		}
		if *bufferSize < 0 {
			fmt.Fprintln(os.Stderr, "Error: --buffer-size cannot be negative.")
			flag.Usage()
			os.Exit(1)
		}
	} else {
		// Warn if live capture parameters are used with file input
		config, _ := LoadConfig("") // Get default config for comparison
		if *snapshotLength != config.SnapshotLength || *bufferSize != config.BufferSize || *captureStats {
			fmt.Fprintln(os.Stderr, "Warning: Live capture parameters (--snapshot-length, --buffer-size, --capture-stats) are ignored when reading from file.")
		}
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