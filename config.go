package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config represents all configuration options that can be set via config file
type Config struct {
	// Core parameters
	InputFile             string
	Interface             string
	Filter                string
	SipPortsRange         string
	OutputDir             string
	DetectedCallsFilename string
	StatsFilename         string
	CallTimeout           time.Duration
	Debug                 bool
	InstanceID            string // Instance identifier; defaults to hostname if empty

	// RTP payload clearing parameters
	NoRtpDump                        bool
	NoRtpDumpForCallIdPattern        string
	NoRtpDumpExceptForCallIdPattern  string
	NoRtpDumpForFromPattern          string
	NoRtpDumpExceptForFromPattern    string
	NoRtpDumpForToPattern            string
	NoRtpDumpExceptForToPattern      string

	// S3 upload parameters
	AutoUploadToS3 bool
	S3URI          string
	S3Region       string

	// ERSPAN parameters
	EnableERSPAN   bool
	ErspanSpanIDs  string
	ErspanVLANs    string
	LogERSPANStats bool

	// Fragmentation parameters
	EnableFragmentation bool
	FragmentTimeout     time.Duration
	MaxFragments        int

	// Live capture parameters (only applicable for interface mode)
	SnapshotLength int  // Snapshot length in bytes (0=262144, max=262144)
	BufferSize     int  // OS capture buffer size in KiB (default: 0 = system default)
	CaptureStats   bool // Enable capture statistics reporting (default: false)

	// Database parameters
	DatabaseHost         string
	DatabasePort         int
	DatabaseUser         string
	DatabasePassword     string
	DatabaseName         string
	DatabaseSSLMode      string
	DatabaseMaxOpenConns int
	DatabaseMaxIdleConns int
	DatabaseConnLifetime time.Duration
}

// DefaultConfig returns a Config struct with default values
func DefaultConfig() *Config {
	return &Config{
		// Core defaults
		InputFile:             "",
		Interface:             "",
		Filter:                "udp",
		SipPortsRange:         "",
		OutputDir:             ".",
		DetectedCallsFilename: "detected_calls.csv",
		StatsFilename:         "calls_statistics.csv",
		CallTimeout:           5 * time.Minute,
		Debug:                 false,
		InstanceID:            "",

		// RTP payload clearing defaults
		NoRtpDump:                        false,
		NoRtpDumpForCallIdPattern:        "",
		NoRtpDumpExceptForCallIdPattern:  "",
		NoRtpDumpForFromPattern:          "",
		NoRtpDumpExceptForFromPattern:    "",
		NoRtpDumpForToPattern:            "",
		NoRtpDumpExceptForToPattern:      "",

		// S3 upload defaults
		AutoUploadToS3: false,
		S3URI:          "",
		S3Region:       "",

		// ERSPAN defaults
		EnableERSPAN:   false,
		ErspanSpanIDs:  "",
		ErspanVLANs:    "",
		LogERSPANStats: false,

		// Fragmentation defaults
		EnableFragmentation: true,
		FragmentTimeout:     30 * time.Second,
		MaxFragments:        1000,

		// Live capture defaults
		SnapshotLength: 2000, // Keep 2000 as default, but 0 will mean 262144
		BufferSize:     0,    // 0 means use system default
		CaptureStats:   false,

		// Database defaults
		DatabaseHost:         "",
		DatabasePort:         5432,
		DatabaseUser:         "",
		DatabasePassword:     "",
		DatabaseName:         "",
		DatabaseSSLMode:      "require",
		DatabaseMaxOpenConns: 25,
		DatabaseMaxIdleConns: 10,
		DatabaseConnLifetime: 1 * time.Hour,
	}
}

// LoadConfig loads configuration from the specified file paths in order of priority:
// 1. configPath (if provided via --config)
// 2. $XDG_CONFIG_HOME/sipcapture/sipcapture.conf
// 3. /etc/sipcapture/sipcapture.conf
// Returns the loaded config or default config if no files are found
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()

	// Determine config file paths to try
	var configPaths []string

	if configPath != "" {
		// User specified config file via --config
		configPaths = append(configPaths, configPath)
	} else {
		// Try standard locations
		if xdgPath := getXDGConfigPath(); xdgPath != "" {
			configPaths = append(configPaths, xdgPath)
		}
		configPaths = append(configPaths, "/etc/sipcapture/sipcapture.conf")
	}

	// Try to load from each path
	var loadedFrom string
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			if err := loadConfigFromFile(config, path); err != nil {
				return nil, fmt.Errorf("error loading config from %s: %w", path, err)
			}
			loadedFrom = path
			break
		}
	}

	if loadedFrom != "" {
		fmt.Fprintf(os.Stderr, "INFO: Loaded configuration from: %s\n", loadedFrom)
	}

	// Apply environment variable fallbacks for database configuration
	applyDatabaseEnvVars(config)

	return config, nil
}

// applyDatabaseEnvVars applies environment variable overrides for database configuration
// Environment variables take precedence over config file values
func applyDatabaseEnvVars(config *Config) {
	// Environment variables override config file values
	if envHost := os.Getenv("DB_HOST"); envHost != "" {
		config.DatabaseHost = envHost
	}
	if envName := os.Getenv("DB_NAME"); envName != "" {
		config.DatabaseName = envName
	}
	if envUser := os.Getenv("DB_USER"); envUser != "" {
		config.DatabaseUser = envUser
	}
	if envPassword := os.Getenv("DB_PASSWORD"); envPassword != "" {
		config.DatabasePassword = envPassword
	}
	if envSSLMode := os.Getenv("DB_SSL_MODE"); envSSLMode != "" {
		config.DatabaseSSLMode = envSSLMode
	}
	// DB_PORT environment variable support
	if envPort := os.Getenv("DB_PORT"); envPort != "" {
		if port, err := strconv.Atoi(envPort); err == nil && port > 0 && port <= 65535 {
			config.DatabasePort = port
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: Invalid DB_PORT environment variable: %s\n", envPort)
		}
	}
}

// getXDGConfigPath returns the XDG config directory path for sipcapture
func getXDGConfigPath() string {
	xdgConfigHome := os.Getenv("XDG_CONFIG_HOME")
	if xdgConfigHome == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		xdgConfigHome = filepath.Join(homeDir, ".config")
	}
	return filepath.Join(xdgConfigHome, "sipcapture", "sipcapture.conf")
}

// loadConfigFromFile loads configuration from an INI-style file
func loadConfigFromFile(config *Config, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Skip section headers [section]
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue
		}

		// Parse key=value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid line %d: %s", lineNum, line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if err := setConfigValue(config, key, value); err != nil {
			return fmt.Errorf("error on line %d: %w", lineNum, err)
		}
	}

	return scanner.Err()
}

// setConfigValue sets a configuration value based on the key
func setConfigValue(config *Config, key, value string) error {
	switch key {
	// Core parameters
	case "input-file":
		config.InputFile = value
	case "interface":
		config.Interface = value
	case "filter":
		config.Filter = value
	case "sip-ports-range":
		config.SipPortsRange = value
	case "output-dir":
		config.OutputDir = value
	case "detected-calls-filename":
		config.DetectedCallsFilename = value
	case "stats-filename":
		config.StatsFilename = value
	case "call-timeout":
		duration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid duration for call-timeout: %w", err)
		}
		config.CallTimeout = duration
	case "debug":
		debug, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean for debug: %w", err)
		}
		config.Debug = debug
	case "instance-id":
		config.InstanceID = value

	// RTP payload clearing parameters
	case "no-rtp-dump":
		noRtpDump, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean for no-rtp-dump: %w", err)
		}
		config.NoRtpDump = noRtpDump
	case "no-rtp-dump-for-callid-pattern":
		config.NoRtpDumpForCallIdPattern = value
	case "no-rtp-dump-except-for-callid-pattern":
		config.NoRtpDumpExceptForCallIdPattern = value
	case "no-rtp-dump-for-from-pattern":
		config.NoRtpDumpForFromPattern = value
	case "no-rtp-dump-except-for-from-pattern":
		config.NoRtpDumpExceptForFromPattern = value
	case "no-rtp-dump-for-to-pattern":
		config.NoRtpDumpForToPattern = value
	case "no-rtp-dump-except-for-to-pattern":
		config.NoRtpDumpExceptForToPattern = value

	// S3 upload parameters
	case "auto-upload-to-s3":
		autoUpload, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean for auto-upload-to-s3: %w", err)
		}
		config.AutoUploadToS3 = autoUpload
	case "s3-uri":
		expandedURI, err := expandHostnameMacros(value)
		if err != nil {
			// Log warning but continue with original value
			fmt.Fprintf(os.Stderr, "Warning: Failed to expand hostname macro in s3-uri: %v\n", err)
			config.S3URI = value
		} else {
			config.S3URI = expandedURI
		}
	case "s3-region":
		config.S3Region = value

	// ERSPAN parameters
	case "enable-erspan":
		enableERSPAN, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean for enable-erspan: %w", err)
		}
		config.EnableERSPAN = enableERSPAN
	case "erspan-span-ids":
		config.ErspanSpanIDs = value
	case "erspan-vlans":
		config.ErspanVLANs = value
	case "log-erspan-stats":
		logStats, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean for log-erspan-stats: %w", err)
		}
		config.LogERSPANStats = logStats

	// Fragmentation parameters
	case "enable-fragmentation":
		enableFrag, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean for enable-fragmentation: %w", err)
		}
		config.EnableFragmentation = enableFrag
	case "fragment-timeout":
		duration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid duration for fragment-timeout: %w", err)
		}
		config.FragmentTimeout = duration
	case "max-fragments":
		maxFrags, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid integer for max-fragments: %w", err)
		}
		config.MaxFragments = maxFrags

	// Live capture parameters
	case "snapshot-length":
		snaplen, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid integer for snapshot-length: %w", err)
		}
		if snaplen < 0 || snaplen > 262144 {
			return fmt.Errorf("snapshot-length must be between 0 and 262144 bytes (0=default 262144)")
		}
		config.SnapshotLength = snaplen
	case "buffer-size":
		bufSize, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid integer for buffer-size: %w", err)
		}
		if bufSize < 0 {
			return fmt.Errorf("buffer-size cannot be negative")
		}
		config.BufferSize = bufSize
	case "capture-stats":
		captureStats, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean for capture-stats: %w", err)
		}
		config.CaptureStats = captureStats

	// Database parameters
	case "database-host":
		config.DatabaseHost = value
	case "database-port":
		port, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid integer for database-port: %w", err)
		}
		if port <= 0 || port > 65535 {
			return fmt.Errorf("database-port must be between 1 and 65535")
		}
		config.DatabasePort = port
	case "database-user":
		config.DatabaseUser = value
	case "database-password":
		config.DatabasePassword = value
	case "database-name":
		config.DatabaseName = value
	case "database-ssl-mode":
		config.DatabaseSSLMode = value
	case "database-max-open-conns":
		conns, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid integer for database-max-open-conns: %w", err)
		}
		if conns <= 0 {
			return fmt.Errorf("database-max-open-conns must be greater than 0")
		}
		config.DatabaseMaxOpenConns = conns
	case "database-max-idle-conns":
		conns, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid integer for database-max-idle-conns: %w", err)
		}
		if conns <= 0 {
			return fmt.Errorf("database-max-idle-conns must be greater than 0")
		}
		config.DatabaseMaxIdleConns = conns
	case "database-conn-lifetime":
		duration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid duration for database-conn-lifetime: %w", err)
		}
		config.DatabaseConnLifetime = duration

	default:
		return fmt.Errorf("unknown configuration key: %s", key)
	}

	return nil
}
// getHostnameShort executes 'hostname -s' and returns the short hostname
func getHostnameShort() (string, error) {
	cmd := exec.Command("hostname", "-s")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute 'hostname -s': %w", err)
	}
	
	hostname := strings.TrimSpace(string(output))
	if hostname == "" {
		return "", fmt.Errorf("hostname command returned empty string")
	}
	
	return hostname, nil
}

// expandHostnameMacros replaces {hostname} macro with actual hostname in the input string
func expandHostnameMacros(input string) (string, error) {
	if !strings.Contains(input, "{hostname}") {
		// No macro to expand, return as-is
		return input, nil
	}
	
	hostname, err := getHostnameShort()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname for macro expansion: %w", err)
	}
	
	// Replace all occurrences of {hostname} with the actual hostname
	expanded := strings.ReplaceAll(input, "{hostname}", hostname)
	return expanded, nil
}