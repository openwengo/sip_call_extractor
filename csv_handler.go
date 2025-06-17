package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
)

var (
	// CSV Writers and File Handles
	detectedCallsFile *os.File
	detectedCallsCSV  *csv.Writer
	statsFile         *os.File
	statsCSV          *csv.Writer
)

func initializeCSVs() error {
	// Ensure output directory exists
	err := os.MkdirAll(*outputDir, 0755) // *outputDir is from cli.go
	if err != nil {
		return fmt.Errorf("failed to create output directory '%s': %w", *outputDir, err)
	}

	// Initialize Detected Calls CSV
	detectedCallsPath := filepath.Join(*outputDir, *detectedCallsFilename) // *detectedCallsFilename from cli.go
	
	// Check if file exists to determine if we need to write headers
	_, err = os.Stat(detectedCallsPath)
	fileExists := !os.IsNotExist(err)
	
	// Open file in append mode if it exists, create if it doesn't
	detectedCallsFile, err = os.OpenFile(detectedCallsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open detected calls CSV file '%s': %w", detectedCallsPath, err)
	}
	detectedCallsCSV = csv.NewWriter(detectedCallsFile)
	
	// Only write headers if file is new
	if !fileExists {
		headersDetected := []string{"call_id", "start_timestamp", "output_pcap_filename", "sip_from", "sip_to", "s3_location"}
		if err := detectedCallsCSV.Write(headersDetected); err != nil {
			detectedCallsFile.Close() // Close file on error
			return fmt.Errorf("failed to write header to detected calls CSV '%s': %w", detectedCallsPath, err)
		}
		detectedCallsCSV.Flush()
		loggerInfo.Printf("Initialized new Detected Calls CSV at: %s", detectedCallsPath) // loggerInfo from main.go (or logging.go later)
	} else {
		loggerInfo.Printf("Appending to existing Detected Calls CSV at: %s", detectedCallsPath) // loggerInfo from main.go (or logging.go later)
	}

	// Initialize Statistics CSV
	statsPath := filepath.Join(*outputDir, *statsFilename) // *statsFilename from cli.go
	
	// Check if file exists to determine if we need to write headers
	_, err = os.Stat(statsPath)
	statsFileExists := !os.IsNotExist(err)
	
	// Open file in append mode if it exists, create if it doesn't
	statsFile, err = os.OpenFile(statsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open statistics CSV file '%s': %w", statsPath, err)
	}
	statsCSV = csv.NewWriter(statsFile)
	
	// Only write headers if file is new
	if !statsFileExists {
		headersStats := []string{
			"call_id", "start_timestamp", "output_pcap_filename", "sip_from", "sip_to",
			"ssrc_hex", "src_rtp_endpoint", "dst_rtp_endpoint",
			"rtp_packet_count", "expected_rtp_packets", "lost_packets",
			"out_of_order_count", "duplicate_count", "max_delta_ms", "min_delta_ms",
			"avg_delta_ms", "ptime_ms", "s3_location",
		}
		if err := statsCSV.Write(headersStats); err != nil {
			statsFile.Close() // Close file on error
			return fmt.Errorf("failed to write header to statistics CSV '%s': %w", statsPath, err)
		}
		statsCSV.Flush()
		loggerInfo.Printf("Initialized new Statistics CSV at: %s", statsPath) // loggerInfo from main.go (or logging.go later)
	} else {
		loggerInfo.Printf("Appending to existing Statistics CSV at: %s", statsPath) // loggerInfo from main.go (or logging.go later)
	}

	return nil
}

func closeCSVs() {
	if detectedCallsCSV != nil {
		detectedCallsCSV.Flush()
	}
	if detectedCallsFile != nil {
		if err := detectedCallsFile.Close(); err != nil {
			loggerInfo.Printf("Error closing detected calls CSV file: %v", err) // loggerInfo from main.go (or logging.go later)
		}
	}
	if statsCSV != nil {
		statsCSV.Flush()
	}
	if statsFile != nil {
		if err := statsFile.Close(); err != nil {
			loggerInfo.Printf("Error closing statistics CSV file: %v", err) // loggerInfo from main.go (or logging.go later)
		}
	}
	loggerInfo.Println("CSV files closed.") // loggerInfo from main.go (or logging.go later)
}