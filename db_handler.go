package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

// Call states
const (
	CallStateActive   = "active"
	CallStateFinished = "finished"
	CallStateTimedOut = "timedout"
)

// DatabaseConfig holds database connection parameters
type DatabaseConfig struct {
	Host               string
	Port               int
	User               string
	Password           string
	Database           string
	SSLMode            string
	MaxOpenConnections int
	MaxIdleConnections int
	ConnMaxLifetime    time.Duration
	InstanceID         string
}

// RTPStreamStatJSON represents RTP stream statistics for JSON storage
type RTPStreamStatJSON struct {
	SSRC            string  `json:"ssrc"`
	SrcEndpoint     string  `json:"src_endpoint"`
	DstEndpoint     string  `json:"dst_endpoint"`
	PacketCount     int64   `json:"packet_count"`
	ExpectedPackets int64   `json:"expected_packets"`
	LostPackets     int64   `json:"lost_packets"`
	OutOfOrderCount int64   `json:"out_of_order_count"`
	DuplicateCount  int64   `json:"duplicate_count"`
	MaxDeltaMs      float64 `json:"max_delta_ms"`
	MinDeltaMs      float64 `json:"min_delta_ms"`
	AvgDeltaMs      float64 `json:"avg_delta_ms"`
	PtimeMs         int     `json:"ptime_ms"`
}

// DatabaseHandler manages database operations for call logging
type DatabaseHandler struct {
	db           *sql.DB
	mu           sync.RWMutex
	enabled      bool
	writeChan    chan dbOperation
	wg           sync.WaitGroup
	config       *DatabaseConfig
	reconnecting bool
	instanceID   string
}

type dbOperation struct {
	opType string
	data   interface{}
}

type callInsertData struct {
	CallID         string
	StartTimestamp time.Time
	PcapFilename   string
	SipFrom        string
	SipTo          string
	S3Location     string
	State          string
}

type callUpdateData struct {
	CallID      string
	SipFrom     string
	SipTo       string
	RTPStats    []RTPStreamStatJSON
	S3Location  string
	EndTime     *time.Time
	State       string
}

var (
	dbHandler *DatabaseHandler
	dbMutex   sync.RWMutex
)

// InitializeDatabase initializes the database connection and creates tables if needed
func InitializeDatabase(config *DatabaseConfig) error {
	if config == nil {
		loggerInfo.Println("No database configuration provided, using CSV fallback")
		return nil
	}

	dbHandler = &DatabaseHandler{
		enabled:    true,
		writeChan:  make(chan dbOperation, 1000), // Buffered channel for async operations
		config:     config,
		instanceID: config.InstanceID,
	}

	// Build connection string
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.User, config.Password, config.Database, config.SSLMode)

	var err error
	dbHandler.db, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool
	dbHandler.db.SetMaxOpenConns(config.MaxOpenConnections)
	dbHandler.db.SetMaxIdleConns(config.MaxIdleConnections)
	dbHandler.db.SetConnMaxLifetime(config.ConnMaxLifetime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := dbHandler.db.PingContext(ctx); err != nil {
		dbHandler.db.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Create table if it doesn't exist
	if err := createTable(dbHandler.db); err != nil {
		dbHandler.db.Close()
		return fmt.Errorf("failed to create table: %w", err)
	}

	// Start background worker for async operations
	dbHandler.wg.Add(1)
	go dbHandler.worker()

	// Start reconnection monitor
	dbHandler.wg.Add(1)
	go dbHandler.reconnectionMonitor()

	loggerInfo.Printf("Database connection established successfully")
	return nil
}

// createTable creates the calls table with proper schema
func createTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS sip_calls (
		call_id TEXT NOT NULL,
		instance_id TEXT NOT NULL,
		start_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
		end_timestamp TIMESTAMP WITH TIME ZONE,
		pcap_filename TEXT,
		sip_from TEXT,
		sip_to TEXT,
		s3_location TEXT,
		state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'finished', 'timedout')),
		rtp_statistics JSONB,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		PRIMARY KEY (call_id, instance_id)
	);
	
	-- Indexes for performance (aligned with database_setup.sql)
	CREATE INDEX IF NOT EXISTS idx_sip_calls_start_timestamp ON sip_calls(start_timestamp);
	CREATE INDEX IF NOT EXISTS idx_sip_calls_created_at ON sip_calls(created_at);
	CREATE INDEX IF NOT EXISTS idx_sip_calls_state_instance ON sip_calls(state, instance_id);
	CREATE INDEX IF NOT EXISTS idx_sip_calls_sip_from ON sip_calls(sip_from);
	CREATE INDEX IF NOT EXISTS idx_sip_calls_sip_to ON sip_calls(sip_to);
	`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := db.ExecContext(ctx, query)
	return err
}

// WriteCallToDatabase writes call information to database (async)
func WriteCallToDatabase(callID, sipFrom, sipTo, pcapFilename, s3Location string, startTime time.Time) {
	if !isDatabaseEnabled() {
		return // Fall back to CSV
	}

	data := callInsertData{
		CallID:         callID,
		StartTimestamp: startTime,
		PcapFilename:   pcapFilename,
		SipFrom:        sipFrom,
		SipTo:          sipTo,
		S3Location:     s3Location,
		State:          CallStateActive,
	}

	select {
	case dbHandler.writeChan <- dbOperation{opType: "insert", data: data}:
		// Successfully queued
	default:
		// Channel full, log warning and continue (don't block capture)
		loggerInfo.Printf("Database write queue full for call %s, skipping database write", callID)
	}
}

// UpdateCallInDatabase updates call with longer sip_from/sip_to or final RTP stats (async)
func UpdateCallInDatabase(callID, sipFrom, sipTo, s3Location string, rtpStats []RTPStreamStatJSON, endTime *time.Time, state string) {
	if !isDatabaseEnabled() {
		return // Fall back to CSV
	}

	data := callUpdateData{
		CallID:     callID,
		SipFrom:    sipFrom,
		SipTo:      sipTo,
		RTPStats:   rtpStats,
		S3Location: s3Location,
		EndTime:    endTime,
		State:      state,
	}

	select {
	case dbHandler.writeChan <- dbOperation{opType: "update", data: data}:
		// Successfully queued
		if *debug {
			loggerDebug.Printf("DEBUG: Successfully queued database update for call %s", callID)
		}
	default:
		// Channel full, log warning and continue (don't block capture)
		loggerInfo.Printf("Database update queue full for call %s, skipping database update", callID)
	}
}

// worker processes database operations asynchronously
func (dh *DatabaseHandler) worker() {
	defer dh.wg.Done()

	for op := range dh.writeChan {
		switch op.opType {
		case "insert":
			if data, ok := op.data.(callInsertData); ok {
				dh.insertCall(data)
			}
		case "update":
			if data, ok := op.data.(callUpdateData); ok {
				dh.updateCall(data)
			}
		case "flush":
			if flushDone, ok := op.data.(chan bool); ok {
				if *debug {
					loggerDebug.Printf("DEBUG: Database worker received flush signal")
				}
				// Signal that all previous operations have been processed
				flushDone <- true
			}
		}
	}
}

// insertCall performs the actual database insert
func (dh *DatabaseHandler) insertCall(data callInsertData) {
	dh.mu.RLock()
	db := dh.db
	enabled := dh.enabled
	dh.mu.RUnlock()
	
	if !enabled || db == nil {
		if *debug {
			loggerDebug.Printf("Database not available, skipping insert for call %s", data.CallID)
		}
		return
	}
	
	query := `
		INSERT INTO sip_calls (call_id, instance_id, start_timestamp, pcap_filename, sip_from, sip_to, s3_location, state, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
		ON CONFLICT (call_id, instance_id)
		DO UPDATE SET
			sip_from = CASE
				WHEN LENGTH($5) > LENGTH(sip_calls.sip_from) THEN $5
				ELSE sip_calls.sip_from
			END,
			sip_to = CASE
				WHEN LENGTH($6) > LENGTH(sip_calls.sip_to) THEN $6
				ELSE sip_calls.sip_to
			END,
			s3_location = COALESCE(NULLIF($7, ''), sip_calls.s3_location),
			updated_at = NOW()
		WHERE sip_calls.state = 'active'
	`

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := db.ExecContext(ctx, query,
		data.CallID, dh.instanceID, data.StartTimestamp, data.PcapFilename,
		data.SipFrom, data.SipTo, data.S3Location, data.State)

	if err != nil {
		loggerInfo.Printf("Failed to insert/update call %s in database: %v", data.CallID, err)
		// Note: Don't disable the handler completely - let reconnection monitor handle this
		if *debug {
			loggerDebug.Printf("Database error for call %s, reconnection monitor will attempt to reconnect", data.CallID)
		}
	} else if *debug {
		loggerDebug.Printf("Successfully inserted/updated call %s in database", data.CallID)
	}
}

// updateCall performs the actual database update
func (dh *DatabaseHandler) updateCall(data callUpdateData) {
	dh.mu.RLock()
	db := dh.db
	enabled := dh.enabled
	dh.mu.RUnlock()
	
	if *debug {
		loggerDebug.Printf("DEBUG: updateCall for %s - enabled: %t, db: %v", data.CallID, enabled, db != nil)
	}
	
	if !enabled || db == nil {
		if *debug {
			loggerDebug.Printf("Database not available, skipping update for call %s", data.CallID)
		}
		return
	}
	
	// Prepare RTP stats JSON
	rtpStatsJSON, err := json.Marshal(data.RTPStats)
	if err != nil {
		loggerInfo.Printf("Failed to marshal RTP stats for call %s: %v", data.CallID, err)
		return
	}

	query := `
		UPDATE sip_calls SET
			sip_from = CASE
				WHEN LENGTH($3) > LENGTH(sip_from) THEN $3
				ELSE sip_from
			END,
			sip_to = CASE
				WHEN LENGTH($4) > LENGTH(sip_to) THEN $4
				ELSE sip_to
			END,
			s3_location = COALESCE(NULLIF($5, ''), s3_location),
			rtp_statistics = $6,
			end_timestamp = COALESCE($7, end_timestamp),
			state = $8,
			updated_at = NOW()
		WHERE call_id = $1 AND instance_id = $2
	`

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = db.ExecContext(ctx, query,
		data.CallID, dbHandler.instanceID, data.SipFrom, data.SipTo, data.S3Location,
		string(rtpStatsJSON), data.EndTime, data.State)

	if err != nil {
		loggerInfo.Printf("Failed to update call %s in database: %v", data.CallID, err)
		// Note: Don't disable the handler completely - let reconnection monitor handle this
		if *debug {
			loggerDebug.Printf("Database error for call %s, reconnection monitor will attempt to reconnect", data.CallID)
		}
	} else if *debug {
		loggerDebug.Printf("Successfully updated call %s with RTP stats in database (state: %s)", data.CallID, data.State)
	}
}

// isDatabaseEnabled checks if the database handler is configured and not explicitly disabled.
// It no longer pings the database, relying on the async worker and reconnection logic.
func isDatabaseEnabled() bool {
	dbMutex.RLock()
	defer dbMutex.RUnlock()

	return dbHandler != nil && dbHandler.enabled && dbHandler.db != nil
}

// reconnectionMonitor periodically checks database connectivity and attempts reconnection
func (dh *DatabaseHandler) reconnectionMonitor() {
	defer dh.wg.Done()
	
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		// Check if we're still running and should be monitoring
		dh.mu.RLock()
		enabled := dh.enabled
		db := dh.db
		dh.mu.RUnlock()
		
		// If the handler was disabled via CloseDatabase, stop monitoring
		if !enabled && db == nil {
			return
		}
		
		// Test current connection and attempt reconnection if needed
		if !dh.testConnection() {
			dh.attemptReconnection()
		}
	}
}

// testConnection checks if the database connection is still working
func (dh *DatabaseHandler) testConnection() bool {
	dh.mu.RLock()
	db := dh.db
	dh.mu.RUnlock()
	
	if db == nil {
		return false
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		loggerInfo.Printf("Database connection lost: %v", err)
		return false
	}
	
	return true
}

// attemptReconnection tries to reconnect to the database
func (dh *DatabaseHandler) attemptReconnection() {
	dh.mu.Lock()
	defer dh.mu.Unlock()
	
	// Avoid multiple concurrent reconnection attempts
	if dh.reconnecting {
		return
	}
	dh.reconnecting = true
	defer func() { dh.reconnecting = false }()
	
	loggerInfo.Println("Attempting to reconnect to database...")
	
	// Close existing connection if it exists
	if dh.db != nil {
		dh.db.Close()
		dh.db = nil
	}
	
	// Build connection string
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		dh.config.Host, dh.config.Port, dh.config.User, dh.config.Password, 
		dh.config.Database, dh.config.SSLMode)
	
	// Attempt to create new connection
	var err error
	dh.db, err = sql.Open("postgres", connStr)
	if err != nil {
		loggerInfo.Printf("Failed to open database connection during reconnection: %v", err)
		dh.enabled = false
		return
	}
	
	// Configure connection pool
	dh.db.SetMaxOpenConns(dh.config.MaxOpenConnections)
	dh.db.SetMaxIdleConns(dh.config.MaxIdleConnections)
	dh.db.SetConnMaxLifetime(dh.config.ConnMaxLifetime)
	
	// Test the new connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := dh.db.PingContext(ctx); err != nil {
		loggerInfo.Printf("Failed to ping database during reconnection: %v", err)
		dh.db.Close()
		dh.db = nil
		dh.enabled = false
		return
	}
	
	// Ensure table still exists (in case database was recreated)
	if err := createTable(dh.db); err != nil {
		loggerInfo.Printf("Failed to verify/create table during reconnection: %v", err)
		dh.db.Close()
		dh.db = nil
		dh.enabled = false
		return
	}
	
	dh.enabled = true
	loggerInfo.Println("Database reconnection successful")
}

// FlushDatabaseOperations waits for all pending database operations to complete
func FlushDatabaseOperations() {
	dbMutex.RLock()
	handler := dbHandler
	dbMutex.RUnlock()
	
	if handler == nil {
		loggerInfo.Println("FlushDatabaseOperations: No database handler, nothing to flush")
		return
	}
	
	loggerInfo.Println("FlushDatabaseOperations: Waiting for all pending database operations to complete...")
	
	// Send a special flush operation to ensure all previous operations are processed
	flushDone := make(chan bool, 1)
	
	select {
	case handler.writeChan <- dbOperation{opType: "flush", data: flushDone}:
		// Wait for flush confirmation
		<-flushDone
		loggerInfo.Println("FlushDatabaseOperations: All database operations completed successfully")
	default:
		// Channel might be full or closed, but that's okay - operations will complete anyway
		loggerInfo.Println("FlushDatabaseOperations: Channel unavailable, but operations will complete during shutdown")
	}
}

// CloseDatabase gracefully shuts down the database handler
func CloseDatabase() {
	loggerInfo.Println("CloseDatabase: Starting database shutdown process...")
	dbMutex.Lock()
	defer dbMutex.Unlock()

	if dbHandler == nil {
		loggerInfo.Println("CloseDatabase: Database handler is nil, nothing to close")
		return
	}

	loggerInfo.Println("CloseDatabase: Disabling database handler to stop reconnection attempts...")
	// Disable handler to stop reconnection attempts
	dbHandler.mu.Lock()
	dbHandler.enabled = false
	dbHandler.mu.Unlock()

	loggerInfo.Println("CloseDatabase: Closing write channel and waiting for worker completion...")
	// Signal worker to stop and wait for completion
	close(dbHandler.writeChan)
	dbHandler.wg.Wait()
	loggerInfo.Println("CloseDatabase: Database worker completed all pending operations")

	if dbHandler.db != nil {
		if err := dbHandler.db.Close(); err != nil {
			loggerInfo.Printf("Error closing database connection: %v", err)
		} else {
			loggerInfo.Println("Database connection closed successfully")
		}
	}
}

// ConvertRTPStreamsToJSON converts RTP stream stats to JSON format
func ConvertRTPStreamsToJSON(rtpStreams map[uint32]*RTPStreamStats, call *Call) []RTPStreamStatJSON {
	var jsonStats []RTPStreamStatJSON
	
	ptimeMs := call.SDPPtime
	if ptimeMs <= 0 {
		ptimeMs = 20 // Default ptime
	}
	
	for ssrc, stats := range rtpStreams {
		jsonStat := RTPStreamStatJSON{
			SSRC:            fmt.Sprintf("%08x", ssrc),
			SrcEndpoint:     stats.SrcRTPEndpoint,
			DstEndpoint:     stats.DstRTPEndpoint,
			PacketCount:     int64(stats.RTPPacketCount),
			ExpectedPackets: int64(stats.ExpectedRTPPackets),
			LostPackets:     int64(stats.LostPackets),
			OutOfOrderCount: int64(stats.OutOfOrderCount),
			DuplicateCount:  int64(stats.DuplicateCount),
			MaxDeltaMs:      stats.MaxDeltaMs,
			MinDeltaMs:      stats.MinDeltaMs,
			AvgDeltaMs:      stats.AvgDeltaMs,
			PtimeMs:         ptimeMs,
		}
		jsonStats = append(jsonStats, jsonStat)
	}
	
	return jsonStats
}