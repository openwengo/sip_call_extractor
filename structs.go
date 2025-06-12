package main

import (
	"os"
	"time"

	"github.com/google/gopacket/pcapgo"
)

// Call holds information about an active SIP call.
type Call struct {
	CallID           string
	StartTime        time.Time
	OutputFilename   string
	SIPFrom          string
	SIPTo            string
	SDPPtime         int // default 20ms, updated from SDP
	LastActivityTime time.Time
	MediaSessions    []MediaSession
	RTPStreams       map[uint32]*RTPStreamStats
	PcapWriter       *pcapgo.Writer // For writing individual call PCAPs
	PcapFile         *os.File       // Underlying file for the PcapWriter, to allow explicit close
	// Mutex           sync.RWMutex   // For concurrent access to call data (if needed per call)
	
	// ERSPAN fields
	ERSPANSessions   map[uint16]*ERSPANSessionInfo // Key: SpanID
}

// ERSPANSessionInfo holds information about ERSPAN sessions associated with a call
type ERSPANSessionInfo struct {
	SpanID      uint16
	VLAN        uint16
	Version     uint8
	FirstSeen   time.Time
	PacketCount uint64
}

// MediaSession defines an IP address and port for media.
type MediaSession struct {
	IPAddress string
	Port      uint16
}

// RTPStreamStats holds statistics for an individual RTP stream.
type RTPStreamStats struct {
	SrcRTPEndpoint     string // e.g., "ip:port"
	DstRTPEndpoint     string
	RTPPacketCount     uint64
	ExpectedRTPPackets uint64 // To be calculated later
	LostPackets        uint64 // To be calculated later
	OutOfOrderCount    uint64
	DuplicateCount     uint64
	DeltasMs           []float64 // list of inter-packet arrival times in ms
	MaxDeltaMs         float64
	MinDeltaMs         float64   // Initialized to -1.0 to indicate not set
	AvgDeltaMs         float64   // To be calculated later
	LastArrivalTime    time.Time
	LastSeqNum         int16 // -1 for uninitialized (uint16 in RTP, use int16 for easier comparison with MaxSeqNumSeen)
	MaxSeqNumSeen      int16 // -1 for uninitialized
	ExpectedMinSeqNum  int16 // -1 for uninitialized (first seq num seen)
	ReceivedSeqNums    map[uint16]struct{}
}