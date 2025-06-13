package main

import (
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// IPv4FragmentKey uniquely identifies a fragmented packet stream
type IPv4FragmentKey struct {
	SrcIP          string
	DstIP          string
	Protocol       uint8
	Identification uint16
}

// IPv4Fragment represents a single IP fragment
type IPv4Fragment struct {
	Offset        uint16    // Fragment offset in bytes
	Length        uint16    // Fragment payload length
	MoreFragments bool      // More fragments flag
	Data          []byte    // Fragment payload data
	Timestamp     time.Time // When fragment was received
}

// IPv4FragmentBuffer manages reassembly of a fragmented packet
type IPv4FragmentBuffer struct {
	Key             IPv4FragmentKey
	Fragments       map[uint16]*IPv4Fragment // Key: fragment offset
	TotalLength     uint16                   // Expected total length (from last fragment)
	FirstSeen       time.Time
	LastSeen        time.Time
	Complete        bool
	ReassembledData []byte
	OriginalPacket  gopacket.Packet // Template for reconstructed packet
	ERSPANMeta      *ERSPANMetadata // ERSPAN metadata if applicable
}

// FragmentManager manages all active fragment reassembly operations
type FragmentManager struct {
	fragments    map[IPv4FragmentKey]*IPv4FragmentBuffer
	mutex        sync.RWMutex
	timeout      time.Duration
	maxFragments int
	stats        FragmentStats
	stop         chan struct{}
}

// FragmentStats tracks fragmentation statistics
type FragmentStats struct {
	TotalFragments     uint64
	ReassembledPackets uint64
	TimeoutFragments   uint64
	ActiveFragments    uint64
	DroppedFragments   uint64
}

// NewFragmentManager creates a new FragmentManager
func NewFragmentManager(timeout time.Duration, maxFragments int) *FragmentManager {
	fm := &FragmentManager{
		fragments:    make(map[IPv4FragmentKey]*IPv4FragmentBuffer),
		timeout:      timeout,
		maxFragments: maxFragments,
		stop:         make(chan struct{}),
	}
	// The cleanup routine is started by the main application, not automatically.
	return fm
}

// Start begins the background cleanup routine.
func (fm *FragmentManager) Start() {
	go fm.startCleanupRoutine()
}

// Stop gracefully stops the FragmentManager's background cleanup goroutine.
func (fm *FragmentManager) Stop() {
	close(fm.stop)
}

// isFragmented checks if an IPv4 packet is fragmented
func isFragmented(ip *layers.IPv4) bool {
	return ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0
}

// ProcessFragment handles a fragmented IPv4 packet
func (fm *FragmentManager) ProcessFragment(packet gopacket.Packet, ip *layers.IPv4, erspanMeta *ERSPANMetadata) gopacket.Packet {
	key := IPv4FragmentKey{
		SrcIP:          ip.SrcIP.String(),
		DstIP:          ip.DstIP.String(),
		Protocol:       uint8(ip.Protocol),
		Identification: ip.Id,
	}

	// Get the payload from the IP layer or from the packet layers after IP
	var payloadData []byte
	if len(ip.Payload) > 0 {
		payloadData = ip.Payload
	} else {
		// If IP payload is empty, extract from layers after IP
		ipFound := false
		for _, layer := range packet.Layers() {
			if ipFound {
				payloadData = append(payloadData, layer.LayerContents()...)
				if layer.LayerPayload() != nil {
					payloadData = append(payloadData, layer.LayerPayload()...)
				}
			}
			if layer.LayerType() == layers.LayerTypeIPv4 {
				ipFound = true
			}
		}
	}

	fragment := &IPv4Fragment{
		Offset:        ip.FragOffset * 8, // Convert to bytes
		Length:        uint16(len(payloadData)),
		MoreFragments: ip.Flags&layers.IPv4MoreFragments != 0,
		Data:          make([]byte, len(payloadData)),
		Timestamp:     packet.Metadata().Timestamp,
	}
	
	if len(payloadData) > 0 {
		copy(fragment.Data, payloadData)
	}

	if *debug {
		loggerDebug.Printf("Processing fragment: Offset=%d, Length=%d, More=%t, ID=%d, PayloadLen=%d",
			fragment.Offset, fragment.Length, fragment.MoreFragments, ip.Id, len(payloadData))
	}

	return fm.addFragment(key, fragment, packet, erspanMeta)
}

func (fm *FragmentManager) addFragment(key IPv4FragmentKey, fragment *IPv4Fragment, originalPacket gopacket.Packet, erspanMeta *ERSPANMetadata) gopacket.Packet {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	// Check fragment limit
	if len(fm.fragments) >= fm.maxFragments {
		fm.stats.DroppedFragments++
		return nil
	}

	buffer, exists := fm.fragments[key]
	if !exists {
		buffer = &IPv4FragmentBuffer{
			Key:            key,
			Fragments:      make(map[uint16]*IPv4Fragment),
			FirstSeen:      fragment.Timestamp,
			OriginalPacket: originalPacket,
			ERSPANMeta:     erspanMeta,
		}
		fm.fragments[key] = buffer
		fm.stats.ActiveFragments++
	}

	buffer.LastSeen = fragment.Timestamp
	buffer.Fragments[fragment.Offset] = fragment
	fm.stats.TotalFragments++

	// Check if we have the last fragment (determines total length)
	if !fragment.MoreFragments {
		buffer.TotalLength = fragment.Offset + fragment.Length
	}

	// Try to reassemble if we have total length
	if buffer.TotalLength > 0 {
		return fm.tryReassemble(buffer)
	}

	return nil
}

func (fm *FragmentManager) tryReassemble(buffer *IPv4FragmentBuffer) gopacket.Packet {
	// Check if we have all fragments by checking for contiguous data
	var currentOffset uint16 = 0
	for currentOffset < buffer.TotalLength {
		fragment, ok := buffer.Fragments[currentOffset]
		if !ok {
			// We're missing a fragment
			if *debug {
				loggerDebug.Printf("Missing fragment at offset %d for reassembly", currentOffset)
			}
			return nil
		}
		
		// Prevent infinite loop - ensure we're making progress
		if fragment.Length == 0 {
			if *debug {
				loggerDebug.Printf("Fragment with zero length at offset %d", currentOffset)
			}
			return nil
		}
		
		currentOffset += fragment.Length
		
		// Safety check to prevent infinite loop
		if currentOffset > 65535 {
			if *debug {
				loggerDebug.Printf("Fragment offset overflow, aborting reassembly")
			}
			return nil
		}
	}

	// Reassemble the packet
	buffer.ReassembledData = make([]byte, buffer.TotalLength)
	for offset, fragment := range buffer.Fragments {
		if offset+fragment.Length > buffer.TotalLength {
			if *debug {
				loggerDebug.Printf("Fragment extends beyond total length, aborting reassembly")
			}
			return nil
		}
		copy(buffer.ReassembledData[offset:offset+fragment.Length], fragment.Data)
	}

	buffer.Complete = true
	fm.stats.ReassembledPackets++
	fm.stats.ActiveFragments--
	delete(fm.fragments, buffer.Key)

	if *debug {
		loggerDebug.Printf("Successfully reassembled packet with %d bytes", buffer.TotalLength)
	}

	// Create reassembled packet
	return fm.createReassembledPacket(buffer)
}

func (fm *FragmentManager) createReassembledPacket(buffer *IPv4FragmentBuffer) gopacket.Packet {
	// Create a new packet based on the original packet's layers
	ipLayer := buffer.OriginalPacket.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		if *debug {
			loggerDebug.Printf("No IPv4 layer found in original packet")
		}
		return nil
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Create new IP header with reassembled payload
	newIp := *ip
	newIp.Flags = 0
	newIp.FragOffset = 0
	newIp.Length = 0 // Will be recalculated by FixLengths

	// Serialize the new packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Find all layers *before* the IP layer to reconstruct the packet properly
	var serializableLayers []gopacket.SerializableLayer
	for _, layer := range buffer.OriginalPacket.Layers() {
		if layer.LayerType() == layers.LayerTypeIPv4 {
			break
		}
		if sl, ok := layer.(gopacket.SerializableLayer); ok {
			serializableLayers = append(serializableLayers, sl)
		}
	}

	// Add the modified IP layer
	serializableLayers = append(serializableLayers, &newIp)
	
	// Add the reassembled payload as a separate layer
	serializableLayers = append(serializableLayers, gopacket.Payload(buffer.ReassembledData))

	if *debug {
		loggerDebug.Printf("Serializing %d layers for reassembled packet", len(serializableLayers))
	}

	err := gopacket.SerializeLayers(buf, opts, serializableLayers...)
	if err != nil {
		if *debug {
			loggerDebug.Printf("Error serializing reassembled packet: %v", err)
		}
		return nil
	}

	// Create the new packet with proper link layer type
	linkLayerType := layers.LayerTypeEthernet
	if buffer.OriginalPacket.LinkLayer() != nil {
		linkLayerType = buffer.OriginalPacket.LinkLayer().LayerType()
	}
	
	newPacket := gopacket.NewPacket(buf.Bytes(), linkLayerType, gopacket.Default)
	
	// Properly set the packet metadata
	if newPacket.Metadata() != nil {
		newPacket.Metadata().Timestamp = buffer.LastSeen
		newPacket.Metadata().CaptureLength = len(buf.Bytes())
		newPacket.Metadata().Length = len(buf.Bytes())
		
		// Copy other metadata from original packet if available
		if buffer.OriginalPacket.Metadata() != nil {
			originalMeta := buffer.OriginalPacket.Metadata()
			if originalMeta.InterfaceIndex != 0 {
				newPacket.Metadata().InterfaceIndex = originalMeta.InterfaceIndex
			}
		}
	}
	
	if *debug {
		loggerDebug.Printf("Created reassembled packet with %d bytes, CaptureLength=%d, Length=%d",
			len(buf.Bytes()), newPacket.Metadata().CaptureLength, newPacket.Metadata().Length)
	}
	
	return newPacket
}

func (fm *FragmentManager) startCleanupRoutine() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fm.cleanupExpiredFragments()
		case <-fm.stop:
			return
		}
	}
}

func (fm *FragmentManager) cleanupExpiredFragments() {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	now := time.Now()
	for key, buffer := range fm.fragments {
		if now.Sub(buffer.FirstSeen) > fm.timeout {
			delete(fm.fragments, key)
			fm.stats.TimeoutFragments++
			fm.stats.ActiveFragments--

			if *debug {
				loggerDebug.Printf("Fragment timeout: %s->%s Proto:%d ID:%d (had %d fragments)",
					key.SrcIP, key.DstIP, key.Protocol, key.Identification, len(buffer.Fragments))
			}
		}
	}
}

// GetStats returns a copy of the current fragment statistics
func (fm *FragmentManager) GetStats() FragmentStats {
	fm.mutex.RLock()
	defer fm.mutex.RUnlock()
	return fm.stats
}