package main

import (
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestFragmentReassembly(t *testing.T) {
	// Create a mock Ethernet packet to be fragmented
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
		DstMAC:       []byte{0, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{1, 2, 3, 4},
		DstIP:    []byte{5, 6, 7, 8},
		Id:       12345,
	}
	tcp := &layers.TCP{
		SrcPort: 1234,
		DstPort: 5678,
	}
	payload := []byte("this is a test payload that will be fragmented")
	tcp.SetNetworkLayerForChecksum(ip)

	// Serialize the TCP layer and its payload
	tcpBuf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(tcpBuf, gopacket.SerializeOptions{ComputeChecksums: true}, tcp, gopacket.Payload(payload))
	tcpPayloadBytes := tcpBuf.Bytes()

	// Fragment the TCP payload
	frag1Payload := tcpPayloadBytes[:24] // Must be multiple of 8
	frag2Payload := tcpPayloadBytes[24:]

	// Create the first fragment
	ip1 := *ip
	ip1.Flags = layers.IPv4MoreFragments
	ip1.FragOffset = 0
	buf1 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf1, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, &ip1, gopacket.Payload(frag1Payload))
	p1 := gopacket.NewPacket(buf1.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Create the second fragment
	ip2 := *ip
	ip2.Flags = 0
	ip2.FragOffset = uint16(len(frag1Payload) / 8)
	buf2 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf2, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, &ip2, gopacket.Payload(frag2Payload))
	p2 := gopacket.NewPacket(buf2.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Initialize FragmentManager
	fm := NewFragmentManager(1*time.Second, 10)
	defer fm.Stop()

	// Process fragments
	reassembled := fm.ProcessFragment(p1, p1.Layer(layers.LayerTypeIPv4).(*layers.IPv4), nil)
	if reassembled != nil {
		t.Fatal("Reassembled too early")
	}

	reassembled = fm.ProcessFragment(p2, p2.Layer(layers.LayerTypeIPv4).(*layers.IPv4), nil)
	if reassembled == nil {
		t.Fatal("Failed to reassemble")
	}

	// Verify reassembled packet
	ipLayer := reassembled.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		t.Fatal("Reassembled packet has no IP layer")
	}
	reassembledIp, _ := ipLayer.(*layers.IPv4)

	// The reassembled IP payload should contain the original TCP+payload
	if len(reassembledIp.Payload) != len(tcpPayloadBytes) {
		t.Errorf("Reassembled payload length is incorrect. Got %d bytes, want %d bytes", len(reassembledIp.Payload), len(tcpPayloadBytes))
	}
	
	// Verify the payload matches
	if string(reassembledIp.Payload) != string(tcpPayloadBytes) {
		t.Errorf("Reassembled payload content doesn't match")
	}
}

func TestFragmentReassemblyOutOfOrder(t *testing.T) {
	// Create a mock Ethernet packet to be fragmented
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
		DstMAC:       []byte{0, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{1, 2, 3, 4},
		DstIP:    []byte{5, 6, 7, 8},
		Id:       54321,
	}
	payload := []byte("this is another test payload that will be fragmented")
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 5678}
	tcp.SetNetworkLayerForChecksum(ip)

	// Serialize the TCP layer and its payload
	tcpBuf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(tcpBuf, gopacket.SerializeOptions{ComputeChecksums: true}, tcp, gopacket.Payload(payload))
	tcpPayloadBytes := tcpBuf.Bytes()

	// Fragment the TCP payload
	frag1Payload := tcpPayloadBytes[:16]
	frag2Payload := tcpPayloadBytes[16:32]
	frag3Payload := tcpPayloadBytes[32:]

	// Create the first fragment
	ip1 := *ip
	ip1.Flags = layers.IPv4MoreFragments
	ip1.FragOffset = 0
	buf1 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf1, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, &ip1, gopacket.Payload(frag1Payload))
	p1 := gopacket.NewPacket(buf1.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Create the second fragment
	ip2 := *ip
	ip2.Flags = layers.IPv4MoreFragments
	ip2.FragOffset = uint16(len(frag1Payload) / 8)
	buf2 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf2, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, &ip2, gopacket.Payload(frag2Payload))
	p2 := gopacket.NewPacket(buf2.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Create the third fragment
	ip3 := *ip
	ip3.Flags = 0
	ip3.FragOffset = uint16((len(frag1Payload) + len(frag2Payload)) / 8)
	buf3 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf3, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, &ip3, gopacket.Payload(frag3Payload))
	p3 := gopacket.NewPacket(buf3.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Initialize FragmentManager
	fm := NewFragmentManager(1*time.Second, 10)
	defer fm.Stop()

	// Process fragments out of order
	fm.ProcessFragment(p3, p3.Layer(layers.LayerTypeIPv4).(*layers.IPv4), nil)
	fm.ProcessFragment(p1, p1.Layer(layers.LayerTypeIPv4).(*layers.IPv4), nil)
	reassembled := fm.ProcessFragment(p2, p2.Layer(layers.LayerTypeIPv4).(*layers.IPv4), nil)

	if reassembled == nil {
		t.Fatal("Failed to reassemble out-of-order fragments")
	}

	// Verify reassembled packet
	ipLayer := reassembled.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		t.Fatal("Reassembled packet has no IP layer")
	}
	reassembledIp, _ := ipLayer.(*layers.IPv4)

	// The reassembled IP payload should contain the original TCP+payload
	if len(reassembledIp.Payload) != len(tcpPayloadBytes) {
		t.Errorf("Reassembled payload length is incorrect. Got %d bytes, want %d bytes", len(reassembledIp.Payload), len(tcpPayloadBytes))
	}
	
	// Verify the payload matches
	if string(reassembledIp.Payload) != string(tcpPayloadBytes) {
		t.Errorf("Reassembled payload content doesn't match")
	}
}

func TestFragmentTimeout(t *testing.T) {
	// Initialize FragmentManager with a short timeout
	fm := NewFragmentManager(10*time.Millisecond, 10)
	fm.Start() // Start the cleanup routine
	defer fm.Stop()

	// Create a mock Ethernet packet to be fragmented
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
		DstMAC:       []byte{0, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{1, 2, 3, 4},
		DstIP:    []byte{5, 6, 7, 8},
		Id:       11111,
	}
	payload := []byte("this is a test payload that will time out")
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 5678}
	tcp.SetNetworkLayerForChecksum(ip)

	// Serialize the TCP layer and its payload
	tcpBuf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(tcpBuf, gopacket.SerializeOptions{ComputeChecksums: true}, tcp, gopacket.Payload(payload))
	tcpPayloadBytes := tcpBuf.Bytes()

	// Fragment the TCP payload
	frag1Payload := tcpPayloadBytes[:24]

	// Create the first fragment
	ip1 := *ip
	ip1.Flags = layers.IPv4MoreFragments
	ip1.FragOffset = 0
	buf1 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf1, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, &ip1, gopacket.Payload(frag1Payload))
	p1 := gopacket.NewPacket(buf1.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Process the fragment
	fm.ProcessFragment(p1, p1.Layer(layers.LayerTypeIPv4).(*layers.IPv4), nil)

	// Wait for the timeout and trigger cleanup manually
	time.Sleep(20 * time.Millisecond)
	fm.cleanupExpiredFragments() // Manually trigger cleanup for testing

	// Check that the fragment has been cleaned up
	fm.mutex.RLock()
	if len(fm.fragments) != 0 {
		t.Errorf("Fragment was not cleaned up after timeout. %d fragments remaining", len(fm.fragments))
	}
	fm.mutex.RUnlock()

	stats := fm.GetStats()
	if stats.TimeoutFragments != 1 {
		t.Errorf("TimeoutFragments stat is incorrect. Got %d, want 1", stats.TimeoutFragments)
	}
}