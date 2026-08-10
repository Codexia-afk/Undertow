package decode

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestDecodePacket_TCP(t := nil) {
	// Synthesize an Ethernet + IPv4 + TCP SYN packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 10},
		DstIP:    []byte{93, 184, 216, 34},
	}
	tcp := &layers.TCP{
		SrcPort: 54321,
		DstPort: 80,
		SYN:     true,
		ACK:     false,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")))
	if err != nil {
		t.Fatalf("Failed to serialize layers: %v", err)
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	info := DecodePacket(packet)

	if info.SrcIP.String() != "192.168.1.10" {
		t.Errorf("Expected SrcIP 192.168.1.10, got %s", info.SrcIP.String())
	}
	if info.DstIP.String() != "93.184.216.34" {
		t.Errorf("Expected DstIP 93.184.216.34, got %s", info.DstIP.String())
	}
	if info.SrcPort != 54321 || info.DstPort != 80 {
		t.Errorf("Expected ports 54321 -> 80, got %d -> %d", info.SrcPort, info.DstPort)
	}
	if !info.TCPFlags.SYN {
		t.Errorf("Expected SYN flag to be true")
	}
	if info.Protocol != "HTTP" {
		t.Errorf("Expected Protocol HTTP, got %s", info.Protocol)
	}
	if info.HTTPMethod != "GET" || info.HTTPHost != "example.com" {
		t.Errorf("Expected HTTP GET example.com, got %s %s", info.HTTPMethod, info.HTTPHost)
	}
}

func TestDecodePacket_DNS(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	eth := &layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 10},
		DstIP:    []byte{8, 8, 8, 8},
	}
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 53,
	}
	_ = udp.SetNetworkLayerForChecksum(ip)
	dns := &layers.DNS{
		ID:    0x1234,
		QR:    false,
		OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("google.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}

	err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns)
	if err != nil {
		t.Fatalf("Failed to serialize DNS layers: %v", err)
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	info := DecodePacket(packet)

	if info.Protocol != "DNS" {
		t.Errorf("Expected Protocol DNS, got %s", info.Protocol)
	}
	if info.DNSQuery != "google.com" {
		t.Errorf("Expected DNSQuery google.com, got %s", info.DNSQuery)
	}
}
