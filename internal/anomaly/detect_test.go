package anomaly

import (
	"net"
	"testing"
	"time"

	"netwatch/internal/model"
)

func TestAnomalyDetector_PortScan(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ScanThreshold = 5
	detector := NewDetector(cfg)

	srcIP := net.ParseIP("192.168.1.50")
	now := time.Now()

	// Feed 4 distinct ports -> No anomaly expected
	for i := uint16(1); i <= 4; i++ {
		pkt := model.PacketInfo{
			Timestamp: now,
			SrcIP:     srcIP,
			DstPort:   i,
			Protocol:  "TCP",
		}
		events := detector.CheckPacket(pkt, nil)
		if len(events) > 0 {
			t.Fatalf("Unexpected anomaly event before threshold: %v", events)
		}
	}

	// Feed 5th distinct port -> PORT_SCAN anomaly expected
	pkt5 := model.PacketInfo{
		Timestamp: now,
		SrcIP:     srcIP,
		DstPort:   5,
		Protocol:  "TCP",
	}
	events := detector.CheckPacket(pkt5, nil)
	if len(events) != 1 {
		t.Fatalf("Expected 1 anomaly event, got %d", len(events))
	}
	if events[0].Kind != "PORT_SCAN" {
		t.Errorf("Expected PORT_SCAN kind, got %s", events[0].Kind)
	}
}

func TestAnomalyDetector_LargeTransfer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TransferThresholdMB = 1 // 1 MB for testing
	detector := NewDetector(cfg)

	flowKey := model.FlowKey{
		SrcIP:    "192.168.1.10",
		DstIP:    "10.0.0.1",
		SrcPort:  50000,
		DstPort:  443,
		Protocol: "TCP",
	}

	flowStat := &model.FlowStat{
		Key:       flowKey,
		BytesSent: 2 * 1024 * 1024, // 2 MB
	}

	pkt := model.PacketInfo{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("192.168.1.10"),
		DstIP:     net.ParseIP("10.0.0.1"),
		Protocol:  "TCP",
	}

	events := detector.CheckPacket(pkt, flowStat)
	if len(events) != 1 {
		t.Fatalf("Expected 1 LARGE_TRANSFER event, got %d", len(events))
	}
	if events[0].Kind != "LARGE_TRANSFER" {
		t.Errorf("Expected LARGE_TRANSFER, got %s", events[0].Kind)
	}

	// Subsequent packet on same flow should NOT duplicate alert
	events2 := detector.CheckPacket(pkt, flowStat)
	if len(events2) != 0 {
		t.Errorf("Expected 0 events on duplicate check, got %d", len(events2))
	}
}

func TestAnomalyDetector_SuspiciousDNS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DNSEntropyThreshold = 3.5
	detector := NewDetector(cfg)

	srcIP := net.ParseIP("192.168.1.100")

	// 1. Normal domain
	normalPkt := model.PacketInfo{
		Timestamp: time.Now(),
		SrcIP:     srcIP,
		Protocol:  "DNS",
		DNSQuery:  "google.com",
	}
	if len(detector.CheckPacket(normalPkt, nil)) != 0 {
		t.Errorf("Normal domain 'google.com' should not trigger anomaly")
	}

	// 2. High entropy DGA domain
	dgaPkt := model.PacketInfo{
		Timestamp: time.Now(),
		SrcIP:     srcIP,
		Protocol:  "DNS",
		DNSQuery:  "a9f87xqz12m9k3p7v5b.example.com",
	}
	dgaEvents := detector.CheckPacket(dgaPkt, nil)
	if len(dgaEvents) != 1 || dgaEvents[0].Kind != "SUSPICIOUS_DNS" {
		t.Errorf("DGA domain should trigger SUSPICIOUS_DNS anomaly")
	}
}
