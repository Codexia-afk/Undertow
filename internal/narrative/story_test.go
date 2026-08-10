package narrative

import (
	"net"
	"strings"
	"testing"
	"time"

	"netwatch/internal/model"
)

func TestStoryTracker_GenerateNarrative(t *testing.T) {
	tracker := NewStoryTracker()
	now := time.Now()
	srcIP := "10.0.0.14"

	// 1. Record DNS Query
	tracker.RecordPacket(model.PacketInfo{
		Timestamp: now,
		SrcIP:     net.ParseIP(srcIP),
		Protocol:  "DNS",
		DNSQuery:  "api.example.com",
	})

	// 2. Record TCP Handshake
	tracker.RecordPacket(model.PacketInfo{
		Timestamp: now.Add(1 * time.Second),
		SrcIP:     net.ParseIP(srcIP),
		DstIP:     net.ParseIP("93.184.216.34"),
		DstPort:   443,
		Protocol:  "TCP",
		TCPFlags:  model.TCPFlagSet{SYN: true},
	})

	// 3. Record Anomaly
	tracker.RecordAnomaly(model.AnomalyEvent{
		Timestamp: now.Add(2 * time.Second),
		Kind:      "PORT_SCAN",
		SourceIP:  srcIP,
		Detail:    "Contacted 20 distinct ports",
	})

	narrative := tracker.GenerateNarrative(srcIP, false)

	if !strings.Contains(narrative, "10.0.0.14") {
		t.Errorf("Expected narrative to mention host IP 10.0.0.14")
	}
	if !strings.Contains(narrative, "api.example.com") {
		t.Errorf("Expected narrative to mention resolved domain api.example.com")
	}
	if !strings.Contains(narrative, "SECURITY ALERT") {
		t.Errorf("Expected narrative to contain security alert")
	}

	// Test IP Redaction
	redactedNarrative := tracker.GenerateNarrative(srcIP, true)
	if strings.Contains(redactedNarrative, "10.0.0.14") {
		t.Errorf("Expected IP 10.0.0.14 to be redacted")
	}
	if !strings.Contains(redactedNarrative, "HOST_A") {
		t.Errorf("Expected redacted IP alias HOST_A, got:\n%s", redactedNarrative)
	}
}
