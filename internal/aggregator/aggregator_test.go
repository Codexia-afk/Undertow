package aggregator

import (
	"context"
	"net"
	"testing"
	"time"

	"netwatch/internal/model"
)

func TestAggregator_ConcurrencyAndRace(t *testing.T) {
	packetChan := make(chan model.PacketInfo, 100)
	var dropped uint64 = 5

	manager := NewStatsManager(60, 200, 100, &dropped, anomaly.DefaultConfig())
	agg := NewAggregator(packetChan, manager)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go agg.Run(ctx)

	// Feed 100 synthetic packets
	for i := 0; i < 100; i++ {
		pkt := model.PacketInfo{
			Timestamp: time.Now(),
			Length:    100,
			SrcIP:     net.ParseIP("192.168.1.10"),
			DstIP:     net.ParseIP("10.0.0.1"),
			Protocol:  "TCP",
			SrcPort:   12345,
			DstPort:   80,
		}
		if i%2 == 0 {
			pkt.Protocol = "UDP"
		}
		packetChan <- pkt
	}

	close(packetChan)

	// Give aggregator time to finish processing closed channel
	time.Sleep(100 * time.Millisecond)

	snap := manager.GetSnapshot()

	if snap.TotalPackets != 100 {
		t.Errorf("Expected 100 total packets, got %d", snap.TotalPackets)
	}
	if snap.TotalBytes != 10000 {
		t.Errorf("Expected 10000 total bytes, got %d", snap.TotalBytes)
	}
	if snap.DroppedPackets != 5 {
		t.Errorf("Expected 5 dropped packets, got %d", snap.DroppedPackets)
	}
	if snap.ProtocolCounts["TCP"] != 50 {
		t.Errorf("Expected 50 TCP packets, got %d", snap.ProtocolCounts["TCP"])
	}
	if snap.ProtocolCounts["UDP"] != 50 {
		t.Errorf("Expected 50 UDP packets, got %d", snap.ProtocolCounts["UDP"])
	}
	if len(snap.TopTalkers) != 2 {
		t.Errorf("Expected 2 top talkers, got %d", len(snap.TopTalkers))
	}
}
