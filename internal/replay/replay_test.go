package replay

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestRecorderAndReplayEngine(t *testing.T) {
	tempDir := t.TempDir()
	pcapFile := filepath.Join(tempDir, "sample_test.pcap")

	// 1. Record synthetic packets
	rec, err := NewRecorder(pcapFile, 65535, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("Failed to create recorder: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	eth := &layers.Ethernet{EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 10},
		DstIP:    []byte{10, 0, 0, 1},
	}
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 80}

	now := time.Now()
	for i := 0; i < 5; i++ {
		_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("TEST_PAYLOAD")))
		pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		pkt.Metadata().Timestamp = now.Add(time.Duration(i) * time.Second)
		pkt.Metadata().CaptureLength = len(buf.Bytes())
		pkt.Metadata().Length = len(buf.Bytes())

		if err := rec.WritePacket(pkt); err != nil {
			t.Fatalf("Failed to write packet: %v", err)
		}
	}
	rec.Close()

	// 2. Replay recorded pcap file
	engine, outChan, err := NewReplayEngine(pcapFile, 10)
	if err != nil {
		t.Fatalf("Failed to create replay engine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Run(ctx)

	var replayed []string
	for pkt := range outChan {
		replayed = append(replayed, pkt.Protocol)
	}

	if len(replayed) != 5 {
		t.Errorf("Expected 5 replayed packets, got %d", len(replayed))
	}

	status := engine.Status()
	if !status.IsReplay {
		t.Errorf("Expected IsReplay to be true")
	}

	_ = os.Remove(pcapFile)
}
