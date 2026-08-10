package views

import (
	"strings"
	"testing"
	"time"

	"github.com/Codexia-afk/Undertow/internal/aggregator"
	"github.com/Codexia-afk/Undertow/internal/model"
)

func TestTopologyView_Update(t *testing.T) {
	tv := NewTopologyView()
	if tv == nil {
		t.Fatalf("Expected non-nil TopologyView")
	}

	snap := &aggregator.Snapshot{
		Flows: []model.FlowStat{
			{
				Key: model.FlowKey{
					SrcIP:    "192.168.1.50",
					DstIP:    "142.250.190.46",
					SrcPort:  45678,
					DstPort:  443,
					Protocol: "TLS",
				},
				BytesSent:   2000000,
				PacketsSent: 1500,
				LastSeen:    time.Now(),
			},
		},
	}

	tv.Update(snap)
	text := tv.view.GetText(false)

	if !strings.Contains(text, "UNDERTOW ASCII NETWORK TOPOLOGY GRAPH") {
		t.Errorf("Expected topology header text")
	}
	if !strings.Contains(text, "192.168.1.50") {
		t.Errorf("Expected local IP 192.168.1.50 in topology rendering")
	}
}
