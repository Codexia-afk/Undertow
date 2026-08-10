package topology

import (
	"strings"
	"testing"
	"time"

	"netwatch/internal/aggregator"
	"netwatch/internal/model"
)

func TestRenderTopologyGraph(t *testing.T) {
	snap := &aggregator.Snapshot{
		Flows: []model.FlowStat{
			{
				Key: model.FlowKey{
					SrcIP:    "192.168.1.10",
					DstIP:    "93.184.216.34",
					SrcPort:  54321,
					DstPort:  443,
					Protocol: "TCP",
				},
				BytesSent:   5 * 1024 * 1024,
				PacketsSent: 1000,
				LastSeen:    time.Now(),
			},
		},
	}

	graphStr := RenderTopologyGraph(snap)

	if !strings.Contains(graphStr, "NETWORK TOPOLOGY & TRAFFIC FLOW GRAPH") {
		t.Errorf("Expected graph title")
	}
	if !strings.Contains(graphStr, "192.168.1.10") {
		t.Errorf("Expected local IP 192.168.1.10 in graph output")
	}
	if !strings.Contains(graphStr, "93.184.216.34") {
		t.Errorf("Expected remote IP 93.184.216.34 in graph output")
	}
}
