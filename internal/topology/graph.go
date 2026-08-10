package topology

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Codexia-afk/Undertow/internal/aggregator"
	"github.com/Codexia-afk/Undertow/internal/model"
)

// RenderTopologyGraph renders an ASCII/Unicode network topology map from the aggregator snapshot.
func RenderTopologyGraph(snap *aggregator.Snapshot) string {
	if len(snap.Flows) == 0 {
		return "  [No active topology flows detected]"
	}

	// Sort flows descending by bytes sent
	flows := make([]model.FlowStat, len(snap.Flows))
	copy(flows, snap.Flows)

	sort.Slice(flows, func(i, j int) bool {
		return flows[i].BytesSent > flows[j].BytesSent
	})

	maxFlows := 10
	if len(flows) < maxFlows {
		maxFlows = len(flows)
	}

	var sb strings.Builder
	sb.WriteString("  [NETWORK TOPOLOGY & TRAFFIC FLOW GRAPH]\n\n")

	// Group hosts into local vs remote subnets
	localNodes := make(map[string]bool)
	remoteNodes := make(map[string]bool)

	for i := 0; i < maxFlows; i++ {
		f := flows[i]
		if isLocalIP(f.Key.SrcIP) {
			localNodes[f.Key.SrcIP] = true
		} else {
			remoteNodes[f.Key.SrcIP] = true
		}
		if isLocalIP(f.Key.DstIP) {
			localNodes[f.Key.DstIP] = true
		} else {
			remoteNodes[f.Key.DstIP] = true
		}
	}

	sb.WriteString("  ┌─── Local Subnet Endpoints ───┐\n")
	for ip := range localNodes {
		sb.WriteString(fmt.Sprintf("  │  [💻 %-15s]     │\n", ip))
	}
	sb.WriteString("  └──────────────────────────────┘\n\n")
	sb.WriteString("              │\n")
	sb.WriteString("              │  (Traffic Bridges & Flows)\n")
	sb.WriteString("              ▼\n\n")

	for i := 0; i < maxFlows; i++ {
		f := flows[i]
		arrow := "────>"
		if f.BytesSent > 10*1024*1024 {
			arrow = "<=====>"
		} else if f.BytesSent > 1024*1024 {
			arrow = "======>"
		} else if f.BytesSent > 100*1024 {
			arrow = "----->"
		}

		proto := f.Key.Protocol
		bytesFormatted := formatBytes(f.BytesSent)

		sb.WriteString(fmt.Sprintf("  [%-15s:%-5d] %s [%-15s:%-5d] (%s | %s)\n",
			f.Key.SrcIP, f.Key.SrcPort, arrow, f.Key.DstIP, f.Key.DstPort, proto, bytesFormatted))
	}

	return sb.String()
}

func isLocalIP(ip string) bool {
	return strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.16.") || strings.HasPrefix(ip, "127.")
}

func formatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
