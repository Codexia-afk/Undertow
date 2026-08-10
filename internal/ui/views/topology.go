package views

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/Codexia-afk/Undertow/internal/aggregator"
	"github.com/Codexia-afk/Undertow/internal/model"
)

// TopologyView renders a text-mode ASCII/Unicode network node-and-edge graph using tview.
type TopologyView struct {
	view *tview.TextView
}

// NewTopologyView constructs a new TopologyView component.
func NewTopologyView() *TopologyView {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	tv.SetBorder(true).SetTitle(" ASCII Network Topology Graph View ").SetTitleAlign(tview.AlignLeft)
	tv.SetBorderColor(tcell.ColorCyan)

	return &TopologyView{
		view: tv,
	}
}

// View returns the underlying tview primitive.
func (tv *TopologyView) View() *tview.TextView {
	return tv.view
}

// Update repaints the ASCII topology graph from the latest statistics snapshot.
func (tv *TopologyView) Update(snap *aggregator.Snapshot) {
	if snap == nil || len(snap.Flows) == 0 {
		tv.view.SetText("\n  [yellow][!] No active network topology flows detected[white]\n")
		return
	}

	flows := make([]model.FlowStat, len(snap.Flows))
	copy(flows, snap.Flows)

	sort.Slice(flows, func(i, j int) bool {
		return flows[i].BytesSent > flows[j].BytesSent
	})

	maxFlows := 12
	if len(flows) < maxFlows {
		maxFlows = len(flows)
	}

	var sb strings.Builder
	sb.WriteString("  [bold yellow]📡 UNDERTOW ASCII NETWORK TOPOLOGY GRAPH[white]\n")
	sb.WriteString("  ====================================================================================\n\n")

	localHosts := make(map[string]bool)
	remoteHosts := make(map[string]bool)

	for i := 0; i < maxFlows; i++ {
		f := flows[i]
		if isLocalIP(f.Key.SrcIP) {
			localHosts[f.Key.SrcIP] = true
		} else {
			remoteHosts[f.Key.SrcIP] = true
		}
		if isLocalIP(f.Key.DstIP) {
			localHosts[f.Key.DstIP] = true
		} else {
			remoteHosts[f.Key.DstIP] = true
		}
	}

	sb.WriteString("  ┌─── [cyan]LOCAL SUBNET & HOST NODES[white] ───┐\n")
	for ip := range localHosts {
		sb.WriteString(fmt.Sprintf("  │   💻 [bold green]%-18s[white]        │\n", ip))
	}
	sb.WriteString("  └──────────────────────────────────┘\n")
	sb.WriteString("                   │\n")
	sb.WriteString("                   │  [yellow](Default Gateway & Traffic Bridge)[white]\n")
	sb.WriteString("                   ▼\n\n")

	for i := 0; i < maxFlows; i++ {
		f := flows[i]
		arrow := "[blue]────>[white]"
		if f.BytesSent > 10*1024*1024 {
			arrow = "[bold red]<=====>[white]"
		} else if f.BytesSent > 1024*1024 {
			arrow = "[bold yellow]======>[white]"
		} else if f.BytesSent > 100*1024 {
			arrow = "[green]----->[white]"
		}

		bytesFormatted := formatBytes(f.BytesSent)
		proto := f.Key.Protocol

		sb.WriteString(fmt.Sprintf("  [%-15s:%-5d] %s [%-15s:%-5d] ([cyan]%-4s[white] | [yellow]%s[white])\n",
			f.Key.SrcIP, f.Key.SrcPort, arrow, f.Key.DstIP, f.Key.DstPort, proto, bytesFormatted))
	}

	tv.view.SetText(sb.String())
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
