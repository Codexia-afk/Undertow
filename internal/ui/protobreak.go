package ui

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"netwatch/internal/aggregator"
)

type ProtocolBreakdownPanel struct {
	view *tview.TextView
}

func NewProtocolBreakdownPanel() *ProtocolBreakdownPanel {
	tv := tview.NewTextView().
		SetDynamicColors(true)
	tv.SetBorder(true).SetTitle(" Protocol Breakdown ").SetTitleAlign(tview.AlignLeft)
	tv.SetBorderColor(tcell.ColorDarkCyan)
	return &ProtocolBreakdownPanel{view: tv}
}

func (pb *ProtocolBreakdownPanel) View() *tview.TextView {
	return pb.view
}

func (pb *ProtocolBreakdownPanel) Update(snap *aggregator.Snapshot) {
	protocols := []string{"TCP", "UDP", "ICMP", "DNS", "HTTP", "ARP", "Other"}
	total := snap.TotalPackets

	var content string
	maxBarWidth := 20

	for _, proto := range protocols {
		count := snap.ProtocolCounts[proto]
		var pct float64
		if total > 0 {
			pct = (float64(count) / float64(total)) * 100.0
		}

		barLen := int((pct / 100.0) * float64(maxBarWidth))
		if count > 0 && barLen == 0 {
			barLen = 1
		}

		bar := ""
		for i := 0; i < barLen; i++ {
			bar += "█"
		}
		for i := barLen; i < maxBarWidth; i++ {
			bar += "░"
		}

		colorStr := "[green]"
		switch proto {
		case "TCP":
			colorStr = "[cyan]"
		case "UDP":
			colorStr = "[blue]"
		case "DNS":
			colorStr = "[yellow]"
		case "HTTP":
			colorStr = "[magenta]"
		case "ICMP":
			colorStr = "[red]"
		}

		content += fmt.Sprintf(" %-6s %s%s[white] %6d  (%5.1f%%)\n", proto, colorStr, bar, count, pct)
	}

	pb.view.SetText(content)
}
