package ui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"netwatch/internal/aggregator"
	"netwatch/internal/model"
)

type PacketLogPanel struct {
	view   *tview.TextView
	paused bool
}

func NewPacketLogPanel() *PacketLogPanel {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	tv.SetBorder(true).SetTitle(" Live Packet Stream (Press 'p' to pause/scroll) ").SetTitleAlign(tview.AlignLeft)
	tv.SetBorderColor(tcell.ColorDarkCyan)
	return &PacketLogPanel{
		view: tv,
	}
}

func (pl *PacketLogPanel) View() *tview.TextView {
	return pl.view
}

func (pl *PacketLogPanel) TogglePause() bool {
	pl.paused = !pl.paused
	if pl.paused {
		pl.view.SetTitle(" Live Packet Stream [PAUSED] (Press 'p' to resume) ")
	} else {
		pl.view.SetTitle(" Live Packet Stream (Press 'p' to pause/scroll) ")
	}
	return pl.paused
}

func (pl *PacketLogPanel) IsPaused() bool {
	return pl.paused
}

func (pl *PacketLogPanel) Update(snap *aggregator.Snapshot, inAppFilter string) {
	if pl.paused {
		return
	}

	var sb strings.Builder
	for _, pkt := range snap.RecentPackets {
		if inAppFilter != "" && !matchesInAppFilter(pkt, inAppFilter) {
			continue
		}

		ts := pkt.Timestamp.Format("15:04:05.000")
		srcStr := "-"
		dstStr := "-"

		if pkt.SrcIP != nil {
			if pkt.SrcPort != 0 {
				srcStr = fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)
			} else {
				srcStr = pkt.SrcIP.String()
			}
		}
		if pkt.DstIP != nil {
			if pkt.DstPort != 0 {
				dstStr = fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort)
			} else {
				dstStr = pkt.DstIP.String()
			}
		}

		colorTag := "[white]"
		switch pkt.Protocol {
		case "TCP":
			colorTag = "[cyan]"
		case "UDP":
			colorTag = "[blue]"
		case "DNS":
			colorTag = "[yellow]"
		case "HTTP":
			colorTag = "[magenta]"
		case "TLS":
			colorTag = "[bold green]"
		case "ICMP":
			colorTag = "[red]"
		}

		extra := ""
		if pkt.Protocol == "TCP" {
			extra = " " + pkt.TCPFlags.String()
		} else if pkt.Protocol == "DNS" && pkt.DNSQuery != "" {
			extra = fmt.Sprintf(" Q:%s (%s)", pkt.DNSQuery, pkt.DNSType)
		} else if pkt.Protocol == "HTTP" && pkt.HTTPMethod != "" {
			extra = fmt.Sprintf(" %s %s%s", pkt.HTTPMethod, pkt.HTTPHost, pkt.HTTPPath)
		} else if pkt.Protocol == "TLS" && pkt.JA3Hash != "" {
			extra = fmt.Sprintf(" JA3:[yellow]%s[white] (%s)", pkt.JA3Hash[:8], pkt.JA3Label)
		}

		line := fmt.Sprintf("%s  %-21s -> %-21s  %s%-6s[white] %5d B%s\n",
			ts, srcStr, dstStr, colorTag, pkt.Protocol, pkt.Length, extra)
		sb.WriteString(line)
	}

	pl.view.SetText(sb.String())
	pl.view.ScrollToEnd()
}

func matchesInAppFilter(pkt model.PacketInfo, filterStr string) bool {
	filterLower := strings.ToLower(filterStr)
	if strings.Contains(strings.ToLower(pkt.Protocol), filterLower) {
		return true
	}
	if pkt.SrcIP != nil && strings.Contains(pkt.SrcIP.String(), filterLower) {
		return true
	}
	if pkt.DstIP != nil && strings.Contains(pkt.DstIP.String(), filterLower) {
		return true
	}
	if strings.Contains(strings.ToLower(pkt.DNSQuery), filterLower) {
		return true
	}
	if strings.Contains(strings.ToLower(pkt.HTTPHost), filterLower) {
		return true
	}
	return false
}
