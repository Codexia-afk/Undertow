package ui

import (
	"fmt"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/Codexia-afk/Undertow/internal/aggregator"
	"github.com/Codexia-afk/Undertow/internal/replay"
)

type TopBar struct {
	view *tview.TextView
	iface string
}

func NewTopBar(iface string) *TopBar {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true)
	tv.SetBorder(true).SetTitle(" [bold yellow]UNDERTOW Dashboard[white] ").SetTitleAlign(tview.AlignLeft)
	tv.SetBorderColor(tcell.ColorDodgerBlue)
	return &TopBar{
		view:  tv,
		iface: iface,
	}
}

func (tb *TopBar) View() *tview.TextView {
	return tb.view
}

func (tb *TopBar) Update(snap *aggregator.Snapshot, paused bool, filterExpr string, replayStatus replay.ReplayStatus) {
	elapsed := time.Since(snap.StartTime).Truncate(time.Second)

	pauseState := "[green]LIVE[white]"
	if paused || replayStatus.IsPaused {
		pauseState = "[yellow]PAUSED[white]"
	}

	filterDisplay := "[gray]None[white]"
	if filterExpr != "" {
		filterDisplay = fmt.Sprintf("[yellow]%s[white]", filterExpr)
	}

	if replayStatus.IsReplay {
		curTimeStr := replayStatus.CurrentTime.Format("15:04:05")
		endTimeStr := replayStatus.EndTime.Format("15:04:05")
		text := fmt.Sprintf(
			" [bold yellow]REPLAY MODE[white] | [cyan]TIME:[white] %s / %s (%.1fx) | [cyan]FILTER:[white] %s | [cyan]PKTS:[white] [bold]%d[white] | [cyan]BYTES:[white] [bold]%s[white] | [cyan]STATUS:[white] %s",
			curTimeStr,
			endTimeStr,
			replayStatus.Speed,
			filterDisplay,
			snap.TotalPackets,
			formatBytes(snap.TotalBytes),
			pauseState,
		)
		tb.view.SetText(text)
		return
	}

	text := fmt.Sprintf(
		" [cyan]IFACE:[white] %-8s | [cyan]FILTER:[white] %s | [cyan]TIME:[white] %s | [cyan]PKTS:[white] [bold]%d[white] | [cyan]BYTES:[white] [bold]%s[white] | [cyan]DROPPED:[white] [red]%d[white] | [cyan]STATUS:[white] %s",
		tb.iface,
		filterDisplay,
		elapsed.String(),
		snap.TotalPackets,
		formatBytes(snap.TotalBytes),
		snap.DroppedPackets,
		pauseState,
	)

	tb.view.SetText(text)
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
