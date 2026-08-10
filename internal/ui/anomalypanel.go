package ui

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"netwatch/internal/aggregator"
)

type AnomalyPanel struct {
	view *tview.TextView
}

func NewAnomalyPanel() *AnomalyPanel {
	tv := tview.NewTextView().
		SetDynamicColors(true)
	tv.SetBorder(true).SetTitle(" Security Anomalies & Alerts ").SetTitleAlign(tview.AlignLeft)
	tv.SetBorderColor(tcell.ColorDarkRed)
	tv.SetText(" [green]✓ No anomalies flagged[white]")
	return &AnomalyPanel{view: tv}
}

func (ap *AnomalyPanel) View() *tview.TextView {
	return ap.view
}

func (ap *AnomalyPanel) Update(snap *aggregator.Snapshot) {
	if len(snap.Anomalies) == 0 {
		ap.view.SetText(" [green]✓ No anomalies flagged[white]")
		return
	}

	// Show top 3 most recent anomalies
	start := 0
	if len(snap.Anomalies) > 3 {
		start = len(snap.Anomalies) - 3
	}

	var content string
	for i := len(snap.Anomalies) - 1; i >= start; i-- {
		evt := snap.Anomalies[i]
		ts := evt.Timestamp.Format("15:04:05")

		kindColor := "[bold red]"
		switch evt.Kind {
		case "PORT_SCAN":
			kindColor = "[bold orange]"
		case "LARGE_TRANSFER":
			kindColor = "[bold yellow]"
		case "BEHAVIORAL_DEVIATION":
			kindColor = "[bold magenta]"
		}

		content += fmt.Sprintf(" %s %s%-20s[white] Src: [cyan]%-15s[white] | %s\n",
			ts, kindColor, evt.Kind, evt.SourceIP, evt.Detail)
	}

	ap.view.SetText(content)
}
