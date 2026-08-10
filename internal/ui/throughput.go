package ui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/Codexia-afk/Undertow/internal/aggregator"
)

type ThroughputPanel struct {
	view *tview.TextView
}

func NewThroughputPanel() *ThroughputPanel {
	tv := tview.NewTextView().
		SetDynamicColors(true)
	tv.SetBorder(true).SetTitle(" Bandwidth Throughput (Last 60s) ").SetTitleAlign(tview.AlignLeft)
	tv.SetBorderColor(tcell.ColorDarkCyan)
	return &ThroughputPanel{view: tv}
}

func (tp *ThroughputPanel) View() *tview.TextView {
	return tp.view
}

func (tp *ThroughputPanel) Update(snap *aggregator.Snapshot) {
	history := snap.ThroughputHistory
	if len(history) == 0 {
		tp.view.SetText(" Waiting for bandwidth samples...")
		return
	}

	var maxVal uint64
	for _, val := range history {
		if val > maxVal {
			maxVal = val
		}
	}

	blocks := []rune{' ', ' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	var sb strings.Builder

	currentRate := uint64(0)
	if len(history) > 0 {
		currentRate = history[len(history)-1]
	}

	sb.WriteString(fmt.Sprintf(" Current Rate: [bold green]%s/s[white]  (Peak: [yellow]%s/s[white])\n\n ",
		formatBytes(currentRate), formatBytes(maxVal)))

	for _, val := range history {
		var index int
		if maxVal > 0 {
			index = int((float64(val) / float64(maxVal)) * float64(len(blocks)-1))
		}
		if index >= len(blocks) {
			index = len(blocks) - 1
		}

		color := "[green]"
		if index > 6 {
			color = "[red]"
		} else if index > 3 {
			color = "[yellow]"
		}

		sb.WriteString(fmt.Sprintf("%s%c[white]", color, blocks[index]))
	}

	tp.view.SetText(sb.String())
}
