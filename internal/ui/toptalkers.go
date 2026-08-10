package ui

import (
	"fmt"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/Codexia-afk/Undertow/internal/aggregator"
)

type TopTalkersPanel struct {
	table *tview.Table
}

func NewTopTalkersPanel() *TopTalkersPanel {
	table := tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false)
	table.SetBorder(true).SetTitle(" Top Talkers (Top 15 by Bandwidth) ").SetTitleAlign(tview.AlignLeft)
	table.SetBorderColor(tcell.ColorDarkCyan)

	headers := []string{"IP Address", "Bytes Sent", "Bytes Recv", "Packets", "Last Seen"}
	for col, h := range headers {
		cell := tview.NewTableCell(h).
			SetTextColor(tcell.ColorYellow).
			SetAttributes(tcell.AttrBold).
			SetSelectable(false)
		table.SetCell(0, col, cell)
	}

	return &TopTalkersPanel{table: table}
}

func (tp *TopTalkersPanel) View() *tview.Table {
	return tp.table
}

func (tp *TopTalkersPanel) Update(snap *aggregator.Snapshot) {
	// Preserve selection row if possible
	selectedRow, _ := tp.table.GetSelection()

	// Clear table except header row
	for i := tp.table.GetRowCount() - 1; i >= 1; i-- {
		tp.table.RemoveRow(i)
	}

	maxRows := 15
	if len(snap.TopTalkers) < maxRows {
		maxRows = len(snap.TopTalkers)
	}

	for i := 0; i < maxRows; i++ {
		t := snap.TopTalkers[i]
		row := i + 1

		lastSeen := "-"
		if !t.LastSeen.IsZero() {
			lastSeen = t.LastSeen.Format("15:04:05")
		}

		tp.table.SetCell(row, 0, tview.NewTableCell(t.IP).SetTextColor(tcell.ColorGreenYellow))
		tp.table.SetCell(row, 1, tview.NewTableCell(formatBytes(t.BytesSent)).SetTextColor(tcell.ColorWhite))
		tp.table.SetCell(row, 2, tview.NewTableCell(formatBytes(t.BytesRecv)).SetTextColor(tcell.ColorWhite))
		tp.table.SetCell(row, 3, tview.NewTableCell(fmt.Sprintf("%d", t.PacketsSent+t.PacketsRecv)).SetTextColor(tcell.ColorLightCyan))
		tp.table.SetCell(row, 4, tview.NewTableCell(lastSeen).SetTextColor(tcell.ColorGray))
	}

	if selectedRow > 0 && selectedRow <= maxRows {
		tp.table.Select(selectedRow, 0)
	} else if maxRows > 0 {
		tp.table.Select(1, 0)
	}
}

func (tp *TopTalkersPanel) SelectedIP() string {
	row, _ := tp.table.GetSelection()
	if row > 0 {
		cell := tp.table.GetCell(row, 0)
		if cell != nil {
			return cell.Text
		}
	}
	return ""
}
