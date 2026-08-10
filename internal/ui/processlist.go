package ui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/Codexia-afk/Undertow/internal/process"
)

type ProcessListPanel struct {
	view    *tview.TextView
	tracker *process.Tracker
}

func NewProcessListPanel() *ProcessListPanel {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	tv.SetBorder(true).SetTitle(" Process Matrix — Active OS Socket-to-Process Correlation (Press 'P' to refresh) ").SetTitleAlign(tview.AlignLeft)
	tv.SetBorderColor(tcell.ColorDarkYellow)

	tr := process.NewTracker()
	return &ProcessListPanel{
		view:    tv,
		tracker: tr,
	}
}

func (plp *ProcessListPanel) View() *tview.TextView {
	return plp.view
}

func (plp *ProcessListPanel) Update() {
	plp.tracker.Refresh()
	procs := plp.tracker.GetProcessMatrix()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  [PID]    %-22s  %-12s  [EXECUTABLE PATH / DETAILS]\n", "PROCESS NAME", "USER"))
	sb.WriteString("  ------------------------------------------------------------------------------------\n")

	if len(procs) == 0 {
		sb.WriteString("  No active socket process mappings detected (requires root or lsof/netstat permissions).\n")
	} else {
		for _, p := range procs {
			path := p.ExecutablePath
			if path == "" {
				path = "-"
			}
			u := p.User
			if u == "" {
				u = "root"
			}
			sb.WriteString(fmt.Sprintf("  [%-5d]  [cyan]%-22s[white]  [yellow]%-12s[white]  %s\n", p.PID, p.ProcessName, u, path))
		}
	}

	plp.view.SetText(sb.String())
}
