package ui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"netwatch/internal/process"
)

type ProcessListPanel struct {
	view     *tview.TextView
	resolver *process.Resolver
}

func NewProcessListPanel() *ProcessListPanel {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	tv.SetBorder(true).SetTitle(" Active Socket-to-Process Mapping (Press 'P' to refresh) ").SetTitleAlign(tview.AlignLeft)
	tv.SetBorderColor(tcell.ColorDarkYellow)

	r := process.NewResolver()
	return &ProcessListPanel{
		view:     tv,
		resolver: r,
	}
}

func (plp *ProcessListPanel) View() *tview.TextView {
	return plp.view
}

func (plp *ProcessListPanel) Update() {
	plp.resolver.Refresh()
	procs := plp.resolver.GetAllProcesses()

	var sb strings.Builder
	sb.WriteString("  [PID]    %-25s  [PATH / DETAILS]\n")
	sb.WriteString("  --------------------------------------------------------\n")

	if len(procs) == 0 {
		sb.WriteString("  No socket process mappings detected (requires root or lsof/netstat permissions).\n")
	} else {
		for _, p := range procs {
			path := p.Path
			if path == "" {
				path = "-"
			}
			sb.WriteString(fmt.Sprintf("  [%-5d]  [cyan]%-25s[white]  %s\n", p.PID, p.Name, path))
		}
	}

	plp.view.SetText(sb.String())
}
