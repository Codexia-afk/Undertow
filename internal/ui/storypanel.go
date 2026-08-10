package ui

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"netwatch/internal/aggregator"
)

type StoryPanel struct {
	view      *tview.TextView
	redactIPs bool
}

func NewStoryPanel(redactIPs bool) *StoryPanel {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	tv.SetBorder(true).SetTitle(" Host Flow Story Narrative (Press 'n' to select host) ").SetTitleAlign(tview.AlignLeft)
	tv.SetBorderColor(tcell.ColorDarkGreen)
	tv.SetText(" Select an IP in the Top Talkers table and press 'n' or switch tab to generate narrative.")
	return &StoryPanel{
		view:      tv,
		redactIPs: redactIPs,
	}
}

func (sp *StoryPanel) View() *tview.TextView {
	return sp.view
}

func (sp *StoryPanel) Update(snap *aggregator.Snapshot, selectedIP string) {
	if snap.StoryTracker == nil || selectedIP == "" {
		if selectedIP == "" {
			sp.view.SetText(" Select an IP row in the Top Talkers table above to generate narrative.")
		}
		return
	}

	narrative := snap.StoryTracker.GenerateNarrative(selectedIP, sp.redactIPs)
	sp.view.SetTitle(fmt.Sprintf(" Flow Story Narrative: %s ", selectedIP))
	sp.view.SetText(narrative)
}
