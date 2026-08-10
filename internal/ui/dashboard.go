package ui

import (
	"context"
	"fmt"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"netwatch/internal/aggregator"
)

type Dashboard struct {
	app            *tview.Application
	pages          *tview.Pages
	statsManager   *aggregator.StatsManager
	topBar         *TopBar
	topTalkers     *TopTalkersPanel
	protoBreakdown *ProtocolBreakdownPanel
	packetLog      *PacketLogPanel
	throughput     *ThroughputPanel
	anomalyPanel   *AnomalyPanel
	storyPanel     *StoryPanel
	mainFlex       *tview.Flex

	bpfFilterExpr   string
	applyFilterFunc  func(expr string) error
	redactIPs       bool
	filterModal     *tview.Flex
	filterInput     *tview.InputField
	filterErrorMsg  *tview.TextView
	storyModal      *tview.Flex
}

func NewDashboard(iface string, sm *aggregator.StatsManager, initialFilter string, applyFilterFunc func(expr string) error, redactIPs bool) *Dashboard {
	app := tview.NewApplication()
	pages := tview.NewPages()

	topBar := NewTopBar(iface)
	topTalkers := NewTopTalkersPanel()
	protoBreakdown := NewProtocolBreakdownPanel()
	packetLog := NewPacketLogPanel()
	throughput := NewThroughputPanel()
	anomalyPanel := NewAnomalyPanel()
	storyPanel := NewStoryPanel(redactIPs)

	// Top Half Split (Top Talkers + Protocol Breakdown)
	topHalf := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(topTalkers.View(), 0, 3, true).
		AddItem(protoBreakdown.View(), 0, 2, false)

	// Bottom Half Split (Packet Log + Throughput)
	bottomHalf := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(packetLog.View(), 0, 3, false).
		AddItem(throughput.View(), 0, 2, false)

	// Main Layout
	mainFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(topBar.View(), 3, 1, false).
		AddItem(anomalyPanel.View(), 4, 1, false).
		AddItem(topHalf, 0, 2, true).
		AddItem(bottomHalf, 0, 2, false)

	pages.AddPage("main", mainFlex, true, true)

	d := &Dashboard{
		app:             app,
		pages:           pages,
		statsManager:    sm,
		topBar:          topBar,
		topTalkers:      topTalkers,
		protoBreakdown:  protoBreakdown,
		packetLog:       packetLog,
		throughput:      throughput,
		anomalyPanel:    anomalyPanel,
		storyPanel:      storyPanel,
		mainFlex:        mainFlex,
		bpfFilterExpr:   initialFilter,
		applyFilterFunc: applyFilterFunc,
		redactIPs:       redactIPs,
	}

	d.setupFilterModal()
	d.setupStoryModal()
	d.setupKeybindings()
	return d
}

func (d *Dashboard) setupFilterModal() {
	d.filterErrorMsg = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)

	d.filterInput = tview.NewInputField().
		SetLabel(" BPF Filter: ").
		SetFieldWidth(40).
		SetText(d.bpfFilterExpr)

	d.filterInput.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			expr := d.filterInput.GetText()
			if d.applyFilterFunc != nil {
				err := d.applyFilterFunc(expr)
				if err != nil {
					d.filterErrorMsg.SetText(fmt.Sprintf("[red]Error: %v[white]", err))
					return
				}
			}
			d.bpfFilterExpr = expr
			d.pages.HidePage("filterModal")
		} else if key == tcell.KeyEscape {
			d.pages.HidePage("filterModal")
		}
	})

	modalBox := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().SetText(" Set BPF Capture Filter (e.g. 'port 80', 'tcp and host 10.0.0.5')\n Press Enter to apply, ESC to cancel.").SetTextAlign(tview.AlignCenter), 3, 1, false).
		AddItem(d.filterInput, 3, 1, true).
		AddItem(d.filterErrorMsg, 2, 1, false)

	modalBox.SetBorder(true).SetTitle(" BPF Filter Config ").SetTitleAlign(tview.AlignCenter)
	modalBox.SetBorderColor(tcell.ColorYellow)

	d.filterModal = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
			AddItem(nil, 0, 1, false).
			AddItem(modalBox, 70, 1, true).
			AddItem(nil, 0, 1, false), 10, 1, true).
		AddItem(nil, 0, 1, false)

	d.pages.AddPage("filterModal", d.filterModal, true, false)
}

func (d *Dashboard) setupStoryModal() {
	storyBox := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(d.storyPanel.View(), 0, 1, true).
		AddItem(tview.NewTextView().SetText(" Press ESC to return to main dashboard ").SetTextAlign(tview.AlignCenter), 1, 1, false)

	storyBox.SetBorder(true).SetTitle(" Host Flow Narrative ").SetTitleAlign(tview.AlignCenter)
	storyBox.SetBorderColor(tcell.ColorGreen)

	d.storyModal = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
			AddItem(nil, 0, 1, false).
			AddItem(storyBox, 90, 1, true).
			AddItem(nil, 0, 1, false), 20, 1, true).
		AddItem(nil, 0, 1, false)

	d.pages.AddPage("storyModal", d.storyModal, true, false)
}

func (d *Dashboard) setupKeybindings() {
	d.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		frontPage, _ := d.pages.GetFrontPage()
		if frontPage == "filterModal" {
			return event
		}
		if frontPage == "storyModal" {
			if event.Key() == tcell.KeyEscape || event.Rune() == 's' || event.Rune() == 'S' {
				d.pages.HidePage("storyModal")
				return nil
			}
			return event
		}

		if event.Key() == tcell.KeyRune {
			switch event.Rune() {
			case 'q', 'Q':
				d.app.Stop()
				return nil
			case 'p', 'P':
				d.packetLog.TogglePause()
				return nil
			case '/':
				d.filterInput.SetText(d.bpfFilterExpr)
				d.filterErrorMsg.SetText("")
				d.pages.ShowPage("filterModal")
				d.app.SetFocus(d.filterInput)
				return nil
			case 's', 'S', 'n', 'N':
				selectedIP := d.topTalkers.SelectedIP()
				snap := d.statsManager.GetSnapshot()
				d.storyPanel.Update(snap, selectedIP)
				d.pages.ShowPage("storyModal")
				d.app.SetFocus(d.storyPanel.View())
				return nil
			}
		}
		return event
	})
}

// Run starts the TUI application and ticker repaint loop.
func (d *Dashboard) Run(ctx context.Context) error {
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				d.app.Stop()
				return
			case <-ticker.C:
				snap := d.statsManager.GetSnapshot()
				selectedIP := d.topTalkers.SelectedIP()
				d.app.QueueUpdateDraw(func() {
					d.topBar.Update(snap, d.packetLog.IsPaused(), d.bpfFilterExpr)
					d.topTalkers.Update(snap)
					d.protoBreakdown.Update(snap)
					d.packetLog.Update(snap, "")
					d.throughput.Update(snap)
					d.anomalyPanel.Update(snap)
					d.storyPanel.Update(snap, selectedIP)
				})
			}
		}
	}()

	return d.app.SetRoot(d.pages, true).EnableMouse(true).Run()
}
