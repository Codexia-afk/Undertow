package ui

import (
	"context"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"netwatch/internal/aggregator"
)

type Dashboard struct {
	app              *tview.Application
	statsManager     *aggregator.StatsManager
	topBar           *TopBar
	topTalkers       *TopTalkersPanel
	protoBreakdown   *ProtocolBreakdownPanel
	packetLog        *PacketLogPanel
	throughput       *ThroughputPanel
	anomalyPanel     *AnomalyPanel
	mainFlex         *tview.Flex
	inAppFilter      string
	filterInputField *tview.InputField
	filterOverlay    *tview.Flex
}

func NewDashboard(iface string, sm *aggregator.StatsManager) *Dashboard {
	app := tview.NewApplication()

	topBar := NewTopBar(iface)
	topTalkers := NewTopTalkersPanel()
	protoBreakdown := NewProtocolBreakdownPanel()
	packetLog := NewPacketLogPanel()
	throughput := NewThroughputPanel()
	anomalyPanel := NewAnomalyPanel()

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

	d := &Dashboard{
		app:            app,
		statsManager:   sm,
		topBar:         topBar,
		topTalkers:     topTalkers,
		protoBreakdown: protoBreakdown,
		packetLog:      packetLog,
		throughput:     throughput,
		anomalyPanel:   anomalyPanel,
		mainFlex:       mainFlex,
	}

	d.setupKeybindings()
	return d
}

func (d *Dashboard) setupKeybindings() {
	d.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyRune {
			switch event.Rune() {
			case 'q', 'Q':
				d.app.Stop()
				return nil
			case 'p', 'P':
				d.packetLog.TogglePause()
				return nil
			}
		}
		return event
	})
}

// Run starts the TUI application and ticker repaint loop.
func (d *Dashboard) Run(ctx context.Context) error {
	// Periodic TUI Redraw loop (250ms)
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
				d.app.QueueUpdateDraw(func() {
					d.topBar.Update(snap, d.packetLog.IsPaused())
					d.topTalkers.Update(snap)
					d.protoBreakdown.Update(snap)
					d.packetLog.Update(snap, d.inAppFilter)
					d.throughput.Update(snap)
					d.anomalyPanel.Update(snap)
				})
			}
		}
	}()

	return d.app.SetRoot(d.mainFlex, true).EnableMouse(true).Run()
}
