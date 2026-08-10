package aggregator

import (
	"context"
	"time"

	"netwatch/internal/model"
)

// Aggregator runs as a single-owner goroutine processing decoded packets.
type Aggregator struct {
	packetChan <-chan model.PacketInfo
	manager    *StatsManager
}

// NewAggregator initializes an Aggregator instance.
func NewAggregator(packetChan <-chan model.PacketInfo, manager *StatsManager) *Aggregator {
	return &Aggregator{
		packetChan: packetChan,
		manager:    manager,
	}
}

// Run starts the aggregator event loop.
// OWNERSHIP: This method must be executed in exactly ONE goroutine.
func (a *Aggregator) Run(ctx context.Context) {
	secTicker := time.NewTicker(1 * time.Second)
	defer secTicker.Stop()

	snapTicker := time.NewTicker(250 * time.Millisecond)
	defer snapTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Drain remaining buffered packets before stopping
			for pkt := range a.packetChan {
				a.manager.AddPacket(pkt)
			}
			a.manager.SaveBaseline()
			a.manager.PublishSnapshot()
			return

		case pkt, ok := <-a.packetChan:
			if !ok {
				a.manager.PublishSnapshot()
				return
			}
			a.manager.AddPacket(pkt)

		case <-secTicker.C:
			a.manager.TickSecond()
			a.manager.PublishSnapshot()

		case <-snapTicker.C:
			a.manager.PublishSnapshot()
		}
	}
}
