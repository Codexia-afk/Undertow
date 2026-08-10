package capture

import (
	"context"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/Codexia-afk/Undertow/internal/replay"
)

// Engine manages packet capture from a pcap handle into a buffered channel.
type Engine struct {
	handle       *pcap.Handle
	packetChan   chan gopacket.Packet
	droppedCount uint64
	recorder     *replay.Recorder
}

// NewEngine constructs a new capture Engine.
func NewEngine(handle *pcap.Handle, bufferSize int, recorder *replay.Recorder) *Engine {
	return &Engine{
		handle:     handle,
		packetChan: make(chan gopacket.Packet, bufferSize),
		recorder:   recorder,
	}
}

// PacketChan returns the read-only channel where captured packets are pushed.
func (e *Engine) PacketChan() <-chan gopacket.Packet {
	return e.packetChan
}

// DroppedCountPointer returns a pointer to the atomic dropped packets counter.
func (e *Engine) DroppedCountPointer() *uint64 {
	return &e.droppedCount
}

// Run starts the capture loop.
// OWNERSHIP: Exactly ONE goroutine runs this loop. Libpcap handles are not thread-safe.
func (e *Engine) Run(ctx context.Context) {
	defer close(e.packetChan)

	packetSource := gopacket.NewPacketSource(e.handle, e.handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-packets:
			if !ok {
				return
			}

			if e.recorder != nil {
				_ = e.recorder.WritePacket(pkt)
			}

			// Non-blocking write to packetChan.
			// BACKPRESSURE STORY: If packetChan buffer is full, drop the packet
			// immediately to avoid stalling libpcap kernel ring buffers.
			select {
			case e.packetChan <- pkt:
			default:
				atomic.AddUint64(&e.droppedCount, 1)
			}
		}
	}
}
