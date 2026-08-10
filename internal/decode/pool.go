package decode

import (
	"context"
	"sync"

	"github.com/google/gopacket"
	"netwatch/internal/model"
)

// WorkerPool manages N concurrent decoder workers.
type WorkerPool struct {
	numWorkers int
	inChan     <-chan gopacket.Packet
	outChan    chan model.PacketInfo
}

// NewWorkerPool initializes a WorkerPool.
func NewWorkerPool(numWorkers int, bufferSize int, inChan <-chan gopacket.Packet) (*WorkerPool, <-chan model.PacketInfo) {
	outChan := make(chan model.PacketInfo, bufferSize)
	return &WorkerPool{
		numWorkers: numWorkers,
		inChan:     inChan,
		outChan:    outChan,
	}, outChan
}

// Run spawns worker goroutines to process packets concurrently.
func (wp *WorkerPool) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < wp.numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case pkt, ok := <-wp.inChan:
					if !ok {
						return
					}
					info := DecodePacket(pkt)
					select {
					case <-ctx.Done():
						return
					case wp.outChan <- info:
					}
				}
			}
		}()
	}

	// Close output channel after all workers exit
	go func() {
		wg.Wait()
		close(wp.outChan)
	}()
}
