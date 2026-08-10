package replay

import (
	"fmt"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Recorder handles recording live captured packets to a standard .pcap file on disk.
type Recorder struct {
	mu     sync.Mutex
	file   *os.File
	writer *pcapgo.Writer
}

// NewRecorder initializes a pcap recorder file.
func NewRecorder(filename string, snaplen uint32, linkType layers.LinkType) (*Recorder, error) {
	f, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("creating record file %s: %w", filename, err)
	}

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(snaplen, linkType); err != nil {
		f.Close()
		return nil, fmt.Errorf("writing pcap header: %w", err)
	}

	return &Recorder{
		file:   f,
		writer: w,
	}, nil
}

// WritePacket writes a single captured packet to the recorded pcap file.
func (r *Recorder) WritePacket(pkt gopacket.Packet) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.writer == nil {
		return nil
	}

	meta := pkt.Metadata()
	captureInfo := gopacket.CaptureInfo{
		Timestamp:      meta.Timestamp,
		CaptureLength:  meta.CaptureLength,
		Length:         meta.Length,
		InterfaceIndex: meta.InterfaceIndex,
	}

	return r.writer.WritePacket(captureInfo, pkt.Data())
}

// Close flushes and closes the recorded pcap file.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file != nil {
		err := r.file.Close()
		r.file = nil
		r.writer = nil
		return err
	}
	return nil
}
