package filter

import (
	"fmt"
	"strings"

	"github.com/google/gopacket/pcap"
)

// ApplyBPFFilter validates and applies a Berkeley Packet Filter (BPF) string to a live pcap handle.
func ApplyBPFFilter(handle *pcap.Handle, filterExpr string) error {
	filterExpr = strings.TrimSpace(filterExpr)
	if filterExpr == "" {
		return nil
	}

	if handle == nil {
		return fmt.Errorf("pcap handle is nil")
	}

	err := handle.SetBPFFilter(filterExpr)
	if err != nil {
		return fmt.Errorf("invalid BPF filter '%s': %w", filterExpr, err)
	}

	return nil
}
