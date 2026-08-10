package anomaly

import (
	"fmt"
	"math"
	"strings"
	"time"

	"netwatch/internal/model"
)

// Config holds configurable threshold limits for anomaly detection heuristics.
type Config struct {
	ScanThreshold       int     // Number of distinct ports within window (default 15)
	ScanWindowSec       int     // Sliding window in seconds (default 10)
	TransferThresholdMB uint64  // Flow transfer size threshold in MB (default 50)
	DNSEntropyThreshold float64 // Shannon entropy threshold for DNS domain labels (default 3.5)
}

// DefaultConfig returns recommended baseline anomaly thresholds.
func DefaultConfig() Config {
	return Config{
		ScanThreshold:       15,
		ScanWindowSec:       10,
		TransferThresholdMB: 50,
		DNSEntropyThreshold: 3.5,
	}
}

type timestampedPort struct {
	port      uint16
	timestamp time.Time
}

// Detector tracks host activity and evaluates detection rules.
// OWNERSHIP: Only called by the aggregator goroutine.
type Detector struct {
	config        Config
	portScanTrack map[string][]timestampedPort // srcIP -> history of (port, timestamp)
	flaggedFlows  map[model.FlowKey]bool       // Prevents duplicate large transfer alerts per flow
}

// NewDetector initializes a Detector.
func NewDetector(cfg Config) *Detector {
	return &Detector{
		config:        cfg,
		portScanTrack: make(map[string][]timestampedPort),
		flaggedFlows:  make(map[model.FlowKey]bool),
	}
}

// CheckPacket evaluates a decoded packet against security heuristics and returns any detected AnomalyEvent.
func (d *Detector) CheckPacket(pkt model.PacketInfo, flowStat *model.FlowStat) []model.AnomalyEvent {
	var events []model.AnomalyEvent

	if pkt.SrcIP == nil {
		return events
	}
	srcIP := pkt.SrcIP.String()

	// 1. Port Scan Detection
	if pkt.Protocol == "TCP" || pkt.Protocol == "UDP" {
		if evt, detected := d.checkPortScan(srcIP, pkt.DstPort, pkt.Timestamp); detected {
			events = append(events, evt)
		}
	}

	// 2. Large Transfer Detection
	if flowStat != nil {
		if evt, detected := d.checkLargeTransfer(pkt, flowStat); detected {
			events = append(events, evt)
		}
	}

	// 3. Suspicious DNS Detection
	if pkt.Protocol == "DNS" && pkt.DNSQuery != "" {
		if evt, detected := d.checkSuspiciousDNS(srcIP, pkt.DNSQuery, pkt.Timestamp); detected {
			events = append(events, evt)
		}
	}

	return events
}

// checkPortScan checks if a single source IP contacts > N distinct ports within the sliding window.
func (d *Detector) checkPortScan(srcIP string, dstPort uint16, now time.Time) (model.AnomalyEvent, bool) {
	windowStart := now.Add(-time.Duration(d.config.ScanWindowSec) * time.Second)

	// Clean expired entries
	entries := d.portScanTrack[srcIP]
	validIndex := 0
	for _, entry := range entries {
		if entry.timestamp.After(windowStart) {
			entries[validIndex] = entry
			validIndex++
		}
	}
	entries = append(entries[:validIndex], timestampedPort{port: dstPort, timestamp: now})
	d.portScanTrack[srcIP] = entries

	// Count distinct ports within window
	distinctPorts := make(map[uint16]bool)
	for _, entry := range entries {
		distinctPorts[entry.port] = true
	}

	if len(distinctPorts) >= d.config.ScanThreshold {
		// Reset tracking for this host after alert to avoid spamming
		d.portScanTrack[srcIP] = nil
		return model.AnomalyEvent{
			Timestamp: now,
			Kind:      "PORT_SCAN",
			SourceIP:  srcIP,
			Detail:    fmt.Sprintf("Contacted %d distinct ports in %ds", len(distinctPorts), d.config.ScanWindowSec),
		}, true
	}

	return model.AnomalyEvent{}, false
}

// checkLargeTransfer flags flows exceeding transfer size threshold.
func (d *Detector) checkLargeTransfer(pkt model.PacketInfo, flow *model.FlowStat) (model.AnomalyEvent, bool) {
	thresholdBytes := d.config.TransferThresholdMB * 1024 * 1024
	if flow.BytesSent >= thresholdBytes && !d.flaggedFlows[flow.Key] {
		d.flaggedFlows[flow.Key] = true
		return model.AnomalyEvent{
			Timestamp: pkt.Timestamp,
			Kind:      "LARGE_TRANSFER",
			SourceIP:  pkt.SrcIP.String(),
			Detail:    fmt.Sprintf("Flow %s -> %s transferred %s (> %d MB)", flow.Key.SrcIP, flow.Key.DstIP, formatBytes(flow.BytesSent), d.config.TransferThresholdMB),
		}, true
	}
	return model.AnomalyEvent{}, false
}

// checkSuspiciousDNS flags high Shannon entropy, long query length, or excessive subdomain dots.
func (d *Detector) checkSuspiciousDNS(srcIP, query string, now time.Time) (model.AnomalyEvent, bool) {
	domain := strings.TrimSuffix(query, ".")
	labels := strings.Split(domain, ".")

	entropy := CalculateShannonEntropy(domain)
	dotCount := len(labels) - 1

	isHighEntropy := entropy > d.config.DNSEntropyThreshold
	isExcessiveLength := len(domain) > 50
	isExcessiveSubdomains := dotCount >= 5

	if isHighEntropy || isExcessiveLength || isExcessiveSubdomains {
		reasons := []string{}
		if isHighEntropy {
			reasons = append(reasons, fmt.Sprintf("High entropy (%.2f)", entropy))
		}
		if isExcessiveLength {
			reasons = append(reasons, fmt.Sprintf("Length %d > 50", len(domain)))
		}
		if isExcessiveSubdomains {
			reasons = append(reasons, fmt.Sprintf("Subdomains %d >= 5", dotCount))
		}

		return model.AnomalyEvent{
			Timestamp: now,
			Kind:      "SUSPICIOUS_DNS",
			SourceIP:  srcIP,
			Detail:    fmt.Sprintf("Query '%s': %s", domain, strings.Join(reasons, ", ")),
		}, true
	}

	return model.AnomalyEvent{}, false
}

// CalculateShannonEntropy calculates Shannon entropy for a given domain string.
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]float64)
	for _, char := range s {
		freq[char]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func formatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
