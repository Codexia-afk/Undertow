package narrative

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"netwatch/internal/model"
)

// EventType categorizes timeline milestones for narrative synthesis.
type EventType string

const (
	EventDNSQuery      EventType = "DNS_QUERY"
	EventTCPHandshake  EventType = "TCP_HANDSHAKE"
	EventTCPClose      EventType = "TCP_CLOSE"
	EventTCPReset      EventType = "TCP_RESET"
	EventLargeData     EventType = "LARGE_DATA"
	EventSecurityAlert EventType = "SECURITY_ALERT"
)

// TimelineEvent records a notable network event for a host.
type TimelineEvent struct {
	Timestamp time.Time
	Type      EventType
	SrcIP     string
	DstIP     string
	DstPort   uint16
	Detail    string
	Bytes     uint64
}

// HostTimeline aggregates chronological events for a specific IP.
type HostTimeline struct {
	IP        string
	FirstSeen time.Time
	LastSeen  time.Time
	Events    []TimelineEvent
}

// StoryTracker maintains timelines for active hosts across the session.
// OWNERSHIP: Mutated by aggregator goroutine.
type StoryTracker struct {
	mu        sync.RWMutex
	timelines map[string]*HostTimeline
	ipAlias   map[string]string // Map IP -> Anonymous Alias if redaction enabled
	aliasSeq  int
}

// NewStoryTracker initializes a StoryTracker.
func NewStoryTracker() *StoryTracker {
	return &StoryTracker{
		timelines: make(map[string]*HostTimeline),
		ipAlias:   make(map[string]string),
	}
}

// RecordPacket inspects decoded packet details and records timeline events if notable.
func (st *StoryTracker) RecordPacket(pkt model.PacketInfo) {
	st.mu.Lock()
	defer st.mu.Unlock()

	now := pkt.Timestamp

	// Track SrcIP timeline
	if pkt.SrcIP != nil {
		srcIP := pkt.SrcIP.String()
		tl, exists := st.timelines[srcIP]
		if !exists {
			tl = &HostTimeline{IP: srcIP, FirstSeen: now}
			st.timelines[srcIP] = tl
		}
		tl.LastSeen = now

		// 1. DNS Query Event
		if pkt.Protocol == "DNS" && pkt.DNSQuery != "" {
			st.addEvent(tl, TimelineEvent{
				Timestamp: now,
				Type:      EventDNSQuery,
				SrcIP:     srcIP,
				Detail:    pkt.DNSQuery,
			})
		}

		// 2. TCP Handshake Start (SYN without ACK)
		if pkt.Protocol == "TCP" && pkt.TCPFlags.SYN && !pkt.TCPFlags.ACK {
			st.addEvent(tl, TimelineEvent{
				Timestamp: now,
				Type:      EventTCPHandshake,
				SrcIP:     srcIP,
				DstIP:     pkt.DstIP.String(),
				DstPort:   pkt.DstPort,
				Detail:    "TCP SYN handshake initiated",
			})
		}

		// 3. TCP Clean Close (FIN)
		if pkt.Protocol == "TCP" && pkt.TCPFlags.FIN {
			st.addEvent(tl, TimelineEvent{
				Timestamp: now,
				Type:      EventTCPClose,
				SrcIP:     srcIP,
				DstIP:     pkt.DstIP.String(),
				DstPort:   pkt.DstPort,
				Detail:    "Connection closed normally (FIN)",
			})
		}

		// 4. TCP Reset (RST)
		if pkt.Protocol == "TCP" && pkt.TCPFlags.RST {
			st.addEvent(tl, TimelineEvent{
				Timestamp: now,
				Type:      EventTCPReset,
				SrcIP:     srcIP,
				DstIP:     pkt.DstIP.String(),
				DstPort:   pkt.DstPort,
				Detail:    "Connection reset forcibly (RST)",
			})
		}
	}
}

// RecordAnomaly adds a security anomaly milestone to the host timeline.
func (st *StoryTracker) RecordAnomaly(evt model.AnomalyEvent) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if evt.SourceIP == "" {
		return
	}

	tl, exists := st.timelines[evt.SourceIP]
	if !exists {
		tl = &HostTimeline{IP: evt.SourceIP, FirstSeen: evt.Timestamp}
		st.timelines[evt.SourceIP] = tl
	}
	tl.LastSeen = evt.Timestamp

	st.addEvent(tl, TimelineEvent{
		Timestamp: evt.Timestamp,
		Type:      EventSecurityAlert,
		SrcIP:     evt.SourceIP,
		Detail:    fmt.Sprintf("[%s] %s", evt.Kind, evt.Detail),
	})
}

func (st *StoryTracker) addEvent(tl *HostTimeline, evt TimelineEvent) {
	// Limit per-host event history cap to 50 items
	if len(tl.Events) >= 50 {
		tl.Events = tl.Events[1:]
	}
	tl.Events = append(tl.Events, evt)
}

// GenerateNarrative synthesizes a human-readable story paragraph for an IP.
func (st *StoryTracker) GenerateNarrative(ip string, redactIPs bool) string {
	st.mu.RLock()
	defer st.mu.RUnlock()

	tl, exists := st.timelines[ip]
	if !exists || len(tl.Events) == 0 {
		displayIP := st.formatIP(ip, redactIPs)
		return fmt.Sprintf("No detailed timeline activity recorded yet for host %s.", displayIP)
	}

	var sb strings.Builder
	displayHost := st.formatIP(ip, redactIPs)
	sb.WriteString(fmt.Sprintf("Host %s activity narrative (Active since %s):\n\n",
		displayHost, tl.FirstSeen.Format("15:04:05")))

	// Sort events chronologically
	events := make([]TimelineEvent, len(tl.Events))
	copy(events, tl.Events)
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	var dnsQueries []string
	var connTargets []string
	var anomalyCount int
	var hasReset bool
	var hasNormalClose bool

	for _, evt := range events {
		ts := evt.Timestamp.Format("15:04:05")
		dstStr := st.formatIP(evt.DstIP, redactIPs)

		switch evt.Type {
		case EventDNSQuery:
			dnsQueries = append(dnsQueries, evt.Detail)
			sb.WriteString(fmt.Sprintf("• [%s] Resolved domain '%s' via DNS.\n", ts, evt.Detail))
		case EventTCPHandshake:
			connTargets = append(connTargets, fmt.Sprintf("%s:%d", dstStr, evt.DstPort))
			sb.WriteString(fmt.Sprintf("• [%s] Opened TCP connection to %s:%d.\n", ts, dstStr, evt.DstPort))
		case EventTCPClose:
			hasNormalClose = true
			sb.WriteString(fmt.Sprintf("• [%s] Closed connection to %s:%d normally (FIN).\n", ts, dstStr, evt.DstPort))
		case EventTCPReset:
			hasReset = true
			sb.WriteString(fmt.Sprintf("• [%s] Connection to %s:%d was RESET (RST).\n", ts, dstStr, evt.DstPort))
		case EventSecurityAlert:
			anomalyCount++
			sb.WriteString(fmt.Sprintf("• [%s] ⚠️ SECURITY ALERT: %s\n", ts, evt.Detail))
		}
	}

	// Synthesis Summary Paragraph
	sb.WriteString("\nSummary Narrative:\n")
	sb.WriteString(fmt.Sprintf("Host %s ", displayHost))
	if len(dnsQueries) > 0 {
		sb.WriteString(fmt.Sprintf("resolved %d domain(s) (e.g. %s)", len(dnsQueries), dnsQueries[0]))
	} else {
		sb.WriteString("engaged in direct IP communications")
	}

	if len(connTargets) > 0 {
		sb.WriteString(fmt.Sprintf(" and initiated TCP sessions with %d target endpoint(s). ", len(connTargets)))
	} else {
		sb.WriteString(". ")
	}

	if hasNormalClose && !hasReset {
		sb.WriteString("Sessions closed cleanly. ")
	} else if hasReset {
		sb.WriteString("Noticeable TCP resets (RST) were observed during the session. ")
	}

	if anomalyCount > 0 {
		sb.WriteString(fmt.Sprintf("⚠️ WARNING: %d security anomaly event(s) were flagged for this host!", anomalyCount))
	} else {
		sb.WriteString("✓ No security anomalies flagged for this host.")
	}

	return sb.String()
}

func (st *StoryTracker) formatIP(ip string, redactIPs bool) string {
	if ip == "" {
		return "-"
	}
	if !redactIPs {
		return ip
	}
	alias, exists := st.ipAlias[ip]
	if !exists {
		st.aliasSeq++
		alias = fmt.Sprintf("HOST_%c", 'A'+(st.aliasSeq-1)%26)
		st.ipAlias[ip] = alias
	}
	return alias
}
