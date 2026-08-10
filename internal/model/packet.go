package model

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// TCPFlagSet represents standard TCP flags.
type TCPFlagSet struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
	PSH bool
	URG bool
}

// String returns a compact representation of active TCP flags (e.g. "[SYN, ACK]").
func (f TCPFlagSet) String() string {
	var flags []string
	if f.SYN {
		flags = append(flags, "SYN")
	}
	if f.ACK {
		flags = append(flags, "ACK")
	}
	if f.FIN {
		flags = append(flags, "FIN")
	}
	if f.RST {
		flags = append(flags, "RST")
	}
	if f.PSH {
		flags = append(flags, "PSH")
	}
	if f.URG {
		flags = append(flags, "URG")
	}
	if len(flags) == 0 {
		return "[]"
	}
	return "[" + strings.Join(flags, ",") + "]"
}

// FlowKey uniquely identifies a directional network flow.
type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

// FlowStat records active connection metrics.
type FlowStat struct {
	Key         FlowKey
	BytesSent   uint64
	PacketsSent uint64
	LastSeen    time.Time
	PID         int
	ProcessName string
	User        string
}

// AnomalyEvent describes a flagged security anomaly event.
type AnomalyEvent struct {
	Timestamp time.Time
	Kind      string // "PORT_SCAN", "LARGE_TRANSFER", "SUSPICIOUS_DNS", "BEHAVIORAL_DEVIATION"
	SourceIP  string
	Detail    string
}

// String returns a human-readable flow string.
func (fk FlowKey) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d (%s)", fk.SrcIP, fk.SrcPort, fk.DstIP, fk.DstPort, fk.Protocol)
}

// PacketInfo represents fully normalized packet details extracted from gopacket decoding layers.
type PacketInfo struct {
	Timestamp  time.Time
	Length     int
	SrcMAC     string
	DstMAC     string
	SrcIP      net.IP
	DstIP      net.IP
	Protocol   string // "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "Other"
	SrcPort    uint16
	DstPort    uint16
	TCPFlags   TCPFlagSet
	DNSQuery   string // Populated if DNS query detected
	DNSType    string // A, AAAA, MX, PTR, etc.
	HTTPMethod string // GET, POST, etc.
	HTTPHost   string
	HTTPPath   string
	JA3Hash    string // TLS Client Hello MD5 hash
	JA3Label   string // Matched client label (e.g. "curl / libcurl")
	JA3Raw      string // Raw JA3 string
	JA4String   string // JA4+ canonical fingerprint string
	JA4Label    string // Matched JA4 client/malware label
	ThreatAlert string // IOC threat feed alert string (e.g. "[!] THREAT_ALERT")
	Payload     []byte
}

// Summary returns a one-line formatted summary of the packet for CLI output.
func (p PacketInfo) Summary() string {
	ts := p.Timestamp.Format("15:04:05.000")
	srcStr := "-"
	dstStr := "-"

	if p.SrcIP != nil {
		if p.SrcPort != 0 {
			srcStr = fmt.Sprintf("%s:%d", p.SrcIP, p.SrcPort)
		} else {
			srcStr = p.SrcIP.String()
		}
	} else if p.SrcMAC != "" {
		srcStr = p.SrcMAC
	}

	if p.DstIP != nil {
		if p.DstPort != 0 {
			dstStr = fmt.Sprintf("%s:%d", p.DstIP, p.DstPort)
		} else {
			dstStr = p.DstIP.String()
		}
	} else if p.DstMAC != "" {
		dstStr = p.DstMAC
	}

	extra := ""
	if p.Protocol == "TCP" {
		extra = " " + p.TCPFlags.String()
	} else if p.Protocol == "DNS" {
		if p.DNSQuery != "" {
			extra = fmt.Sprintf(" Q:%s (%s)", p.DNSQuery, p.DNSType)
		}
	} else if p.Protocol == "HTTP" {
		if p.HTTPMethod != "" {
			extra = fmt.Sprintf(" %s %s%s", p.HTTPMethod, p.HTTPHost, p.HTTPPath)
		}
	}

	return fmt.Sprintf("%s  %-22s -> %-22s  %-6s %5d bytes%s", ts, srcStr, dstStr, p.Protocol, p.Length, extra)
}
