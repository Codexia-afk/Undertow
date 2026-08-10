package decode

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/Codexia-afk/Undertow/internal/model"
	"github.com/Codexia-afk/Undertow/internal/security"
	"github.com/Codexia-afk/Undertow/internal/tls"
)

var threatEngine = security.NewEngine()

// SetThreatEngine updates the global Threat Intelligence engine instance.
func SetThreatEngine(e *security.Engine) {
	if e != nil {
		threatEngine = e
	}
}

// DecodePacket transforms a gopacket.Packet into a normalized model.PacketInfo.
// It safely handles missing/corrupt layers without panicking.
func DecodePacket(packet gopacket.Packet) model.PacketInfo {
	info := model.PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
		Protocol:  "Other",
	}

	if packet == nil {
		return info
	}

	// 1. Link Layer (Ethernet)
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if eth, ok := ethLayer.(*layers.Ethernet); ok {
			info.SrcMAC = eth.SrcMAC.String()
			info.DstMAC = eth.DstMAC.String()
		}
	}

	// 2. Network Layer (IPv4 / IPv6 / ARP)
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		if ip4, ok := ip4Layer.(*layers.IPv4); ok {
			info.SrcIP = ip4.SrcIP
			info.DstIP = ip4.DstIP
			info.Protocol = ip4.Protocol.String()
		}
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		if ip6, ok := ip6Layer.(*layers.IPv6); ok {
			info.SrcIP = ip6.SrcIP
			info.DstIP = ip6.DstIP
			info.Protocol = ip6.NextHeader.String()
		}
	} else if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		if arp, ok := arpLayer.(*layers.ARP); ok {
			info.Protocol = "ARP"
			info.SrcIP = arp.SourceProtAddress
			info.DstIP = arp.DstProtAddress
		}
	}

	// 3. Transport Layer (TCP / UDP / ICMP)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			info.Protocol = "TCP"
			info.SrcPort = uint16(tcp.SrcPort)
			info.DstPort = uint16(tcp.DstPort)
			info.TCPFlags = model.TCPFlagSet{
				SYN: tcp.SYN,
				ACK: tcp.ACK,
				FIN: tcp.FIN,
				RST: tcp.RST,
				PSH: tcp.PSH,
				URG: tcp.URG,
			}
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			info.Protocol = "UDP"
			info.SrcPort = uint16(udp.SrcPort)
			info.DstPort = uint16(udp.DstPort)
		}
	} else if icmp4Layer := packet.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		info.Protocol = "ICMP"
	} else if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		info.Protocol = "ICMP"
	}

	// 4. Application Layer Inspection

	// A. DNS Detection
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		if dns, ok := dnsLayer.(*layers.DNS); ok {
			info.Protocol = "DNS"
			if len(dns.Questions) > 0 {
				info.DNSQuery = string(dns.Questions[0].Name)
				info.DNSType = dns.Questions[0].Type.String()
			} else if len(dns.Answers) > 0 {
				info.DNSQuery = string(dns.Answers[0].Name)
				info.DNSType = dns.Answers[0].Type.String()
			}
		}
	}

	// B. HTTP Detection (Port 80 or TCP payload sniffing)
	if info.Protocol == "TCP" && (info.SrcPort == 80 || info.DstPort == 80 || hasHTTPHeader(packet)) {
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload := appLayer.Payload()
			info.Payload = payload
			method, host, path := parseHTTPInfo(payload)
			if method != "" || host != "" {
				info.Protocol = "HTTP"
				info.HTTPMethod = method
				info.HTTPHost = host
				info.HTTPPath = path
			}
		}
	}

	// C. TLS ClientHello / JA3 & JA4 Fingerprinting
	if info.Protocol == "TCP" {
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload := appLayer.Payload()
			if ja3Res, ok := tls.ParseClientHello(payload); ok {
				info.Protocol = "TLS"
				info.JA3Hash = ja3Res.Hash
				info.JA3Label = ja3Res.Label
				info.JA3Raw = ja3Res.RawString
			}
			if ja4Res, ok := CalculateJA4(payload); ok {
				info.Protocol = "TLS"
				info.JA4String = ja4Res.JA4String
				info.JA4Label = ja4Res.Label
				if ja4Res.IsMalware {
					info.ThreatAlert = fmt.Sprintf("[!] THREAT_ALERT: %s", ja4Res.Label)
				}
			}
		}
	}

	// Threat Intelligence IOC Lookup
	if info.ThreatAlert == "" {
		if matched, cat := threatEngine.MatchIP(info.SrcIP); matched {
			info.ThreatAlert = fmt.Sprintf("[!] THREAT_ALERT: %s (%s)", cat, info.SrcIP)
		} else if matched, cat := threatEngine.MatchIP(info.DstIP); matched {
			info.ThreatAlert = fmt.Sprintf("[!] THREAT_ALERT: %s (%s)", cat, info.DstIP)
		} else if info.DNSQuery != "" {
			if matched, cat := threatEngine.MatchDomain(info.DNSQuery); matched {
				info.ThreatAlert = fmt.Sprintf("[!] THREAT_ALERT: %s (%s)", cat, info.DNSQuery)
			}
		}
	}

	// Store raw payload if present and not yet captured
	if len(info.Payload) == 0 {
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			info.Payload = appLayer.Payload()
		}
	}

	// Handle decode errors silently or gracefully without crashing
	if errLayer := packet.ErrorLayer(); errLayer != nil {
		// Log or keep existing classification without failing
		_ = errLayer.Error()
	}

	return info
}

// hasHTTPHeader inspects the payload prefix to identify HTTP request/response methods.
func hasHTTPHeader(packet gopacket.Packet) bool {
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return false
	}
	payload := appLayer.Payload()
	if len(payload) < 4 {
		return false
	}

	prefix := string(payload[:min(len(payload), 10)])
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/1."}
	for _, m := range methods {
		if strings.HasPrefix(prefix, m) {
			return true
		}
	}
	return false
}

// parseHTTPInfo parses plain HTTP headers from a raw byte payload.
func parseHTTPInfo(payload []byte) (method string, host string, path string) {
	if len(payload) == 0 {
		return "", "", ""
	}

	reader := bufio.NewReader(bytes.NewReader(payload))
	req, err := http.ReadRequest(reader)
	if err == nil && req != nil {
		method = req.Method
		host = req.Host
		if req.URL != nil {
			path = req.URL.Path
		}
		return method, host, path
	}

	// Fallback manual line parsing if net/http parsing fails on partial packets
	lines := strings.Split(string(payload), "\r\n")
	if len(lines) > 0 {
		parts := strings.Split(lines[0], " ")
		if len(parts) >= 2 {
			validMethods := map[string]bool{
				"GET": true, "POST": true, "PUT": true,
				"DELETE": true, "HEAD": true, "OPTIONS": true, "PATCH": true,
			}
			if validMethods[parts[0]] {
				method = parts[0]
				path = parts[1]
			}
		}
	}

	for _, line := range lines[1:] {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(line[5:])
			break
		}
	}

	return method, host, path
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
