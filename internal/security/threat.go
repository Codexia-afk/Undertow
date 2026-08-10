package security

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

//go:embed assets/threat_feed.json
var defaultThreatFeedBytes []byte

// ThreatFeed represents the JSON structure for IOC threat feeds.
type ThreatFeed struct {
	IPBlocks     []string `json:"ip_blocks"`
	C2Domains    []string `json:"c2_domains"`
	MaliciousIPs []string `json:"malicious_ips"`
}

// Engine performs offline IOC threat intelligence lookup against IP blocks, C2 domains, and exact malicious IPs.
type Engine struct {
	mu        sync.RWMutex
	cidrs     []*net.IPNet
	exactIPs  map[string]bool
	c2Domains map[string]bool
}

// NewEngine constructs a Threat Intelligence Engine with embedded default Spamhaus / C2 feeds.
func NewEngine() *Engine {
	e := &Engine{
		exactIPs:  make(map[string]bool),
		c2Domains: make(map[string]bool),
	}
	e.loadFeedBytes(defaultThreatFeedBytes)
	return e
}

// LoadCustomFeed parses a custom local JSON threat feed file.
func (e *Engine) LoadCustomFeed(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading custom threat feed file (%s): %w", filePath, err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	return e.loadFeedBytes(data)
}

func (e *Engine) loadFeedBytes(data []byte) error {
	var feed ThreatFeed
	if err := json.Unmarshal(data, &feed); err != nil {
		return err
	}

	for _, cidrStr := range feed.IPBlocks {
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err == nil && ipNet != nil {
			e.cidrs = append(e.cidrs, ipNet)
		}
	}

	for _, ip := range feed.MaliciousIPs {
		e.exactIPs[strings.TrimSpace(ip)] = true
	}

	for _, dom := range feed.C2Domains {
		e.c2Domains[strings.ToLower(strings.TrimSpace(dom))] = true
	}

	return nil
}

// MatchIP checks whether an IP address matches known malicious IPs or Spamhaus DROP CIDR blocks.
func (e *Engine) MatchIP(ipStr string) (bool, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	ipStr = strings.TrimSpace(ipStr)
	if e.exactIPs[ipStr] {
		return true, "Malicious C2 Host"
	}

	ip := net.ParseIP(ipStr)
	if ip != nil {
		for _, cidr := range e.cidrs {
			if cidr.Contains(ip) {
				return true, fmt.Sprintf("Spamhaus DROP Block (%s)", cidr.String())
			}
		}
	}

	return false, ""
}

// MatchDomain checks whether a domain matches known malicious C2 domain indicators.
func (e *Engine) MatchDomain(domain string) (bool, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSpace(domain))
	if e.c2Domains[domain] {
		return true, "Malicious C2 Domain"
	}

	return false, ""
}
