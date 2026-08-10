package security

import (
	"testing"
)

func TestThreatEngine_DefaultFeed(t *testing.T) {
	engine := NewEngine()
	if engine == nil {
		t.Fatalf("Expected non-nil Threat Intelligence Engine")
	}

	// 1. Exact Malicious IP Match
	matched, category := engine.MatchIP("198.51.100.45")
	if !matched {
		t.Errorf("Expected IP 198.51.100.45 to match threat feed")
	}
	_ = category

	// 2. CIDR Block Subnet Match
	matched2, _ := engine.MatchIP("185.220.101.99")
	if !matched2 {
		t.Errorf("Expected IP 185.220.101.99 to match CIDR block 185.220.101.0/24")
	}

	// 3. Legitimate IP Non-Match
	matched3, _ := engine.MatchIP("8.8.8.8")
	if matched3 {
		t.Errorf("Expected legitimate IP 8.8.8.8 NOT to match threat feed")
	}

	// 4. C2 Domain Match
	matchedDom, _ := engine.MatchDomain("cobaltstrike-beacon.net")
	if !matchedDom {
		t.Errorf("Expected domain cobaltstrike-beacon.net to match C2 indicators")
	}
}
