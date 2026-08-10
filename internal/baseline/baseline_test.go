package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBaselineManager_WarmupAndDeviation(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "baseline_test.json")

	cfg := Config{
		WarmupSec: 2, // 2 second warmup for testing
		Alpha:     0.2,
		SigmaK:    3.0,
		FilePath:  filePath,
	}

	mgr := NewManager(cfg)
	ip := "192.168.1.10"
	now := time.Now()

	// 1. Train baseline during warmup (normal traffic ~10 pkts/sec)
	for i := 0; i < 20; i++ {
		events := mgr.ObserveHost(ip, 10.0, 1000.0, 2.0, now.Add(time.Duration(i)*time.Second))
		if len(events) > 0 {
			t.Fatalf("Unexpected anomaly event during warmup: %v", events)
		}
	}

	// 2. Simulate sudden spike (burst 500 pkts/sec) after warmup
	burstTime := now.Add(25 * time.Second)
	events := mgr.ObserveHost(ip, 500.0, 50000.0, 50.0, burstTime)

	if len(events) == 0 {
		t.Fatalf("Expected BEHAVIORAL_DEVIATION anomaly on burst traffic, got 0 events")
	}

	foundDeviation := false
	for _, evt := range events {
		if evt.Kind == "BEHAVIORAL_DEVIATION" && evt.SourceIP == ip {
			foundDeviation = true
			break
		}
	}
	if !foundDeviation {
		t.Errorf("Expected BEHAVIORAL_DEVIATION for IP %s", ip)
	}

	// 3. Test Save & Reload
	err := mgr.SaveToFile(filePath)
	if err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	mgr2 := NewManager(cfg)
	if len(mgr2.hosts) != 1 {
		t.Errorf("Expected 1 host restored from disk, got %d", len(mgr2.hosts))
	}
	if mgr2.hosts[ip] == nil {
		t.Errorf("Host %s not restored correctly", ip)
	}

	_ = os.Remove(filePath)
}
