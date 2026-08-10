package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netwatch/internal/aggregator"
	"netwatch/internal/anomaly"
	"netwatch/internal/baseline"
	"netwatch/internal/model"
)

func TestGenerateHTMLReport(t *testing.T) {
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "report_test.html")

	var dropped uint64 = 0
	sm := aggregator.NewStatsManager(60, 200, 100, &dropped, anomaly.DefaultConfig(), baseline.DefaultConfig())

	sm.AddPacket(model.PacketInfo{
		Timestamp: time.Now(),
		Length:    1024,
		SrcIP:     []byte{192, 168, 1, 10},
		DstIP:     []byte{10, 0, 0, 1},
		Protocol:  "TCP",
	})

	snap := sm.GetSnapshot()

	err := GenerateHTMLReport(snap, "eth0", "port 80", false, outputFile)
	if err != nil {
		t.Fatalf("Failed to generate HTML report: %v", err)
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read report file: %v", err)
	}

	htmlStr := string(content)

	if !strings.Contains(htmlStr, "<!DOCTYPE html>") {
		t.Errorf("Expected valid HTML5 DOCTYPE header")
	}
	if !strings.Contains(htmlStr, "<svg") {
		t.Errorf("Expected inline SVG vector charts")
	}
	if strings.Contains(htmlStr, "<script src=") || strings.Contains(htmlStr, "<link rel=\"stylesheet\" href=\"http") {
		t.Errorf("Report should be 100%% self-contained with no external CDN dependencies")
	}

	_ = os.Remove(outputFile)
}
