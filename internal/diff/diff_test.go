package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Codexia-afk/Undertow/internal/aggregator"
)

func TestCompareSnapshots(t *testing.T) {
	tempDir := t.TempDir()

	snapA := aggregator.Snapshot{
		TotalPackets: 100,
		TotalBytes:   10000,
		TopTalkers: []aggregator.TalkerStat{
			{IP: "192.168.1.10", BytesSent: 5000},
		},
	}

	snapB := aggregator.Snapshot{
		TotalPackets: 200,
		TotalBytes:   50000,
		TopTalkers: []aggregator.TalkerStat{
			{IP: "192.168.1.10", BytesSent: 30000},
			{IP: "10.0.0.99", BytesSent: 20000},
		},
	}

	fileA := filepath.Join(tempDir, "snapA.json")
	fileB := filepath.Join(tempDir, "snapB.json")

	dataA, _ := json.Marshal(snapA)
	dataB, _ := json.Marshal(snapB)

	_ = os.WriteFile(fileA, dataA, 0644)
	_ = os.WriteFile(fileB, dataB, 0644)

	res, textSummary, err := CompareSnapshots(fileA, fileB)
	if err != nil {
		t.Fatalf("Failed to compare snapshots: %v", err)
	}

	if len(res.NewEndpoints) != 1 || res.NewEndpoints[0] != "10.0.0.99" {
		t.Errorf("Expected 1 new endpoint '10.0.0.99'")
	}
	if textSummary == "" {
		t.Errorf("Expected non-empty summary text")
	}

	_ = os.Remove(fileA)
	_ = os.Remove(fileB)
}
