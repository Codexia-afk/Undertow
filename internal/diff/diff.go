package diff

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"

	"netwatch/internal/aggregator"
)

// DiffResult holds comparative analysis details between two snapshot sessions.
type DiffResult struct {
	NewEndpoints       []string
	RemovedEndpoints   []string
	DriftedTalkers     []string
	NewJA3Hashes       []string
	TotalBytesDiffPct  float64
	TotalPacketsDiff   int64
	SummaryText        string
}

// CompareSnapshots parses two JSON snapshot files and generates comparative diff results.
func CompareSnapshots(fileA, fileB string) (DiffResult, string, error) {
	snapA, err := loadSnapshot(fileA)
	if err != nil {
		return DiffResult{}, "", fmt.Errorf("loading file A (%s): %w", fileA, err)
	}

	snapB, err := loadSnapshot(fileB)
	if err != nil {
		return DiffResult{}, "", fmt.Errorf("loading file B (%s): %w", fileB, err)
	}

	var res DiffResult

	// 1. Total Volume & Packet Count Drift
	if snapA.TotalBytes > 0 {
		diff := float64(snapB.TotalBytes) - float64(snapA.TotalBytes)
		res.TotalBytesDiffPct = (diff / float64(snapA.TotalBytes)) * 100.0
	}
	res.TotalPacketsDiff = int64(snapB.TotalPackets) - int64(snapA.TotalPackets)

	// 2. Endpoints Diff (Top Talkers)
	mapA := make(map[string]aggregator.TalkerStat)
	for _, t := range snapA.TopTalkers {
		mapA[t.IP] = t
	}

	mapB := make(map[string]aggregator.TalkerStat)
	for _, t := range snapB.TopTalkers {
		mapB[t.IP] = t
	}

	for ip, statB := range mapB {
		if statA, found := mapA[ip]; found {
			// Check throughput drift (> 20%)
			bytesA := float64(statA.TotalBytes())
			bytesB := float64(statB.TotalBytes())
			if bytesA > 0 {
				drift := math.Abs((bytesB - bytesA) / bytesA) * 100.0
				if drift > 20.0 {
					res.DriftedTalkers = append(res.DriftedTalkers,
						fmt.Sprintf("%s: %.1f MB -> %.1f MB (Drift: %.1f%%)",
							ip, bytesA/1048576, bytesB/1048576, drift))
				}
			}
		} else {
			res.NewEndpoints = append(res.NewEndpoints, ip)
		}
	}

	for ip := range mapA {
		if _, found := mapB[ip]; !found {
			res.RemovedEndpoints = append(res.RemovedEndpoints, ip)
		}
	}

	// 3. Format Terminal Output
	var sb strings.Builder
	sb.WriteString("========================================================\n")
	sb.WriteString(fmt.Sprintf(" 🔍 NETWATCH SESSION SNAPSHOT DIFF: %s vs %s\n", filepathBase(fileA), filepathBase(fileB)))
	sb.WriteString("========================================================\n\n")

	sb.WriteString(fmt.Sprintf("• Total Traffic Drift: %.1f%% (%d -> %d packets)\n",
		res.TotalBytesDiffPct, snapA.TotalPackets, snapB.TotalPackets))

	if len(res.NewEndpoints) > 0 {
		sb.WriteString(fmt.Sprintf("\n➕ New Active Endpoints (%d):\n", len(res.NewEndpoints)))
		for _, ep := range res.NewEndpoints {
			sb.WriteString(fmt.Sprintf("   + %s\n", ep))
		}
	}

	if len(res.RemovedEndpoints) > 0 {
		sb.WriteString(fmt.Sprintf("\n➖ Removed Endpoints (%d):\n", len(res.RemovedEndpoints)))
		for _, ep := range res.RemovedEndpoints {
			sb.WriteString(fmt.Sprintf("   - %s\n", ep))
		}
	}

	if len(res.DriftedTalkers) > 0 {
		sb.WriteString(fmt.Sprintf("\n📈 Host Throughput Deviations (>20%% Drift) (%d):\n", len(res.DriftedTalkers)))
		for _, d := range res.DriftedTalkers {
			sb.WriteString(fmt.Sprintf("   ~ %s\n", d))
		}
	}

	res.SummaryText = sb.String()
	return res, res.SummaryText, nil
}

func loadSnapshot(path string) (*aggregator.Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var snap aggregator.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

func filepathBase(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return path
}
