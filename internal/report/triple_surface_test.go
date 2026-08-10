package report

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Codexia-afk/Undertow/internal/aggregator"
	"github.com/Codexia-afk/Undertow/internal/anomaly"
	"github.com/Codexia-afk/Undertow/internal/baseline"
	"github.com/Codexia-afk/Undertow/internal/remote"
)

func TestTripleSurfaceReportingEngine(t *testing.T) {
	tempDir := t.TempDir()
	exportPath := filepath.Join(tempDir, "triple_report.html")

	dropped := uint64(0)
	sm := aggregator.NewStatsManager(60, 200, 100, &dropped, anomaly.DefaultConfig(), baseline.DefaultConfig(), "")

	// 1. Surface 1: Live Snapshot Retrieval (TUI Read Path)
	snap := sm.GetSnapshot()
	if snap == nil {
		t.Fatalf("Surface 1 (Live TUI Read Path): Expected non-nil snapshot")
	}

	// 2. Surface 2: Standalone HTML Export Path
	err := GenerateHTMLReport(snap, "eth0", "port 80", false, exportPath)
	if err != nil {
		t.Fatalf("Surface 2 (HTML Report Export): Failed: %v", err)
	}

	info, err := os.Stat(exportPath)
	if err != nil || info.Size() == 0 {
		t.Fatalf("Surface 2 (HTML Report Export): Output file invalid or empty")
	}

	// 3. Surface 3: Remote Broadcast SSE Web Server Path
	srv := remote.NewServer(":28080", "", sm)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://localhost:28080/")
	if err != nil {
		t.Fatalf("Surface 3 (Remote SSE Web Server): HTTP GET failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Surface 3 (Remote SSE Web Server): Expected 200 OK, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
