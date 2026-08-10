package remote

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"netwatch/internal/aggregator"
	"netwatch/internal/anomaly"
	"netwatch/internal/baseline"
)

func TestRemoteServer_HTTPAndAuth(t *testing.T) {
	var dropped uint64 = 0
	sm := aggregator.NewStatsManager(60, 200, 100, &dropped, anomaly.DefaultConfig(), baseline.DefaultConfig())

	srv := NewServer(":18080", "secret123", sm)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// 1. Request without token -> 401 Unauthorized expected
	resp, err := http.Get("http://localhost:18080/")
	if err != nil {
		t.Fatalf("Failed to send HTTP GET: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized without token, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 2. Request with valid token -> 200 OK expected
	resp2, err := http.Get("http://localhost:18080/?token=secret123")
	if err != nil {
		t.Fatalf("Failed to send authenticated HTTP GET: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK with valid token, got %d", resp2.StatusCode)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if !strings.Contains(string(body), "NetWatch Remote Broadcast Dashboard") {
		t.Errorf("Expected embedded HTML content")
	}
}
