package ai

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Codexia-afk/Undertow/internal/model"
)

func TestOllamaClient_GenerateIncidentSummary(t *testing.T) {
	// 1. Test Mock Ollama HTTP Server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/generate" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"response": "MOCK AI SUMMARY: Host 192.168.1.10 exhibited port scan activity.", "done": true}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	client := NewClient(mockServer.URL, "llama3")
	anomalies := []model.AnomalyEvent{
		{
			Timestamp: time.Now(),
			Kind:      "PORT_SCAN",
			SourceIP:  "192.168.1.10",
			Detail:    "Contacted 25 distinct ports",
		},
	}

	summary, err := client.GenerateIncidentSummary("192.168.1.10", "Host 192.168.1.10 connected to multiple endpoints.", anomalies)
	if err != nil {
		t.Fatalf("Failed to generate incident summary: %v", err)
	}

	if !strings.Contains(summary, "MOCK AI SUMMARY") {
		t.Errorf("Expected summary from mock Ollama server, got: %s", summary)
	}

	// 2. Test Offline Fallback Synthesizer
	offlineClient := NewClient("http://localhost:59999", "llama3")
	fallbackSummary, err := offlineClient.GenerateIncidentSummary("192.168.1.10", "Host story text...", anomalies)
	if err != nil {
		t.Fatalf("Failed to generate fallback summary: %v", err)
	}

	if !strings.Contains(fallbackSummary, "UNDERTOW INCIDENT RESPONSE AI SUMMARY") {
		t.Errorf("Expected fallback AI summary header")
	}
}
