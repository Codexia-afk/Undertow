package webhook

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Codexia-afk/Undertow/internal/model"
)

func TestWebhookSender(t *testing.T) {
	received := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.Header.Get("Content-Type") == "application/json" {
			received = true
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer ts.Close()

	sender := NewSender(ts.URL)
	evt := model.AnomalyEvent{
		Timestamp: time.Now(),
		Kind:      "PORT_SCAN",
		SourceIP:  "192.168.1.50",
		Detail:    "Contacted 20 distinct ports",
	}

	err := sender.SendAnomalyAlert(evt)
	if err != nil {
		t.Fatalf("Failed to send webhook alert: %v", err)
	}

	if !received {
		t.Errorf("Expected webhook test server to receive POST request")
	}
}
