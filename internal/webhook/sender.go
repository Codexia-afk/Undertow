package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"netwatch/internal/model"
)

// WebhookPayload represents a structured JSON alert event posted to external webhooks.
type WebhookPayload struct {
	Timestamp   string             `json:"timestamp"`
	EventType   string             `json:"event_type"` // "ANOMALY_ALERT" or "SESSION_SNAPSHOT"
	Anomaly     *model.AnomalyEvent `json:"anomaly,omitempty"`
	Message     string             `json:"message"`
}

// Sender delivers security alert payloads to HTTP POST webhook endpoints.
type Sender struct {
	webhookURL string
	client     *http.Client
}

// NewSender initializes a WebhookSender.
func NewSender(url string) *Sender {
	return &Sender{
		webhookURL: url,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// SendAnomalyAlert posts a security anomaly event JSON payload to the configured webhook URL.
func (s *Sender) SendAnomalyAlert(evt model.AnomalyEvent) error {
	if s.webhookURL == "" {
		return nil
	}

	payload := WebhookPayload{
		Timestamp: evt.Timestamp.Format(time.RFC3339),
		EventType: "ANOMALY_ALERT",
		Anomaly:   &evt,
		Message:   fmt.Sprintf("[%s] Security Alert: %s (Src: %s)", evt.Kind, evt.Detail, evt.SourceIP),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", s.webhookURL, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "NetWatch-Webhook-Engine/3.0.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending webhook to %s: %w", s.webhookURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook endpoint %s returned status %d", s.webhookURL, resp.StatusCode)
	}

	return nil
}
