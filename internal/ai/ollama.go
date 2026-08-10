package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Codexia-afk/Undertow/internal/model"
)

// OllamaRequest represents the request payload sent to local Ollama API.
type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

// OllamaResponse represents the JSON response received from local Ollama API.
type OllamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// Client manages offline connection to local Ollama AI engine.
type Client struct {
	endpoint string
	model    string
	client   *http.Client
}

// NewClient initializes a local Ollama AI client.
func NewClient(endpoint, modelName string) *Client {
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	if modelName == "" {
		modelName = "llama3"
	}
	return &Client{
		endpoint: endpoint,
		model:    modelName,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GenerateIncidentSummary sends host timeline stories and anomaly logs to local Ollama LLM.
func (c *Client) GenerateIncidentSummary(targetHost string, flowStory string, anomalies []model.AnomalyEvent) (string, error) {
	var anomalySb strings.Builder
	if len(anomalies) == 0 {
		anomalySb.WriteString("No 3-sigma or security anomalies flagged for this host.")
	} else {
		for _, a := range anomalies {
			anomalySb.WriteString(fmt.Sprintf("- [%s] %s: %s\n", a.Kind, a.SourceIP, a.Detail))
		}
	}

	prompt := fmt.Sprintf(`You are a Tier-3 Cyber Security Analyst conducting an incident response audit.
Analyze the following network flow narrative and anomaly events for host '%s' and output a concise, structured incident report in plain English:

[HOST NETWORK FLOW NARRATIVE]
%s

[FLAGGED ANOMALY LOGS]
%s

Provide:
1. Executive Assessment
2. Risk Level (Low/Medium/High/Critical)
3. Recommended Mitigation Actions`, targetHost, flowStory, anomalySb.String())

	reqPayload := OllamaRequest{
		Model:  c.model,
		Prompt: prompt,
		Stream: false,
	}

	data, err := json.Marshal(reqPayload)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/api/generate", strings.TrimSuffix(c.endpoint, "/"))
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		// Provide high-quality local heuristic summary when Ollama service is unreachable
		return c.generateLocalFallbackSummary(targetHost, flowStory, anomalies), nil
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return c.generateLocalFallbackSummary(targetHost, flowStory, anomalies), nil
	}

	var ollamaResp OllamaResponse
	if err := json.Unmarshal(respBytes, &ollamaResp); err != nil || ollamaResp.Response == "" {
		return c.generateLocalFallbackSummary(targetHost, flowStory, anomalies), nil
	}

	return ollamaResp.Response, nil
}

func (c *Client) generateLocalFallbackSummary(targetHost string, flowStory string, anomalies []model.AnomalyEvent) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🤖 UNDERTOW INCIDENT RESPONSE AI SUMMARY (Host: %s)\n", targetHost))
	sb.WriteString("======================================================================\n\n")

	riskLevel := "LOW"
	if len(anomalies) > 3 {
		riskLevel = "CRITICAL"
	} else if len(anomalies) > 0 {
		riskLevel = "HIGH"
	}

	sb.WriteString(fmt.Sprintf("• Risk Level: %s\n", riskLevel))
	sb.WriteString(fmt.Sprintf("• Offline Intelligence Mode: Local Rule Synthesizer (Ollama offline at %s)\n\n", c.endpoint))

	sb.WriteString("1. EXECUTIVE ASSESSMENT:\n")
	sb.WriteString(fmt.Sprintf("   Host %s was monitored during the active capture window. ", targetHost))
	if len(anomalies) > 0 {
		sb.WriteString(fmt.Sprintf("%d anomalous events were detected including %s.\n\n", len(anomalies), anomalies[0].Kind))
	} else {
		sb.WriteString("Traffic flow observed normal baseline communication patterns with no severe deviations.\n\n")
	}

	sb.WriteString("2. DETECTED ANOMALIES & BEHAVIOR:\n")
	if len(anomalies) > 0 {
		for _, a := range anomalies {
			sb.WriteString(fmt.Sprintf("   ⚠️  [%s] %s\n", a.Kind, a.Detail))
		}
	} else {
		sb.WriteString("   ✓ No anomalous port scans, DGA entropy spikes, or 3-sigma deviations.\n")
	}
	sb.WriteString("\n3. RECOMMENDED ACTIONS:\n")
	if riskLevel != "LOW" {
		sb.WriteString("   - Isolate host network interface for forensic packet inspection.\n")
		sb.WriteString("   - Correlate process PID with endpoint EDR telemetry.\n")
	} else {
		sb.WriteString("   - Continue standard continuous network monitoring.\n")
	}

	return sb.String()
}
