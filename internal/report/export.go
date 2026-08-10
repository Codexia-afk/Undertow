package report

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"netwatch/internal/aggregator"
)

// ReportData holds sanitized view data for HTML report template rendering.
type ReportData struct {
	Title             string
	GeneratedAt       string
	Interface         string
	Filter            string
	Duration          string
	TotalPackets      uint64
	TotalBytesFormatted string
	DroppedPackets    uint64
	ProtocolCounts    map[string]uint64
	TopTalkers        []aggregator.TalkerStat
	Anomalies         []string
	HostStories       []string
	ThroughputSVG     template.HTML
	ProtocolSVG       template.HTML
}

// GenerateHTMLReport builds a standalone HTML report file with inline CSS and SVG vector graphics.
func GenerateHTMLReport(snap *aggregator.Snapshot, iface, filterExpr string, redactIPs bool, outputFile string) error {
	elapsed := time.Since(snap.StartTime).Truncate(time.Second)

	filterDisplay := "None"
	if filterExpr != "" {
		filterDisplay = filterExpr
	}

	// 1. Format Anomalies
	var anomalyLines []string
	for _, a := range snap.Anomalies {
		line := fmt.Sprintf("[%s] %s - %s (Src: %s)",
			a.Timestamp.Format("15:04:05"), a.Kind, a.Detail, a.SourceIP)
		anomalyLines = append(anomalyLines, line)
	}

	// 2. Format Host Stories for top 5 hosts
	var hostStories []string
	if snap.StoryTracker != nil {
		maxHosts := 5
		if len(snap.TopTalkers) < maxHosts {
			maxHosts = len(snap.TopTalkers)
		}
		for i := 0; i < maxHosts; i++ {
			story := snap.StoryTracker.GenerateNarrative(snap.TopTalkers[i].IP, redactIPs)
			hostStories = append(hostStories, story)
		}
	}

	// 3. Render Inline SVG Charts
	tpSVG := renderThroughputSVG(snap.ThroughputHistory)
	protoSVG := renderProtocolSVG(snap.ProtocolCounts, snap.TotalPackets)

	data := ReportData{
		Title:               "NetWatch SOC Traffic Intelligence Report",
		GeneratedAt:         time.Now().Format("2006-01-02 15:04:05 MST"),
		Interface:           iface,
		Filter:              filterDisplay,
		Duration:            elapsed.String(),
		TotalPackets:        snap.TotalPackets,
		TotalBytesFormatted: formatBytes(snap.TotalBytes),
		DroppedPackets:      snap.DroppedPackets,
		ProtocolCounts:      snap.ProtocolCounts,
		TopTalkers:          snap.TopTalkers,
		Anomalies:           anomalyLines,
		HostStories:         hostStories,
		ThroughputSVG:       template.HTML(tpSVG),
		ProtocolSVG:         template.HTML(protoSVG),
	}

	tmpl, err := template.New("report").Parse(htmlReportTemplate)
	if err != nil {
		return fmt.Errorf("parsing HTML report template: %w", err)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("creating report file %s: %w", outputFile, err)
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func renderThroughputSVG(history []uint64) string {
	if len(history) == 0 {
		return `<svg width="700" height="150"><text x="350" y="75" fill="#94a3b8" text-anchor="middle">No throughput data available</text></svg>`
	}

	var maxVal uint64
	for _, v := range history {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}

	width := 700
	height := 150
	barWidth := float64(width) / float64(len(history))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg width="%d" height="%d" viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg">`, width, height, width, height))
	sb.WriteString(`<defs><linearGradient id="barGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#38bdf8"/><stop offset="100%" stop-color="#0284c7"/></linearGradient></defs>`)

	for i, val := range history {
		barH := (float64(val) / float64(maxVal)) * float64(height-20)
		x := float64(i) * barWidth
		y := float64(height) - barH

		sb.WriteString(fmt.Sprintf(`<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="url(#barGrad)" rx="2"><title>%.0f B/s</title></rect>`,
			x, y, barWidth-1, barH, float64(val)))
	}

	sb.WriteString(`</svg>`)
	return sb.String()
}

func renderProtocolSVG(counts map[string]uint64, total uint64) string {
	if total == 0 {
		return `<svg width="400" height="150"><text x="200" y="75" fill="#94a3b8" text-anchor="middle">No protocol data available</text></svg>`
	}

	protocols := []string{"TCP", "UDP", "TLS", "DNS", "HTTP", "ICMP", "Other"}
	colors := map[string]string{
		"TCP": "#38bdf8", "UDP": "#60a5fa", "TLS": "#22c55e",
		"DNS": "#facc15", "HTTP": "#c084fc", "ICMP": "#f43f5e", "Other": "#94a3b8",
	}

	var sb strings.Builder
	sb.WriteString(`<svg width="450" height="180" viewBox="0 0 450 180" xmlns="http://www.w3.org/2000/svg">`)

	y := 10
	for _, proto := range protocols {
		cnt := counts[proto]
		if cnt == 0 {
			continue
		}
		pct := (float64(cnt) / float64(total)) * 100.0
		barWidth := (pct / 100.0) * 250.0
		color := colors[proto]

		sb.WriteString(fmt.Sprintf(`<text x="10" y="%d" fill="#e2e8f0" font-family="sans-serif" font-size="12" font-weight="bold">%s</text>`, y+12, proto))
		sb.WriteString(fmt.Sprintf(`<rect x="70" y="%d" width="%.1f" height="14" fill="%s" rx="3"/>`, y, barWidth, color))
		sb.WriteString(fmt.Sprintf(`<text x="%.1f" y="%d" fill="#94a3b8" font-family="sans-serif" font-size="11"> %d (%.1f%%)</text>`, 75+barWidth, y+12, cnt, pct))

		y += 24
	}

	sb.WriteString(`</svg>`)
	return sb.String()
}

func formatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.Title}}</title>
<style>
  :root {
    --bg-dark: #0f172a;
    --card-bg: #1e293b;
    --border-color: #334155;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
    --accent-blue: #38bdf8;
    --accent-green: #22c55e;
    --accent-red: #f43f5e;
    --accent-yellow: #facc15;
  }
  body {
    background-color: var(--bg-dark);
    color: var(--text-main);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    margin: 0;
    padding: 24px;
  }
  .container { max-width: 1100px; margin: 0 auto; }
  .header {
    display: flex; justify-content: space-between; align-items: center;
    border-bottom: 2px solid var(--border-color); padding-bottom: 16px; margin-bottom: 24px;
  }
  .title { font-size: 24px; font-weight: bold; color: var(--accent-blue); margin: 0; }
  .badge { background: #0284c7; color: #fff; padding: 4px 10px; borderRadius: 4px; font-size: 12px; font-weight: bold; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; }
  .card-title { font-size: 12px; color: var(--text-muted); text-transform: uppercase; margin-bottom: 8px; }
  .card-value { font-size: 22px; font-weight: bold; color: var(--text-main); }
  .section-title { font-size: 18px; font-weight: bold; color: var(--accent-blue); margin-top: 32px; margin-bottom: 16px; border-bottom: 1px solid var(--border-color); padding-bottom: 8px; }
  table { width: 100%; border-collapse: collapse; background: var(--card-bg); border-radius: 8px; overflow: hidden; margin-bottom: 24px; }
  th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border-color); }
  th { background: #0f172a; color: var(--accent-yellow); font-size: 13px; text-transform: uppercase; }
  .pre-box { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; font-family: monospace; white-space: pre-wrap; font-size: 13px; color: #e2e8f0; margin-bottom: 12px; }
  .alert-card { background: #450a0a; border: 1px solid var(--accent-red); border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; color: #fca5a5; font-family: monospace; font-size: 13px; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1 class="title">🛡️ {{.Title}}</h1>
      <div style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Generated: {{.GeneratedAt}}</div>
    </div>
    <span class="badge">NetWatch Standalone Report</span>
  </div>

  <div class="grid">
    <div class="card"><div class="card-title">Interface</div><div class="card-value">{{.Interface}}</div></div>
    <div class="card"><div class="card-title">Capture Duration</div><div class="card-value">{{.Duration}}</div></div>
    <div class="card"><div class="card-title">Total Packets</div><div class="card-value">{{.TotalPackets}}</div></div>
    <div class="card"><div class="card-title">Total Volume</div><div class="card-value">{{.TotalBytesFormatted}}</div></div>
  </div>

  <div class="section-title">📊 Bandwidth Throughput History</div>
  <div class="card">{{.ThroughputSVG}}</div>

  <div style="display: flex; gap: 24px; margin-top: 24px;">
    <div style="flex: 1;">
      <div class="section-title">🔌 Protocol Distribution</div>
      <div class="card">{{.ProtocolSVG}}</div>
    </div>
    <div style="flex: 1;">
      <div class="section-title">🛡️ Security Anomalies</div>
      {{if .Anomalies}}
        {{range .Anomalies}}
          <div class="alert-card">⚠️ {{.}}</div>
        {{end}}
      {{else}}
        <div class="card" style="color: var(--accent-green);">✓ Zero security anomalies flagged during capture session.</div>
      {{end}}
    </div>
  </div>

  <div class="section-title">🔝 Top Bandwidth Talkers</div>
  <table>
    <thead>
      <tr>
        <th>IP Address</th>
        <th>Bytes Sent</th>
        <th>Bytes Recv</th>
        <th>Total Packets</th>
        <th>Last Active</th>
      </tr>
    </thead>
    <tbody>
      {{range .TopTalkers}}
      <tr>
        <td style="color: var(--accent-green); font-weight: bold;">{{.IP}}</td>
        <td>{{.BytesSent}}</td>
        <td>{{.BytesRecv}}</td>
        <td>{{.PacketsSent}}</td>
        <td style="color: var(--text-muted);">{{.LastSeen.Format "15:04:05"}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>

  <div class="section-title">📖 Host Session Flow Stories</div>
  {{range .HostStories}}
    <div class="pre-box">{{.}}</div>
  {{end}}
</div>
</body>
</html>`
