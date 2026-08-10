package baseline

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"netwatch/internal/model"
)

// HostMetrics maintains EMA averages and running variance using Welford's algorithm.
type HostMetrics struct {
	IP            string    `json:"ip"`
	PacketsSecEMA float64   `json:"packets_sec_ema"`
	BytesSecEMA   float64   `json:"bytes_sec_ema"`
	PortsMinEMA   float64   `json:"ports_min_ema"`
	PacketsSecVar float64   `json:"packets_sec_var"`
	BytesSecVar   float64   `json:"bytes_sec_var"`
	SampleCount   int64     `json:"sample_count"`
	LastUpdated   time.Time `json:"last_updated"`
}

// Config holds adaptive baselining parameters.
type Config struct {
	WarmupSec int     // Warm-up duration in seconds before flagging alerts (default 60)
	Alpha     float64 // EMA smoothing factor (default 0.1)
	SigmaK    float64 // Standard deviation multiplier threshold (default 3.0)
	FilePath  string  // Persistence file path (default ~/.netwatch/baseline.json)
}

// DefaultConfig returns recommended defaults for baselining.
func DefaultConfig() Config {
	home, _ := os.UserHomeDir()
	defaultFile := filepath.Join(home, ".netwatch", "baseline.json")
	return Config{
		WarmupSec: 60,
		Alpha:     0.1,
		SigmaK:    3.0,
		FilePath:  defaultFile,
	}
}

// Manager tracks per-host baselines and evaluates behavioral deviations.
// OWNERSHIP: Thread-safe, safe for concurrent updates/snapshots.
type Manager struct {
	mu        sync.RWMutex
	hosts     map[string]*HostMetrics
	config    Config
	startTime time.Time
}

// NewManager initializes the baseline manager and loads saved baselines if available.
func NewManager(cfg Config) *Manager {
	m := &Manager{
		hosts:     make(map[string]*HostMetrics),
		config:    cfg,
		startTime: time.Now(),
	}

	if cfg.FilePath != "" {
		_ = m.LoadFromFile(cfg.FilePath)
	}

	return m
}

// ObserveHost updates host metrics and evaluates 3-sigma behavioral deviations after warmup.
func (m *Manager) ObserveHost(ip string, pktsSec, bytesSec, portsMin float64, now time.Time) []model.AnomalyEvent {
	m.mu.Lock()
	defer m.mu.Unlock()

	var events []model.AnomalyEvent

	hm, exists := m.hosts[ip]
	if !exists {
		hm = &HostMetrics{
			IP:            ip,
			PacketsSecEMA: pktsSec,
			BytesSecEMA:   bytesSec,
			PortsMinEMA:   portsMin,
			LastUpdated:   now,
		}
		m.hosts[ip] = hm
	}

	isWarmedUp := now.Sub(m.startTime) >= time.Duration(m.config.WarmupSec)*time.Second || hm.SampleCount >= 30

	// 1. Check for 3-sigma deviation if warmed up
	if isWarmedUp && hm.SampleCount > 10 {
		pktsStdDev := math.Sqrt(hm.PacketsSecVar)
		bytesStdDev := math.Sqrt(hm.BytesSecVar)

		// Check Packets/sec deviation
		if pktsStdDev > 1.0 && pktsSec > (hm.PacketsSecEMA+m.config.SigmaK*pktsStdDev) {
			events = append(events, model.AnomalyEvent{
				Timestamp: now,
				Kind:      "BEHAVIORAL_DEVIATION",
				SourceIP:  ip,
				Detail:    fmt.Sprintf("Packets/s rate %.1f exceeds host mean (%.1f ± %.1f)", pktsSec, hm.PacketsSecEMA, pktsStdDev),
			})
		}

		// Check Bytes/sec deviation
		if bytesStdDev > 1024.0 && bytesSec > (hm.BytesSecEMA+m.config.SigmaK*bytesStdDev) {
			events = append(events, model.AnomalyEvent{
				Timestamp: now,
				Kind:      "BEHAVIORAL_DEVIATION",
				SourceIP:  ip,
				Detail:    fmt.Sprintf("Bytes/s rate %.0f B/s exceeds host mean (%.0f ± %.0f B/s)", bytesSec, hm.BytesSecEMA, bytesStdDev),
			})
		}
	}

	// 2. Update EMA and Running Variance via Welford's algorithm
	hm.SampleCount++
	alpha := m.config.Alpha

	// Packets/sec EMA and Variance
	diffP := pktsSec - hm.PacketsSecEMA
	hm.PacketsSecEMA = alpha*pktsSec + (1-alpha)*hm.PacketsSecEMA
	hm.PacketsSecVar = (1-alpha)*(hm.PacketsSecVar + alpha*diffP*diffP)

	// Bytes/sec EMA and Variance
	diffB := bytesSec - hm.BytesSecEMA
	hm.BytesSecEMA = alpha*bytesSec + (1-alpha)*hm.BytesSecEMA
	hm.BytesSecVar = (1-alpha)*(hm.BytesSecVar + alpha*diffB*diffB)

	// Ports/min EMA
	hm.PortsMinEMA = alpha*portsMin + (1-alpha)*hm.PortsMinEMA
	hm.LastUpdated = now

	return events
}

// SaveToFile persists baseline state to disk.
func (m *Manager) SaveToFile(path string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if path == "" {
		path = m.config.FilePath
	}
	if path == "" {
		return nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(m.hosts, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// LoadFromFile loads saved baselines from disk.
func (m *Manager) LoadFromFile(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var loaded map[string]*HostMetrics
	if err := json.Unmarshal(data, &loaded); err != nil {
		return err
	}

	m.hosts = loaded
	return nil
}
