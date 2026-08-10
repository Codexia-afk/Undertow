package aggregator

import (
	"sort"
	"sync/atomic"
	"time"

	"github.com/Codexia-afk/Undertow/internal/anomaly"
	"github.com/Codexia-afk/Undertow/internal/baseline"
	"github.com/Codexia-afk/Undertow/internal/model"
	"github.com/Codexia-afk/Undertow/internal/narrative"
	"github.com/Codexia-afk/Undertow/internal/webhook"
)

// TalkerStat records per-IP bandwidth and packet counts.
type TalkerStat struct {
	IP          string
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64
	LastSeen    time.Time
}

// TotalBytes returns sum of bytes sent and received.
func (t *TalkerStat) TotalBytes() uint64 {
	return t.BytesSent + t.BytesRecv
}

// Snapshot is an immutable copy of aggregator state published for TUI rendering.
type Snapshot struct {
	Timestamp         time.Time
	StartTime         time.Time
	TotalPackets      uint64
	TotalBytes        uint64
	DroppedPackets    uint64
	ProtocolCounts    map[string]uint64
	TopTalkers        []TalkerStat // Sorted by total bytes descending
	Flows             []model.FlowStat
	ThroughputHistory []uint64 // Bytes per second over last N seconds
	RecentPackets     []model.PacketInfo
	Anomalies         []model.AnomalyEvent
	StoryTracker      *narrative.StoryTracker
}

// RingBuffer stores a fixed-size ring of generic items.
type RingBuffer[T any] struct {
	data  []T
	capacity int
	head  int
	size  int
}

// NewRingBuffer initializes a ring buffer with the given capacity.
func NewRingBuffer[T any](capacity int) *RingBuffer[T] {
	return &RingBuffer[T]{
		data:     make([]T, capacity),
		capacity: capacity,
	}
}

// Push adds an item to the ring buffer.
func (r *RingBuffer[T]) Push(item T) {
	if r.capacity == 0 {
		return
	}
	r.data[r.head] = item
	r.head = (r.head + 1) % r.capacity
	if r.size < r.capacity {
		r.size++
	}
}

// Slice returns all elements in chronological order (oldest to newest).
func (r *RingBuffer[T]) Slice() []T {
	if r.size == 0 {
		return nil
	}
	res := make([]T, r.size)
	if r.size < r.capacity {
		copy(res, r.data[:r.size])
	} else {
		// Ring full: head points to oldest element
		n := copy(res, r.data[r.head:])
		copy(res[n:], r.data[:r.head])
	}
	return res
}

// Stats represents the aggregator's internal mutable state.
// OWNERSHIP: Only the single aggregator goroutine writes to Stats.
type Stats struct {
	StartTime         time.Time
	TotalPackets      uint64
	TotalBytes        uint64
	DroppedPackets    uint64
	ProtocolCounts    map[string]uint64
	TopTalkers        map[string]*TalkerStat
	Flows             map[model.FlowKey]*model.FlowStat
	ThroughputRing    *RingBuffer[uint64]
	RecentPacketsRing *RingBuffer[model.PacketInfo]
	AnomaliesRing     *RingBuffer[model.AnomalyEvent]

	currentSecBytes uint64
}

// StatsManager encapsulates Stats and publishes snapshots atomically.
type StatsManager struct {
	stats           Stats
	publishedPtr    atomic.Pointer[Snapshot]
	droppedCountPtr *uint64 // Shared pointer to atomic dropped count from capture producer
	detector        *anomaly.Detector
	storyTracker    *narrative.StoryTracker
	baselineMgr     *baseline.Manager
	webhookSender   *webhook.Sender
}

// NewStatsManager initializes stats state with ring buffer capacities, anomaly detector, baseline manager, and optional webhook sender.
func NewStatsManager(throughputSecs, recentPktsCap, anomaliesCap int, droppedPtr *uint64, anomalyCfg anomaly.Config, baselineCfg baseline.Config, webhookURL string) *StatsManager {
	var ws *webhook.Sender
	if webhookURL != "" {
		ws = webhook.NewSender(webhookURL)
	}

	sm := &StatsManager{
		stats: Stats{
			StartTime:         time.Now(),
			ProtocolCounts:    make(map[string]uint64),
			TopTalkers:        make(map[string]*TalkerStat),
			Flows:             make(map[model.FlowKey]*model.FlowStat),
			ThroughputRing:    NewRingBuffer[uint64](throughputSecs),
			RecentPacketsRing: NewRingBuffer[model.PacketInfo](recentPktsCap),
			AnomaliesRing:     NewRingBuffer[model.AnomalyEvent](anomaliesCap),
		},
		droppedCountPtr: droppedPtr,
		detector:        anomaly.NewDetector(anomalyCfg),
		storyTracker:    narrative.NewStoryTracker(),
		baselineMgr:     baseline.NewManager(baselineCfg),
		webhookSender:   ws,
	}

	// Publish initial empty snapshot
	sm.PublishSnapshot()
	return sm
}

// AddPacket updates all internal metrics for a newly decoded packet and evaluates anomaly heuristics.
// OWNERSHIP: Must only be called by the aggregator goroutine.
func (sm *StatsManager) AddPacket(pkt model.PacketInfo) {
	st := &sm.stats
	st.TotalPackets++
	st.TotalBytes += uint64(pkt.Length)
	st.currentSecBytes += uint64(pkt.Length)

	// Record story timeline event
	if sm.storyTracker != nil {
		sm.storyTracker.RecordPacket(pkt)
	}

	// Update protocol counter
	st.ProtocolCounts[pkt.Protocol]++

	// Update Top Talkers
	if pkt.SrcIP != nil {
		srcIP := pkt.SrcIP.String()
		srcStat, exists := st.TopTalkers[srcIP]
		if !exists {
			srcStat = &TalkerStat{IP: srcIP}
			st.TopTalkers[srcIP] = srcStat
		}
		srcStat.PacketsSent++
		srcStat.BytesSent += uint64(pkt.Length)
		srcStat.LastSeen = pkt.Timestamp
	}

	if pkt.DstIP != nil {
		dstIP := pkt.DstIP.String()
		dstStat, exists := st.TopTalkers[dstIP]
		if !exists {
			dstStat = &TalkerStat{IP: dstIP}
			st.TopTalkers[dstIP] = dstStat
		}
		dstStat.PacketsRecv++
		dstStat.BytesRecv += uint64(pkt.Length)
		dstStat.LastSeen = pkt.Timestamp
	}

	// Update Flow
	var currentFlow *model.FlowStat
	if pkt.SrcIP != nil && pkt.DstIP != nil {
		fk := model.FlowKey{
			SrcIP:    pkt.SrcIP.String(),
			DstIP:    pkt.DstIP.String(),
			SrcPort:  pkt.SrcPort,
			DstPort:  pkt.DstPort,
			Protocol: pkt.Protocol,
		}
		flow, exists := st.Flows[fk]
		if !exists {
			flow = &model.FlowStat{Key: fk}
			st.Flows[fk] = flow
		}
		flow.PacketsSent++
		flow.BytesSent += uint64(pkt.Length)
		flow.LastSeen = pkt.Timestamp
		currentFlow = flow
	}

	// Push to recent packets
	st.RecentPacketsRing.Push(pkt)

	// Run Anomaly Detection Heuristics
	if sm.detector != nil {
		events := sm.detector.CheckPacket(pkt, currentFlow)
		for _, evt := range events {
			sm.AddAnomaly(evt)
		}
	}
}

// TickSecond rolls the 1-second throughput bucket into history and evaluates behavioral baselines.
// OWNERSHIP: Must only be called by the aggregator goroutine on a 1s ticker.
func (sm *StatsManager) TickSecond() {
	st := &sm.stats
	now := time.Now()
	st.ThroughputRing.Push(st.currentSecBytes)
	st.currentSecBytes = 0

	// Evaluate Behavioral Baselines per host
	if sm.baselineMgr != nil {
		for _, talker := range st.TopTalkers {
			pktsSec := float64(talker.PacketsSent + talker.PacketsRecv)
			bytesSec := float64(talker.BytesSent + talker.BytesRecv)
			events := sm.baselineMgr.ObserveHost(talker.IP, pktsSec, bytesSec, 1.0, now)
			for _, evt := range events {
				sm.AddAnomaly(evt)
			}
		}
	}
}

// SaveBaseline persists baseline data to disk on shutdown.
func (sm *StatsManager) SaveBaseline() {
	if sm.baselineMgr != nil {
		_ = sm.baselineMgr.SaveToFile("")
	}
}

// AddAnomaly records an anomaly event and passes it to the host story timeline.
// OWNERSHIP: Must only be called by the aggregator goroutine.
func (sm *StatsManager) AddAnomaly(evt model.AnomalyEvent) {
	sm.stats.AnomaliesRing.Push(evt)
	if sm.storyTracker != nil {
		sm.storyTracker.RecordAnomaly(evt)
	}
	if sm.webhookSender != nil {
		go func(e model.AnomalyEvent) {
			_ = sm.webhookSender.SendAnomalyAlert(e)
		}(evt)
	}
}

// PublishSnapshot creates a deep copy of current metrics and updates publishedPtr atomically.
// OWNERSHIP: Called by aggregator goroutine.
func (sm *StatsManager) PublishSnapshot() {
	st := &sm.stats

	// Read atomic dropped packets
	var dropped uint64
	if sm.droppedCountPtr != nil {
		dropped = atomic.LoadUint64(sm.droppedCountPtr)
	}

	// Deep copy protocol counts
	protoCounts := make(map[string]uint64, len(st.ProtocolCounts))
	for k, v := range st.ProtocolCounts {
		protoCounts[k] = v
	}

	// Deep copy & sort top talkers
	talkers := make([]TalkerStat, 0, len(st.TopTalkers))
	for _, t := range st.TopTalkers {
		talkers = append(talkers, *t)
	}
	sort.Slice(talkers, func(i, j int) bool {
		return talkers[i].TotalBytes() > talkers[j].TotalBytes()
	})

	// Deep copy flows
	flows := make([]model.FlowStat, 0, len(st.Flows))
	for _, f := range st.Flows {
		flows = append(flows, *f)
	}

	snap := &Snapshot{
		Timestamp:         time.Now(),
		StartTime:         st.StartTime,
		TotalPackets:      st.TotalPackets,
		TotalBytes:        st.TotalBytes,
		DroppedPackets:    dropped,
		ProtocolCounts:    protoCounts,
		TopTalkers:        talkers,
		Flows:             flows,
		ThroughputHistory: st.ThroughputRing.Slice(),
		RecentPackets:     st.RecentPacketsRing.Slice(),
		Anomalies:         st.AnomaliesRing.Slice(),
		StoryTracker:      sm.storyTracker,
	}

	sm.publishedPtr.Store(snap)
}

// GetSnapshot returns the latest published snapshot. Safe for concurrent access by UI/consumers.
func (sm *StatsManager) GetSnapshot() *Snapshot {
	snap := sm.publishedPtr.Load()
	if snap == nil {
		return &Snapshot{ProtocolCounts: make(map[string]uint64)}
	}
	return snap
}
