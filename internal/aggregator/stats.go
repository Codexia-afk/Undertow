package aggregator

import (
	"sort"
	"sync/atomic"
	"time"

	"netwatch/internal/model"
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
}

// NewStatsManager initializes stats state with ring buffer capacities.
func NewStatsManager(throughputSecs, recentPktsCap, anomaliesCap int, droppedPtr *uint64) *StatsManager {
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
	}

	// Publish initial empty snapshot
	sm.PublishSnapshot()
	return sm
}

// AddPacket updates all internal metrics for a newly decoded packet.
// OWNERSHIP: Must only be called by the aggregator goroutine.
func (sm *StatsManager) AddPacket(pkt model.PacketInfo) {
	st := &sm.stats
	st.TotalPackets++
	st.TotalBytes += uint64(pkt.Length)
	st.currentSecBytes += uint64(pkt.Length)

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
	}

	// Push to recent packets
	st.RecentPacketsRing.Push(pkt)
}

// TickSecond rolls the 1-second throughput bucket into history.
// OWNERSHIP: Must only be called by the aggregator goroutine on a 1s ticker.
func (sm *StatsManager) TickSecond() {
	st := &sm.stats
	st.ThroughputRing.Push(st.currentSecBytes)
	st.currentSecBytes = 0
}

// AddAnomaly records an anomaly event.
// OWNERSHIP: Must only be called by the aggregator goroutine.
func (sm *StatsManager) AddAnomaly(evt model.AnomalyEvent) {
	sm.stats.AnomaliesRing.Push(evt)
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
