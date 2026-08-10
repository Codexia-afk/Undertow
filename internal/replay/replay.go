package replay

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/Codexia-afk/Undertow/internal/decode"
	"github.com/Codexia-afk/Undertow/internal/model"
)

// ReplayStatus holds virtual clock playback state.
type ReplayStatus struct {
	IsReplay      bool
	IsPaused      bool
	Speed         float64
	CurrentTime   time.Time
	StartTime     time.Time
	EndTime       time.Time
	TotalPackets  int
	CurrentIndex  int
}

// ReplayEngine handles offline pcap file playback with virtual time scrubbing.
type ReplayEngine struct {
	mu           sync.Mutex
	filename     string
	packets      []model.PacketInfo
	outChan      chan model.PacketInfo
	speed        float64
	isPaused     bool
	currentIndex int
	startTime    time.Time
	endTime      time.Time
}

// NewReplayEngine opens a recorded pcap file and parses all packets for virtual clock playback.
func NewReplayEngine(filename string, bufferSize int) (*ReplayEngine, <-chan model.PacketInfo, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("opening pcap file %s: %w", filename, err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var decoded []model.PacketInfo

	for pkt := range packetSource.Packets() {
		info := decode.DecodePacket(pkt)
		decoded = append(decoded, info)
	}

	if len(decoded) == 0 {
		return nil, nil, fmt.Errorf("pcap file %s contains no packets", filename)
	}

	outChan := make(chan model.PacketInfo, bufferSize)

	engine := &ReplayEngine{
		filename:     filename,
		packets:      decoded,
		outChan:      outChan,
		speed:        1.0,
		isPaused:     false,
		currentIndex: 0,
		startTime:    decoded[0].Timestamp,
		endTime:      decoded[len(decoded)-1].Timestamp,
	}

	return engine, outChan, nil
}

// Status returns current replay engine playback metadata.
func (re *ReplayEngine) Status() ReplayStatus {
	re.mu.Lock()
	defer re.mu.Unlock()

	curTime := re.startTime
	if re.currentIndex < len(re.packets) {
		curTime = re.packets[re.currentIndex].Timestamp
	} else if len(re.packets) > 0 {
		curTime = re.endTime
	}

	return ReplayStatus{
		IsReplay:     true,
		IsPaused:     re.isPaused,
		Speed:        re.speed,
		CurrentTime:  curTime,
		StartTime:    re.startTime,
		EndTime:      re.endTime,
		TotalPackets: len(re.packets),
		CurrentIndex: re.currentIndex,
	}
}

// TogglePause toggles play/pause state.
func (re *ReplayEngine) TogglePause() bool {
	re.mu.Lock()
	defer re.mu.Unlock()
	re.isPaused = !re.isPaused
	return re.isPaused
}

// SetSpeed sets the virtual playback multiplier (0.5x, 1x, 2x, 4x, 8x).
func (re *ReplayEngine) SetSpeed(speed float64) {
	re.mu.Lock()
	defer re.mu.Unlock()
	if speed > 0 {
		re.speed = speed
	}
}

// CycleSpeed cycles through playback speeds (1x -> 2x -> 4x -> 8x -> 0.5x -> 1x).
func (re *ReplayEngine) CycleSpeed() float64 {
	re.mu.Lock()
	defer re.mu.Unlock()
	switch re.speed {
	case 1.0:
		re.speed = 2.0
	case 2.0:
		re.speed = 4.0
	case 4.0:
		re.speed = 8.0
	case 8.0:
		re.speed = 0.5
	default:
		re.speed = 1.0
	}
	return re.speed
}

// StepSec steps playback forward or backward by N seconds.
func (re *ReplayEngine) StepSec(seconds int) {
	re.mu.Lock()
	defer re.mu.Unlock()

	if len(re.packets) == 0 {
		return
	}

	targetTime := re.packets[re.currentIndex].Timestamp.Add(time.Duration(seconds) * time.Second)
	if seconds > 0 {
		for re.currentIndex < len(re.packets)-1 && re.packets[re.currentIndex].Timestamp.Before(targetTime) {
			re.currentIndex++
		}
	} else {
		for re.currentIndex > 0 && re.packets[re.currentIndex].Timestamp.After(targetTime) {
			re.currentIndex--
		}
	}
}

// JumpStart jumps playback to the beginning of the recording.
func (re *ReplayEngine) JumpStart() {
	re.mu.Lock()
	defer re.mu.Unlock()
	re.currentIndex = 0
}

// JumpEnd jumps playback to the end of the recording.
func (re *ReplayEngine) JumpEnd() {
	re.mu.Lock()
	defer re.mu.Unlock()
	if len(re.packets) > 0 {
		re.currentIndex = len(re.packets) - 1
	}
}

// Run executes the virtual clock playback loop, pushing packets to outChan.
func (re *ReplayEngine) Run(ctx context.Context) {
	defer close(re.outChan)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		re.mu.Lock()
		if re.currentIndex >= len(re.packets) {
			re.mu.Unlock()
			// Replay finished: wait for context cancel
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if re.isPaused {
			re.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
			continue
		}

		pkt := re.packets[re.currentIndex]
		nextIndex := re.currentIndex + 1
		speed := re.speed
		re.currentIndex++
		re.mu.Unlock()

		// Send packet to outChan
		select {
		case <-ctx.Done():
			return
		case re.outChan <- pkt:
		}

		// Pace virtual clock delay to match real timestamps scaled by speed
		if nextIndex < len(re.packets) {
			nextPkt := re.packets[nextIndex]
			delay := nextPkt.Timestamp.Sub(pkt.Timestamp)
			if delay > 0 {
				scaledDelay := time.Duration(float64(delay) / speed)
				// Cap max delay to 2 seconds for interactive responsiveness during idle periods
				if scaledDelay > 2*time.Second {
					scaledDelay = 2 * time.Second
				}
				time.Sleep(scaledDelay)
			}
		}
	}
}
