package process

import (
	"testing"

	"github.com/Codexia-afk/Undertow/internal/model"
)

func TestTracker_ResolveFlow(t *testing.T) {
	tracker := NewTracker()
	if tracker == nil {
		t.Fatalf("Expected non-nil process tracker")
	}

	fk := model.FlowKey{
		SrcIP:    "127.0.0.1",
		DstIP:    "127.0.0.1",
		SrcPort:  80,
		DstPort:  54321,
		Protocol: "TCP",
	}

	pid, name, path, user := tracker.ResolveFlow(fk)
	if pid < 0 {
		t.Errorf("Invalid PID: %d", pid)
	}
	_ = name
	_ = path
	_ = user

	matrix := tracker.GetProcessMatrix()
	if matrix == nil {
		t.Errorf("Expected process matrix slice (got nil)")
	}
}
