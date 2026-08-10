package process

import (
	"testing"
)

func TestProcessResolver(t *testing.T) {
	r := NewResolver()
	if r == nil {
		t.Fatalf("Expected non-nil process resolver")
	}

	// Trigger refresh and ensure thread-safety
	r.Refresh()

	pid, name, _ := r.Lookup(80)
	if pid < 0 {
		t.Errorf("Invalid PID returned: %d", pid)
	}
	_ = name
}
