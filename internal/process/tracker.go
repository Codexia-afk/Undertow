package process

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Codexia-afk/Undertow/internal/model"
)

// FlowProcessInfo stores local OS process metadata linked to a 5-tuple flow.
type FlowProcessInfo struct {
	PID            int
	ProcessName    string
	ExecutablePath string
	User           string
	LocalPort      uint16
	RemotePort     uint16
	Protocol       string
	LastUpdated    time.Time
}

// Tracker correlates network flows to local operating system processes.
type Tracker struct {
	mu         sync.RWMutex
	portMap    map[uint16]*FlowProcessInfo
	lastLookup time.Time
}

// NewTracker initializes a Flow-to-Process Tracker.
func NewTracker() *Tracker {
	t := &Tracker{
		portMap: make(map[uint16]*FlowProcessInfo),
	}
	t.Refresh()
	return t
}

// ResolveFlow returns local process metadata (PID, ProcessName, ExecutablePath, User) for a network flow.
func (t *Tracker) ResolveFlow(fk model.FlowKey) (int, string, string, string) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Try local port lookup
	if info, found := t.portMap[fk.SrcPort]; found {
		return info.PID, info.ProcessName, info.ExecutablePath, info.User
	}
	if info, found := t.portMap[fk.DstPort]; found {
		return info.PID, info.ProcessName, info.ExecutablePath, info.User
	}

	return 0, "System/Kernel", "-", "root"
}

// Refresh scans system sockets and correlates PIDs, process names, paths, and user owners.
func (t *Tracker) Refresh() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if time.Since(t.lastLookup) < 2*time.Second && len(t.portMap) > 0 {
		return
	}
	t.lastLookup = time.Now()

	switch runtime.GOOS {
	case "linux":
		t.refreshLinux()
	case "windows":
		t.refreshWindows()
	case "darwin":
		t.refreshMacOS()
	}
}

func (t *Tracker) refreshLinux() {
	inodes := make(map[string]uint16)

	parseProcNet := func(filePath string) {
		f, err := os.Open(filePath)
		if err != nil {
			return
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Scan()
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}
			localAddrHex := fields[1]
			inode := fields[9]

			parts := strings.Split(localAddrHex, ":")
			if len(parts) == 2 {
				if p, err := strconv.ParseUint(parts[1], 16, 16); err == nil {
					inodes[inode] = uint16(p)
				}
			}
		}
	}

	parseProcNet("/proc/net/tcp")
	parseProcNet("/proc/net/udp")

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		commBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		procName := strings.TrimSpace(string(commBytes))
		if procName == "" {
			procName = fmt.Sprintf("PID_%d", pid)
		}

		exePath, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))

		userName := "root"
		statusBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		for _, line := range strings.Split(string(statusBytes), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if u, err := user.LookupId(fields[1]); err == nil {
						userName = u.Username
					}
				}
				break
			}
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			linkTarget, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}

			if strings.HasPrefix(linkTarget, "socket:[") {
				inode := strings.TrimSuffix(strings.TrimPrefix(linkTarget, "socket:["), "]")
				if port, found := inodes[inode]; found {
					t.portMap[port] = &FlowProcessInfo{
						PID:            pid,
						ProcessName:    procName,
						ExecutablePath: exePath,
						User:           userName,
						LocalPort:      port,
						LastUpdated:    time.Now(),
					}
				}
			}
		}
	}
}

func (t *Tracker) refreshWindows() {
	cmd := exec.Command("netstat", "-ano", "-p", "tcp")
	out, err := cmd.Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && strings.HasPrefix(fields[0], "TCP") {
			localAddr := fields[1]
			pidStr := fields[len(fields)-1]
			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				continue
			}

			parts := strings.Split(localAddr, ":")
			if len(parts) >= 2 {
				portStr := parts[len(parts)-1]
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
					t.portMap[uint16(p)] = &FlowProcessInfo{
						PID:         pid,
						ProcessName: fmt.Sprintf("Process_%d", pid),
						User:        "SYSTEM",
						LocalPort:   uint16(p),
						LastUpdated: time.Now(),
					}
				}
			}
		}
	}
}

func (t *Tracker) refreshMacOS() {
	cmd := exec.Command("lsof", "-i", "-n", "-P")
	out, err := cmd.Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 9 {
			procName := fields[0]
			pid, _ := strconv.Atoi(fields[1])
			userName := fields[2]
			addrInfo := fields[8]

			parts := strings.Split(addrInfo, ":")
			if len(parts) >= 2 {
				portStr := strings.Split(parts[len(parts)-1], "->")[0]
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
					t.portMap[uint16(p)] = &FlowProcessInfo{
						PID:         pid,
						ProcessName: procName,
						User:        userName,
						LocalPort:   uint16(p),
						LastUpdated: time.Now(),
					}
				}
			}
		}
	}
}

// GetProcessMatrix returns a slice of all active process socket mappings for the TUI Process Matrix view.
func (t *Tracker) GetProcessMatrix() []FlowProcessInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var list []FlowProcessInfo
	for _, v := range t.portMap {
		list = append(list, *v)
	}
	return list
}
