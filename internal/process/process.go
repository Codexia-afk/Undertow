package process

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcessInfo holds process identification linked to a network socket.
type ProcessInfo struct {
	PID         int
	Name        string
	Path        string
	LocalPort   uint16
	RemotePort  uint16
	Protocol    string
	LastUpdated time.Time
}

// Resolver periodically correlates active network sockets to local process PIDs and executable names.
type Resolver struct {
	mu         sync.RWMutex
	socketMap  map[string]ProcessInfo // Key: "IP:Port" or "Port" -> ProcessInfo
	lastLookup time.Time
}

// NewResolver constructs a new socket-to-process resolver.
func NewResolver() *Resolver {
	r := &Resolver{
		socketMap: make(map[string]ProcessInfo),
	}
	r.Refresh()
	return r
}

// Lookup attempts to resolve PID and process name for a given port or endpoint string.
func (r *Resolver) Lookup(port uint16) (int, string, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := fmt.Sprintf("%d", port)
	if info, found := r.socketMap[key]; found {
		return info.PID, info.Name, info.Path
	}
	return 0, "Unknown", ""
}

// Refresh updates the internal socket-to-process map using OS-specific inspection mechanisms.
func (r *Resolver) Refresh() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Rate limit system calls/parsing to at most once per 2 seconds
	if time.Since(r.lastLookup) < 2*time.Second && len(r.socketMap) > 0 {
		return
	}
	r.lastLookup = time.Now()

	switch runtime.GOOS {
	case "linux":
		r.refreshLinux()
	case "windows":
		r.refreshWindows()
	case "darwin":
		r.refreshMacOS()
	default:
		r.refreshFallback()
	}
}

// refreshLinux parses /proc/net/tcp, /proc/net/udp and correlates socket inodes to /proc/[pid]/fd/*
func (r *Resolver) refreshLinux() {
	inodes := make(map[string]string) // inode -> "IP:Port"

	parseProcNet := func(filePath, proto string) {
		f, err := os.Open(filePath)
		if err != nil {
			return
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header line
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}
			localAddrHex := fields[1]
			inode := fields[9]

			parts := strings.Split(localAddrHex, ":")
			if len(parts) == 2 {
				portHex := parts[1]
				if p, err := strconv.ParseUint(portHex, 16, 16); err == nil {
					inodes[inode] = fmt.Sprintf("%d", p)
				}
			}
		}
	}

	parseProcNet("/proc/net/tcp", "TCP")
	parseProcNet("/proc/net/udp", "UDP")

	// Walk /proc/[pid]/fd/*
	files, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	for _, file := range files {
		if !file.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(file.Name())
		if err != nil {
			continue
		}

		// Read process name
		commBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		procName := strings.TrimSpace(string(commBytes))
		if procName == "" {
			procName = fmt.Sprintf("PID_%d", pid)
		}

		exePath, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))

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
				if portKey, found := inodes[inode]; found {
					r.socketMap[portKey] = ProcessInfo{
						PID:         pid,
						Name:        procName,
						Path:        exePath,
						LastUpdated: time.Now(),
					}
				}
			}
		}
	}
}

// refreshWindows uses netstat / powershell inspect fallback
func (r *Resolver) refreshWindows() {
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
					key := fmt.Sprintf("%d", p)
					r.socketMap[key] = ProcessInfo{
						PID:         pid,
						Name:        fmt.Sprintf("Process_%d", pid),
						Path:        "",
						LastUpdated: time.Now(),
					}
				}
			}
		}
	}
}

// refreshMacOS uses lsof invocation
func (r *Resolver) refreshMacOS() {
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
			addrInfo := fields[8]

			parts := strings.Split(addrInfo, ":")
			if len(parts) >= 2 {
				portStr := strings.Split(parts[len(parts)-1], "->")[0]
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
					key := fmt.Sprintf("%d", p)
					r.socketMap[key] = ProcessInfo{
						PID:         pid,
						Name:        procName,
						LastUpdated: time.Now(),
					}
				}
			}
		}
	}
}

func (r *Resolver) refreshFallback() {
	// Fallback placeholder
}

// GetAllProcesses returns snapshot of resolved socket process mappings.
func (r *Resolver) GetAllProcesses() []ProcessInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []ProcessInfo
	for _, v := range r.socketMap {
		result = append(result, v)
	}
	return result
}
