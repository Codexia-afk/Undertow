# NetWatch 🛡️

> A Wireshark-inspired, terminal-native network traffic analyzer written in Go. Captures live packets off a network interface, decodes protocol layers, aggregates real-time statistics, and renders a live TUI dashboard with anomaly detection.

---

## 🏗️ Architecture

```
                    ┌─────────────────┐
                    │  Capture Layer  │   (1 goroutine: reads pcap.Handle,
                    │  (Producer)     │    non-blocking send -> buffered channel)
                    └────────┬────────┘
                             │ buffered channel (default: 1000)
                             ▼
                    ┌─────────────────┐
                    │  Decode Pool    │   (Worker Pool: N goroutines decode layers
                    │                 │    into normalized PacketInfo structs)
                    └────────┬────────┘
                             │ chan PacketInfo
                             ▼
                    ┌─────────────────┐
                    │  Aggregator     │   (1 goroutine: sole owner of Stats state,
                    │  (Single Owner) │    publishes atomic.Pointer[Snapshot])
                    └────────┬────────┘
                             │ atomic.Pointer[Snapshot] (250ms interval)
                             ▼
                    ┌─────────────────┐
                    │  TUI Renderer   │   (tview event loop reads Snapshot
                    │  (Consumer)     │    and repaints widgets)
                    └─────────────────┘
```

---

## 📋 System Prerequisites

Before building NetWatch, `libpcap` development libraries must be installed on your system:

### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev build-essential
```

### macOS
```bash
# Installed automatically via Xcode CLI Tools or Homebrew:
brew install libpcap
```

---

## 🚀 Building & Installation

```bash
# Clone repository
git clone https://github.com/Codexia-afk/Undertow.git
cd Undertow

# Download dependencies & build
go build -o netwatch ./cmd/netwatch
```

### Running without `sudo` (Linux Capabilities)
Instead of running as root with `sudo`, grant raw socket access to the binary:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./netwatch
./netwatch -i eth0
```

---

## ⚡ Usage Examples

### 1. Basic Interactive TUI
```bash
sudo ./netwatch -i eth0
```

### 2. Capture with BPF Kernel Filter
```bash
sudo ./netwatch -i eth0 -filter "port 443"
```

### 3. Custom Anomaly Thresholds & Worker Tuning
```bash
sudo ./netwatch -i eth0 -workers 8 -scan-threshold 10 -transfer-threshold-mb 100
```

---

## ⌨️ Dashboard Keybindings

| Key | Action |
|-----|--------|
| `q` | Quit application gracefully |
| `p` | Toggle pause/resume packet log stream |
| `/` | Open interactive BPF filter input overlay |
| `Mouse / Arrows` | Navigate rows in the Top Talkers table |

---

## ⚙️ CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-i` | `""` | Network interface to capture on (**required**) |
| `-filter` | `""` | Initial BPF capture filter (e.g. `'port 80'`, `'tcp and host 10.0.0.5'`) |
| `-snaplen` | `65535` | Snap length for packet capture |
| `-promisc` | `true` | Enable promiscuous mode |
| `-timeout` | `1` | Read timeout in seconds |
| `-workers` | `NumCPU()` | Number of parallel decoding worker goroutines |
| `-bufsize` | `1000` | Packet channel buffer size (drop-on-full backpressure) |
| `-scan-threshold` | `15` | Distinct destination ports per source IP threshold for port scan alert |
| `-transfer-threshold-mb` | `50` | Flow transfer byte threshold in MB for large transfer alert |
| `-dns-entropy-threshold` | `3.5` | Shannon entropy threshold for suspicious DNS domain alert |
| `-no-tui` | `false` | Disable TUI dashboard and output summary stream to stdout |
