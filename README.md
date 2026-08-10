# NetWatch 🛡️ — Terminal-Native Network Traffic Analyzer & SOC Dashboard in Go

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/Codexia-afk/Undertow/pulls)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey)](https://github.com/Codexia-afk/Undertow)

**NetWatch** is a high-performance, Wireshark-inspired **terminal network packet sniffer, traffic analyzer, and security monitoring dashboard** written in pure Go. It captures live network packets off Ethernet/Wi-Fi interfaces, decodes deep protocol stacks, aggregates real-time bandwidth statistics, and renders an interactive, lock-free TUI dashboard equipped with automated security anomaly detection and human-readable session narratives.

---

## 🌟 Key Features

* 🚀 **High-Throughput Packet Engine**: Built on `google/gopacket` + `libpcap` with a lock-free multi-worker concurrency model.
* 📊 **Live TUI Dashboard**: Real-time interactive terminal UI using `tview` featuring Top Talker tables, Protocol breakdowns, Bandwidth sparklines (` ▂▃▄▅▆▇█`), and live packet feeds.
* 🛡️ **Automated Security Anomaly Heuristics**: Detects Port Scans, Large File Transfers, and Suspicious DNS Tunneling/DGA domains (Shannon entropy analysis).
* 📖 **Flow Story Narratives**: Synthesizes natural-language session summaries for any network host (e.g. *"Host A resolved api.domain.com and established a 4.2 MB HTTPS session..."*).
* 🔒 **Privacy Mode (`-redact-ips`)**: Anonymizes IP addresses on the fly for privacy-safe screen sharing and reporting.
* ⚡ **Kernel BPF Filtering**: Live interactive filter configuration (`/` key) with zero-copy BPF compilation (`port 443`, `tcp and host 10.0.0.5`).
* 🪶 **Single Binary Zero-Dependency Deployment**: Compiles down to a standalone binary for instant triage on servers and edge devices.

---

## 🏗️ Architecture & Concurrency Model

```
                    ┌─────────────────┐
                    │  Capture Engine │   (1 Goroutine: reads pcap handle,
                    │  (Producer)     │    non-blocking drop-on-full channel)
                    └────────┬────────┘
                             │ buffered channel (default: 1000)
                             ▼
                    ┌─────────────────┐
                    │  Decode Pool    │   (Worker Pool: N CPU-bound goroutines
                    │  (Workers)      │    decoding Ethernet -> IP -> TCP/UDP/DNS/HTTP)
                    └────────┬────────┘
                             │ chan model.PacketInfo
                             ▼
                    ┌─────────────────┐
                    │  Aggregator     │   (1 Goroutine: sole owner of Stats,
                    │  (Single Owner) │    publishes atomic.Pointer[Snapshot])
                    └────────┬────────┘
                             │ atomic.Pointer[Snapshot] (250ms refresh)
                             ▼
                    ┌─────────────────┐
                    │  TUI Renderer   │   (tview event loop reads Snapshot
                    │  (Consumer)     │    and repaints UI lock-free)
                    └─────────────────┘
```

---

## 📦 Prerequisites

NetWatch requires `libpcap` runtime headers to interface with kernel packet rings.

### Linux (Debian / Ubuntu / Kali / RHEL)
```bash
sudo apt-get update && sudo apt-get install -y libpcap-dev build-essential
```

### macOS (Homebrew / Xcode)
```bash
brew install libpcap
```

---

## ⚡ Quick Start & Installation

```bash
# 1. Clone the repository
git clone https://github.com/Codexia-afk/Undertow.git
cd Undertow

# 2. Build the binary
go build -o netwatch ./cmd/netwatch

# 3. Run live dashboard (requires root permissions for network capture)
sudo ./netwatch -i eth0
```

### Run without `sudo` (Linux Capabilities)
```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./netwatch
./netwatch -i eth0
```

---

## ⌨️ Interactive Keybindings

| Key | Description |
|:---:|:---|
| `q` / `Q` | Gracefully quit application |
| `p` / `P` | Pause / resume live packet stream auto-scrolling |
| `/` | Open BPF capture filter input overlay |
| `s` / `n` | View Flow Story narrative for selected host |
| `Mouse` / `Arrows` | Select rows in Top Talkers table |

---

## ⚙️ Command-Line Reference

```text
Usage: netwatch -i <interface> [flags]

Flags:
  -i string
        Network interface to capture on (required, e.g. eth0, wlan0, en0)
  -filter string
        Initial BPF capture filter (e.g. 'port 80', 'tcp and host 10.0.0.5')
  -workers int
        Number of parallel decoding worker goroutines (default: NumCPU)
  -bufsize int
        Packet channel buffer size (default: 1000)
  -redact-ips
        Anonymize IP addresses in narratives for privacy
  -scan-threshold int
        Distinct destination ports threshold for port scan alert (default: 15)
  -transfer-threshold-mb uint
        Flow transfer threshold in MB for large transfer alert (default: 50)
  -dns-entropy-threshold float
        Shannon entropy threshold for suspicious DNS alert (default: 3.5)
  -no-tui
        Disable TUI and output periodic stats summary to stdout
```

---

## 🧪 Running Unit Tests

```bash
# Run unit tests with Go race detector
make test
# OR manually:
go test -race -v ./internal/...
```

---

## 📄 License

This project is open-source under the [MIT License](LICENSE).
