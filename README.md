# NetWatch 🛡️ — Ultimate Network Traffic Analyzer & SOC Intelligence Platform

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![Version](https://img.shields.io/badge/Release-v3.0.0--Ultimate-gold.svg)](https://github.com/Codexia-afk/Undertow)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/Codexia-afk/Undertow/pulls)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/Codexia-afk/Undertow)

**NetWatch** is a high-performance, Wireshark-inspired **terminal network packet sniffer, protocol decoder, behavioral anomaly detector, and broadcast dashboard** written in pure Go. It captures live network packets off network interfaces, decodes deep layer stacks (including JA3 TLS fingerprinting without decryption), aggregates real-time bandwidth statistics, and renders an interactive, lock-free TUI dashboard equipped with automated security anomaly detection, host session stories, time-travel DVR replay, self-contained HTML export, and remote web streaming.

---

## 🌟 God-Tier Feature Matrix (Milestones 1–12 Complete)

* 🚀 **Multi-Core Parallel Decoder**: `google/gopacket` + `libpcap` wrapper with a multi-worker pool architecture and drop-on-full backpressure.
* 📊 **Interactive TUI Dashboard**: Live `tview` terminal dashboard with Top Talkers table, Protocol breakdown, Bandwidth sparkline (` ▂▃▄▅▆▇█`), and live packet log.
* 🛡️ **Rule-Based & Adaptive Anomaly Heuristics**: Detects Port Scans, Large File Transfers, Suspicious DGA/Tunneling DNS domains (Shannon entropy), and 3-Sigma Behavioral Deviations.
* 📈 **Adaptive Behavioral Baselining**: Learns per-host normal behavior (EMA + Welford variance tracking) and persists baseline profiles to `~/.netwatch/baseline.json`.
* 📖 **Flow Story Narratives**: Synthesizes natural-language session summaries for any network host with optional IP privacy redaction (`-redact-ips`).
* ⏩ **Time-Travel Replay Mode (DVR)**: Record live traffic to `.pcap` (`-record`) and replay recorded pcaps (`-replay`) with virtual clock controls (`Space`, `←`/`→`, `+`/`-`, `Home`/`End`).
* 🔑 **JA3/JA3S TLS Fingerprinting**: Identifies client applications (`curl`, `Chrome`, `Go net/http`, `Python`) from unencrypted ClientHello headers without TLS decryption.
* 📄 **Self-Contained HTML Reports**: Export 100% offline, zero-dependency HTML SOC reports (`-export-html` or `e` key) containing inline SVG vector charts.
* 🌐 **Remote Broadcast Mode**: Broadcast read-only live metrics over Server-Sent Events (`-serve :8080` with `-serve-token`) to any browser or mobile device.

---

## 🏗️ System Architecture

```
                    ┌─────────────────┐
                    │  Capture Engine │   (1 Goroutine: reads pcap handle,
                    │  (Producer)     │    non-blocking drop-on-full channel)
                    └────────┬────────┘
                             │ buffered channel (default: 1000)
                             ▼
                    ┌─────────────────┐
                    │  Decode Pool    │   (Worker Pool: N CPU-bound goroutines
                    │  (Workers)      │    decodes Ethernet -> IP -> TCP/UDP/DNS/HTTP/TLS)
                    └────────┬────────┘
                             │ chan model.PacketInfo
                             ▼
                    ┌─────────────────┐
                    │  Aggregator     │   (1 Goroutine: sole owner of Stats,
                    │  (Single Owner) │    publishes atomic.Pointer[Snapshot])
                    └────────┬────────┘
                             │ atomic.Pointer[Snapshot] (250ms refresh)
                             ├─────────────────────────┬─────────────────────────┐
                             ▼                         ▼                         ▼
                    ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
                    │  TUI Dashboard  │       │  HTML Exporter  │       │  Remote Server  │
                    │  (tview)        │       │  (inline SVG)   │       │  (SSE / :8080)  │
                    └─────────────────┘       └─────────────────┘       └─────────────────┘
```

---

## 🖥️ Cross-Platform Installation & Verification

### 1️⃣ Linux (Ubuntu, Debian, Kali, Arch Linux, Fedora, Alpine, Linux Mint)

#### Ubuntu / Debian / Linux Mint
```bash
sudo apt update && sudo apt install -y libpcap-dev build-essential git
go build -o netwatch ./cmd/netwatch
sudo ./netwatch -i eth0
```

#### Kali Linux
```bash
sudo apt update && sudo apt install -y libpcap-dev
go build -o netwatch ./cmd/netwatch
sudo ./netwatch -i wlan0 -filter "port 80 or port 443" -record kali.pcap
```

#### Arch Linux / Manjaro
```bash
sudo pacman -Syu --needed libpcap go base-devel
go build -o netwatch ./cmd/netwatch
sudo ./netwatch -i eth0
```

#### Fedora / RHEL
```bash
sudo dnf install -y libpcap-devel gcc
go build -o netwatch ./cmd/netwatch
sudo ./netwatch -i eth0
```

#### Alpine Linux
```bash
apk add --no-cache libpcap-dev build-base go git
go build -o netwatch ./cmd/netwatch
sudo ./netwatch -i eth0
```

### 2️⃣ macOS (Apple Silicon M1/M2/M3/M4 & Intel)

```bash
brew install libpcap go
go build -o netwatch ./cmd/netwatch
sudo ./netwatch -i en0 -record macos_capture.pcap
```

### 3️⃣ Windows (PowerShell & Command Prompt)

```powershell
# Run all unit tests
go test -v ./internal/...

# Replay any standard .pcap file in offline DVR mode (no admin privileges required!)
.\netwatch.exe -replay C:\captures\sample.pcap -serve :8080
```

---

## ⌨️ TUI Keyboard Controls

| Key | Action |
|:---:|:---|
| `q` / `Q` | Gracefully quit application |
| `p` / `P` | Pause / resume live packet stream auto-scrolling |
| `/` | Open interactive BPF capture filter input overlay |
| `s` / `n` | View Flow Story narrative for selected host |
| `e` / `E` | Instantly export self-contained HTML SOC report |
| `Space` | (Replay Mode) Play / Pause virtual clock |
| `→` / `←` | (Replay Mode) Step 5s forward / backward |
| `+` / `-` | (Replay Mode) Cycle playback speed multiplier (`0.5x` → `8.0x`) |
| `Home` / `End` | (Replay Mode) Jump to start / end of recording |

---

## ⚙️ Complete Command-Line Options

```text
Flags:
  -i string
        Network interface to capture on (required for live capture)
  -filter string
        Initial BPF capture filter (e.g. 'port 80', 'tcp and host 10.0.0.5')
  -workers int
        Number of parallel decoding worker goroutines (default: NumCPU)
  -bufsize int
        Packet channel buffer size (default: 1000)
  -redact-ips
        Anonymize IP addresses in narrative summaries for privacy
  -record string
        Record captured live traffic to a .pcap file on disk
  -replay string
        Replay a recorded .pcap file with virtual clock DVR controls
  -export-html string
        Export session metrics to a self-contained HTML report file on exit
  -serve string
        Start HTTP broadcast server for remote read-only web monitoring (e.g. ':8080')
  -serve-token string
        Optional secret authentication token for remote broadcast server
  -scan-threshold int
        Distinct destination ports threshold for port scan alert (default: 15)
  -transfer-threshold-mb uint
        Flow transfer threshold in MB for large transfer alert (default: 50)
  -dns-entropy-threshold float
        Shannon entropy threshold for suspicious DNS alert (default: 3.5)
  -baseline-warmup int
        Warm-up duration in seconds for adaptive behavioral baselining (default: 60)
  -baseline-file string
        File path to persist host behavioral baselining state
  -no-tui
        Disable TUI dashboard and print summary stream to stdout
```

---

## 🧪 Testing

```bash
make test
# OR
go test -race -v ./internal/...
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
