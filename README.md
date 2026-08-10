# Undertow — Terminal SOC Workstation & Go Packet Sniffer

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![Version](https://img.shields.io/badge/Release-v5.0.0--Ultimate-gold.svg)](https://github.com/Codexia-afk/Undertow)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/Codexia-afk/Undertow)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/Codexia-afk/Undertow)

> **Zero-dependency Terminal SOC Workstation & Packet Sniffer in Go with JA4+ Security & Process Correlation**

**Undertow** is a single-binary, ultra-high-performance **Terminal SOC Workstation and Network Traffic Analyzer** written in pure Go 1.22+. It captures live network packets, decodes deep layer stacks, computes **JA4+ and JA3 TLS fingerprints** without decryption, correlates network flows to local OS processes (PID, Process Name, User), detects 3-sigma behavioral anomalies and threat IOCs, renders an interactive ASCII topology graph, synthesizes local offline AI incident summaries via Ollama, and exports multi-surface reports (TUI, standalone HTML with SVGs, and SSE web streaming).

---

## Modern Wireshark & Termshark Alternative in Pure Go

Undertow is engineered from the ground up to replace bloated web tools and heavy packet inspection agents with a zero-alloc, single-binary workstation.

| Feature / Metric | **Undertow (v5.0.0)** | **Termshark** | **bandwhich** | **ntopng** | **Zeek** |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Zero-Alloc Concurrency** | ✅ Yes (`sync.Pool`) | ❌ No | ❌ No | ❌ No | ❌ No |
| **JA4+ & JA3 Fingerprinting** | ✅ Built-in | ❌ No | ❌ No | ⚠️ Plugin | ✅ Script |
| **Process-to-Socket Correlation** | ✅ Linux/macOS/Win | ❌ No | ✅ Basic | ⚠️ Agent | ❌ No |
| **Air-Gapped Threat Intel (IOC)** | ✅ Spamhaus + Custom | ❌ No | ❌ No | ⚠️ Complex | ✅ Script |
| **ASCII Topology Graph View** | ✅ Live (`tview`) | ❌ No | ❌ No | ❌ No | ❌ No |
| **Local AI Incident Summary** | ✅ Local Ollama | ❌ No | ❌ No | ❌ No | ❌ No |
| **Triple-Surface Output** | ✅ TUI / HTML / SSE | ⚠️ TUI Only | ⚠️ TUI Only | ⚠️ Web Only | ⚠️ Log Only |
| **Single Portable Binary** | ✅ 100% Standalone | ⚠️ Requires tshark | ✅ Rust binary | ❌ Complex | ❌ Enterprise |

---

## Encrypted Traffic Inspection with JA4+ and JA3 Fingerprinting

Undertow inspects raw TLS ClientHello frames (`0x16 0x03`) without decrypting payloads:
* **JA4+ Fingerprint Calculation**: Extracts protocol type (`t`), TLS version (`13`/`12`), SNI status (`d`/`i`), non-GREASE cipher count, extension count, ALPN characters (`h2`), and SHA256 truncated digests of sorted ciphers and extensions.
* **Malware Signature Lookup**: Matches generated hashes against an embedded offline lookup database (`ja4db.json`) to detect malware tools (**Cobalt Strike C2**, **LummaC2 Infostealer**, **Evilginx**, **IcedID**) and legitimate clients (**Chrome**, **curl**, **Go net/http**).

---

## Local Process-to-Socket Correlation (Linux, macOS, Windows)

Undertow maps active 5-tuple network flows (`SrcIP:SrcPort -> DstIP:DstPort`) directly to operating system processes:
* **Linux**: Correlates socket inodes from `/proc/net/tcp` and `/proc/net/udp` to `/proc/[pid]/fd/*`, executable paths in `/proc/[pid]/exe`, and user owners from `/proc/[pid]/status`.
* **Windows**: Performs `netstat -ano` / `GetExtendedTcpTable` endpoint correlation.
* **macOS**: Resolves sockets via `lsof -i -n -P` inspection.
* **Process Matrix (`HotKey: P`)**: Displays a real-time TUI panel listing `[PID] [PROCESS NAME] [USER] [EXECUTABLE PATH]`.

---

## Air-Gapped Threat Intelligence & Anomaly Detection

* **Threat IOC Engine**: Matches active traffic against embedded Spamhaus DROP CIDR blocks, exact malicious C2 IPs, and C2 domain indicators. Supports custom threat lists via `--threat-feed feeds.json`.
* **3-Sigma Adaptive Baselining**: Learns normal per-host traffic behavior using Exponential Moving Averages (EMA) and Welford running variance, persisting baseline profiles to `~/.undertow/baseline.json`.
* **Security Badging**: Marks suspicious flows in the packet stream with a bold **`[!] THREAT_ALERT`** badge.

---

## 🚀 Key Features Breakdown

### 1. ASCII Network Topology Graph View (`HotKey: g`)
Text-mode node-and-edge layout engine rendered via `tview` grouping local subnet endpoints versus remote servers, with edges styled by real-time bandwidth consumption (`────>`, `======>`, `<=====>`).

### 2. "Ask AI" Local Incident Response (`HotKey: A`)
Connects to a local Ollama LLM instance (`http://localhost:11434`, model `llama3`/`mistral`) to transform host Flow Story Narratives and Anomaly Logs into plain-English incident response summaries. Includes an offline rule synthesizer when Ollama is unreachable.

### 3. Triple-Surface Reporting Engine
1. **Live Interactive TUI**: Terminal dashboard built with `tview` using lock-free `atomic.Pointer[Snapshot]` read paths.
2. **Self-Contained HTML Report**: Exports 100% offline HTML SOC reports (`--export report.html` or `e` key) containing inline vector SVG charts.
3. **Remote Web Streaming**: Broadcasts live metrics over Server-Sent Events (`--listen :8080` with `--serve-token`) to any browser.

### 4. Session Snapshot Diffing (`undertow diff`)
CLI subcommand `undertow diff captureA.json captureB.json [--output-md diff.md]` comparing session snapshots to highlight endpoint drift, host throughput deviations (>20%), and novel fingerprints.

### 5. Headless Webhook Pipeline (`--headless` & `--webhook-url`)
Runs in headless daemon mode, streaming real-time JSON alert payloads to external HTTP POST webhooks for SIEM / Slack integration.

---

## 💻 Quick Start & Installation

### Linux (Ubuntu, Debian, Kali, Arch Linux, Fedora, Alpine, Linux Mint)

```bash
# Install prerequisites (Debian/Ubuntu/Kali/Mint)
sudo apt update && sudo apt install -y libpcap-dev build-essential git

# Clone and Build Undertow
git clone https://github.com/Codexia-afk/Undertow.git
cd Undertow
go build -o undertow ./cmd/undertow

# Grant net capture capabilities & run
sudo setcap cap_net_raw,cap_net_admin=eip ./undertow
./undertow -i eth0 -serve :8080
```

### macOS (Apple Silicon M1/M2/M3/M4 & Intel)

```bash
brew install libpcap go
git clone https://github.com/Codexia-afk/Undertow.git
cd Undertow
go build -o undertow ./cmd/undertow
sudo ./undertow -i en0 -export report.html
```

### Windows (PowerShell & Command Prompt)

```powershell
# 1. Install Npcap (WinPcap compatibility mode enabled)
# 2. Build or run Undertow
go build -o undertow.exe ./cmd/undertow

# 3. Replay offline pcap or run session diff
.\undertow.exe -replay C:\captures\sample.pcap -listen :8080
.\undertow.exe diff snapA.json snapB.json --output-md diff.md
```

---

## ⌨️ Interactive Keyboard Shortcuts Cheat Sheet

| Shortcut Key | Action / Feature View |
|:---:|:---|
| `g` / `G` | Toggle **ASCII Network Topology Graph** view |
| `P` | Open **Process Matrix** panel (PID, Process Name, User, Executable Path) |
| `A` / `a` | Trigger **Ask AI Local Incident Response** summary (Ollama) |
| `s` / `n` | View **Host Flow Story Narrative** for selected talker IP |
| `e` / `E` | Instantly export self-contained **HTML SOC Report** with vector SVGs |
| `/` | Open interactive **BPF Capture Filter** input modal |
| `p` | Pause / resume live packet stream auto-scrolling |
| `Space` | (Replay Mode) Pause / play virtual clock |
| `→` / `←` | (Replay Mode) Step 5 seconds forward / backward |
| `+` / `-` | (Replay Mode) Cycle virtual playback speed (`0.5x` → `8.0x`) |
| `Home` / `End` | (Replay Mode) Jump to start / end of recording |
| `q` / `Q` | Gracefully exit application |

---

## 📄 License

Distributed under the [MIT License](LICENSE).
