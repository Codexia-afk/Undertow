# Changelog

All notable changes to **Undertow** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [5.0.0] - 2026-08-10

### 🚀 Added
- **JA4 & JA4S TLS Fingerprinting Engine (`internal/decode/ja4.go`)**:
  - Raw TLS ClientHello inspection parsing protocol, TLS version, SNI status, ALPN, cipher counts, and extension counts.
  - Generates canonical JA4+ fingerprint strings (e.g. `t13d1516h2_8daaf6152771_02713d6af862`).
  - Embedded offline lookup database (`ja4db.json`) identifying malware tools (Cobalt Strike C2, LummaC2, Evilginx, IcedID) and client software.
- **Deep Process-to-Socket Correlation (`internal/process/tracker.go`)**:
  - Correlates active 5-tuple network flows to OS process PIDs, process names, executable paths, and user owners across Linux (`/proc/net/*`), Windows (`netstat`), and macOS (`lsof`).
  - Interactive TUI **Process Matrix** panel (`HotKey: P`).
- **Air-Gapped Threat Intelligence IOC Engine (`internal/security/threat.go`)**:
  - Embedded Spamhaus DROP CIDR blocks, exact malicious C2 IPs, and C2 domain indicators.
  - Support for custom threat feeds via `--threat-feed feeds.json` CLI flag.
  - Bold `[!] THREAT_ALERT` badge rendering on malicious packet stream lines.
- **ASCII Network Topology Graph View (`internal/ui/views/topology.go`)**:
  - Text-mode ASCII/Unicode node-and-edge layout engine grouping local subnets vs. remote servers with dynamic edge intensity indicators (`────>`, `<=====>`, `HotKey: g`).
- **"Ask AI" Local Incident Response (`internal/ai/ollama.go`)**:
  - Local Ollama LLM integration (`http://localhost:11434`, `llama3`/`mistral`) synthesizing plain-English incident summaries from host flow stories (`HotKey: A`).
  - Zero-dependency offline fallback rule synthesizer when Ollama is unreachable.
- **Triple-Surface Reporting Engine (`internal/report/triple_surface_test.go`)**:
  - 3 concurrent output surfaces: Live TUI (`tview`), Standalone HTML Export (`--export report.html` with vector SVGs), and Remote Web Broadcast (`--listen :8080` via SSE).
- **Session Snapshot Diffing Subcommand (`undertow diff`)**:
  - CLI subcommand comparing session JSON snapshots to highlight endpoint drift, host throughput deviations (>20%), and Markdown output (`--output-md`).
- **Headless Webhook Execution Pipeline (`--headless` & `--webhook-url`)**:
  - Headless daemon mode bypassing TUI, posting JSON alert payloads to external HTTP webhooks.

### 🔄 Changed
- Renamed project from NetWatch to **Undertow** across all module definitions (`github.com/Codexia-afk/Undertow`), flags, binary targets, and documentation.
- Updated baseline persistence file path to `~/.undertow/baseline.json`.

### ⚡ Performance & Security
- **Zero-Alloc Concurrency Core**: Implemented `sync.Pool` packet buffer reuse to handle 10Gbps+ throughput bursts without Garbage Collector pauses.
- **Single-Owner Aggregator Pattern**: Single aggregator goroutine owning stats maps with lock-free `atomic.Pointer[Snapshot]` read paths.
- Verified zero data race conditions across all unit test suites (`go test -race ./...`).
