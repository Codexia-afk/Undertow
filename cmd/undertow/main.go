package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket/pcap"

	"github.com/Codexia-afk/Undertow/internal/aggregator"
	"github.com/Codexia-afk/Undertow/internal/anomaly"
	"github.com/Codexia-afk/Undertow/internal/baseline"
	"github.com/Codexia-afk/Undertow/internal/capture"
	"github.com/Codexia-afk/Undertow/internal/decode"
	"github.com/Codexia-afk/Undertow/internal/diff"
	"github.com/Codexia-afk/Undertow/internal/filter"
	"github.com/Codexia-afk/Undertow/internal/remote"
	"github.com/Codexia-afk/Undertow/internal/replay"
	"github.com/Codexia-afk/Undertow/internal/report"
	"github.com/Codexia-afk/Undertow/internal/security"
	"github.com/Codexia-afk/Undertow/internal/ui"
)

func listInterfaces() {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding devices: %v\n", err)
		return
	}
	fmt.Println("Available interfaces:")
	for _, dev := range devs {
		var addrs []string
		for _, a := range dev.Addresses {
			addrs = append(addrs, a.IP.String())
		}
		fmt.Printf("- %s (%s)\n", dev.Name, strings.Join(addrs, ", "))
	}
}

func handleDiffSubcommand() bool {
	if len(os.Args) >= 4 && (os.Args[1] == "diff" || os.Args[1] == "--diff") {
		fileA := os.Args[2]
		fileB := os.Args[3]

		outputMD := ""
		for i, arg := range os.Args {
			if (arg == "--output-md" || arg == "-output-md") && i+1 < len(os.Args) {
				outputMD = os.Args[i+1]
			}
		}

		res, summary, err := diff.CompareSnapshots(fileA, fileB)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Diff Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(summary)

		if outputMD != "" {
			mdContent := fmt.Sprintf("# Undertow Session Snapshot Diff Report\n\n```text\n%s\n```\n", summary)
			if err := os.WriteFile(outputMD, []byte(mdContent), 0644); err == nil {
				fmt.Printf("Wrote diff report to Markdown file: %s\n", outputMD)
			}
		}

		_ = res
		os.Exit(0)
		return true
	}
	return false
}

func main() {
	if handleDiffSubcommand() {
		return
	}

	iface := flag.String("i", "", "Network interface to capture on (required for live mode)")
	snaplen := flag.Int("snaplen", 65535, "Snap length for packet capture")
	promisc := flag.Bool("promisc", true, "Set promiscuous mode")
	timeoutSec := flag.Int("timeout", 1, "Read timeout in seconds")
	workers := flag.Int("workers", runtime.NumCPU(), "Number of decode worker goroutines")
	bufsize := flag.Int("bufsize", 1000, "Packet buffer channel size")
	filterExpr := flag.String("filter", "", "Initial BPF capture filter (e.g. 'port 80', 'tcp and host 10.0.0.5')")
	noTUI := flag.Bool("no-tui", false, "Disable TUI dashboard and print summary stream to stdout")
	headless := flag.Bool("headless", false, "Bypass TUI dashboard entirely and operate in headless daemon mode")
	webhookURL := flag.String("webhook-url", "", "HTTP POST webhook endpoint for real-time security anomaly JSON alerts")
	scanThreshold := flag.Int("scan-threshold", 15, "Distinct destination ports per source IP threshold for port scan alert")
	transferThresholdMB := flag.Uint64("transfer-threshold-mb", 50, "Flow bytes threshold in MB for large transfer alert")
	dnsEntropyThreshold := flag.Float64("dns-entropy-threshold", 3.5, "Shannon entropy threshold for suspicious DNS alert")
	redactIPs := flag.Bool("redact-ips", false, "Anonymize/redact IP addresses in narrative summaries for privacy")
	baselineWarmup := flag.Int("baseline-warmup", 60, "Warm-up duration in seconds for adaptive behavioral baselining")
	baselineFile := flag.String("baseline-file", "", "File path to persist host behavioral baselining state")
	recordFile := flag.String("record", "", "Record captured live packets to a .pcap file on disk")
	replayFile := flag.String("replay", "", "Replay a recorded .pcap file with virtual clock DVR controls")
	exportHTML := flag.String("export-html", "", "Export session metrics to a self-contained HTML report file on exit")
	exportFlag := flag.String("export", "", "Export session metrics to a self-contained HTML report file on exit")
	serveAddr := flag.String("serve", "", "Start HTTP broadcast server for remote read-only web monitoring (e.g. ':8080')")
	listenAddr := flag.String("listen", "", "Start HTTP broadcast server for remote read-only web monitoring (e.g. ':8080')")
	serveToken := flag.String("serve-token", "", "Optional secret authentication token for remote broadcast server")
	threatFeedFile := flag.String("threat-feed", "", "Path to custom local threat intelligence feed JSON file")
	flag.Parse()

	if *exportFlag != "" && *exportHTML == "" {
		exportHTML = exportFlag
	}
	if *listenAddr != "" && *serveAddr == "" {
		serveAddr = listenAddr
	}

	isHeadlessMode := *noTUI || *headless

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()

	if *threatFeedFile != "" {
		engine := security.NewEngine()
		if err := engine.LoadCustomFeed(*threatFeedFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading custom threat feed %s: %v\n", *threatFeedFile, err)
		} else {
			decode.SetThreatEngine(engine)
			fmt.Printf("Loaded custom threat feed from %s\n", *threatFeedFile)
		}
	}

	anomalyCfg := anomaly.Config{
		ScanThreshold:       *scanThreshold,
		ScanWindowSec:       10,
		TransferThresholdMB: *transferThresholdMB,
		DNSEntropyThreshold: *dnsEntropyThreshold,
	}

	baselineCfg := baseline.DefaultConfig()
	baselineCfg.WarmupSec = *baselineWarmup
	if *baselineFile != "" {
		baselineCfg.FilePath = *baselineFile
	}

	// Mode 1: Replay Mode
	if *replayFile != "" {
		replayEngine, packetInfoChan, err := replay.NewReplayEngine(*replayFile, *bufsize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening replay file: %v\n", err)
			os.Exit(1)
		}

		statsManager := aggregator.NewStatsManager(60, 200, 100, nil, anomalyCfg, baselineCfg, *webhookURL)
		agg := aggregator.NewAggregator(packetInfoChan, statsManager)

		if *serveAddr != "" {
			srv := remote.NewServer(*serveAddr, *serveToken, statsManager)
			go func() { _ = srv.Start(ctx) }()
		}

		go replayEngine.Run(ctx)
		go agg.Run(ctx)

		if isHeadlessMode {
			fmt.Printf("Replaying %s (Headless)... Press Ctrl+C to stop.\n", *replayFile)
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					snap := statsManager.GetSnapshot()
					fmt.Printf("[REPLAY HEADLESS] %d pkts | %d bytes\n", snap.TotalPackets, snap.TotalBytes)
				}
			}
		} else {
			dashboard := ui.NewDashboard("REPLAY", statsManager, *filterExpr, nil, *redactIPs, replayEngine)
			if err := dashboard.Run(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "Dashboard error: %v\n", err)
			}
		}
		return
	}

	// Mode 2: Live Capture Mode
	if *iface == "" {
		fmt.Println("Interface not specified.")
		listInterfaces()
		os.Exit(1)
	}

	handle, err := pcap.OpenLive(*iface, int32(*snaplen), *promisc, time.Duration(*timeoutSec)*time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "permission denied") {
			fmt.Fprintf(os.Stderr, "Permission error opening interface %s: %v\n", *iface, err)
			fmt.Fprintln(os.Stderr, "You may need to run as root or grant capabilities, e.g.:\n  sudo setcap cap_net_raw,cap_net_admin=eip $(which undertow)")
		} else {
			fmt.Fprintf(os.Stderr, "Error opening interface %s: %v\n", *iface, err)
		}
		os.Exit(1)
	}
	defer handle.Close()

	if *filterExpr != "" {
		if err := filter.ApplyBPFFilter(handle, *filterExpr); err != nil {
			fmt.Fprintf(os.Stderr, "Error applying BPF filter: %v\n", err)
			os.Exit(1)
		}
	}

	var recorder *replay.Recorder
	if *recordFile != "" {
		rec, err := replay.NewRecorder(*recordFile, uint32(*snaplen), handle.LinkType())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening record file %s: %v\n", *recordFile, err)
			os.Exit(1)
		}
		recorder = rec
		defer recorder.Close()
		fmt.Printf("Recording live traffic to %s ...\n", *recordFile)
	}

	engine := capture.NewEngine(handle, *bufsize, recorder)
	pool, packetInfoChan := decode.NewWorkerPool(*workers, *bufsize, engine.PacketChan())
	statsManager := aggregator.NewStatsManager(60, 200, 100, engine.DroppedCountPointer(), anomalyCfg, baselineCfg, *webhookURL)
	agg := aggregator.NewAggregator(packetInfoChan, statsManager)

	if *serveAddr != "" {
		srv := remote.NewServer(*serveAddr, *serveToken, statsManager)
		go func() { _ = srv.Start(ctx) }()
	}

	go engine.Run(ctx)
	go pool.Run(ctx)
	go agg.Run(ctx)

	applyFilterCallback := func(expr string) error {
		return filter.ApplyBPFFilter(handle, expr)
	}

	if isHeadlessMode {
		fmt.Printf("Undertow Headless Engine on %s (%d workers)... Press Ctrl+C to stop.\n", *iface, *workers)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				if *exportHTML != "" {
					snap := statsManager.GetSnapshot()
					_ = report.GenerateHTMLReport(snap, *iface, *filterExpr, *redactIPs, *exportHTML)
					fmt.Printf("Exported HTML Report to %s\n", *exportHTML)
				}
				return
			case <-ticker.C:
				snap := statsManager.GetSnapshot()
				fmt.Printf("[HEADLESS STATS] %d pkts | %d bytes | dropped: %d\n", snap.TotalPackets, snap.TotalBytes, snap.DroppedPackets)
			}
		}
	} else {
		dashboard := ui.NewDashboard(*iface, statsManager, *filterExpr, applyFilterCallback, *redactIPs, nil)
		if err := dashboard.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Dashboard error: %v\n", err)
		}
		if *exportHTML != "" {
			snap := statsManager.GetSnapshot()
			_ = report.GenerateHTMLReport(snap, *iface, *filterExpr, *redactIPs, *exportHTML)
			fmt.Printf("Exported HTML Report to %s\n", *exportHTML)
		}
	}
}
