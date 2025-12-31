package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Zerofisher/pktanalyzer/agent"
	"github.com/Zerofisher/pktanalyzer/agent/llm"
	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/expert"
	"github.com/Zerofisher/pktanalyzer/export"
	"github.com/Zerofisher/pktanalyzer/fields"
	"github.com/Zerofisher/pktanalyzer/filter"
	"github.com/Zerofisher/pktanalyzer/stats"
	"github.com/Zerofisher/pktanalyzer/stream"
	"github.com/Zerofisher/pktanalyzer/tls"
	"github.com/Zerofisher/pktanalyzer/ui"
)

// arrayFlags allows multiple -e flags
type arrayFlags []string

func (a *arrayFlags) String() string {
	return strings.Join(*a, ",")
}

func (a *arrayFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}

func main() {
	// Command line flags
	iface := flag.String("i", "", "Network interface for live capture")
	file := flag.String("r", "", "Read packets from pcap/pcapng file")
	bpfFilter := flag.String("f", "", "BPF filter expression (capture filter)")
	displayFilter := flag.String("Y", "", "Display filter expression (like Wireshark)")
	keyLogFile := flag.String("k", "", "SSLKEYLOGFILE for TLS decryption")
	enableStreams := flag.Bool("S", false, "Enable TCP stream reassembly")
	enableAI := flag.Bool("A", false, "Enable AI assistant (requires ANTHROPIC_API_KEY or OPENAI_API_KEY)")
	listIfaces := flag.Bool("D", false, "List available network interfaces")

	// CLI output options (tshark-compatible)
	outputFormat := flag.String("T", "", "Output format: text, json, fields (enables CLI mode)")
	outputFile := flag.String("w", "", "Write packets to pcapng file")
	maxCount := flag.Int("c", 0, "Stop after n packets (0 = unlimited)")
	showDetail := flag.Bool("V", false, "Show packet details (verbose)")
	showHex := flag.Bool("x", false, "Show hex dump")

	// Field extraction
	var extractFields arrayFlags
	flag.Var(&extractFields, "e", "Field to extract (can be specified multiple times, use with -T fields)")

	// Field listing
	listFields := flag.Bool("G", false, "List available fields (use with 'fields' argument)")

	// Statistics (tshark -z compatible)
	statsOption := flag.String("z", "", "Statistics: endpoints, conv,tcp, conv,udp, io,stat,<interval>, follow,tcp,ascii,<stream>, expert")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "PktAnalyzer - Network Packet Analyzer with TLS Decryption and AI\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s -i <interface> [-f <filter>] [-k <keylog>] [-S] [-A]   Live capture (TUI)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -i <interface> -w <file>                               Live capture to file\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r <file> [-f <filter>] [-k <keylog>] [-S] [-A]        Read pcap file (TUI)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r <file> -w <outfile> [-Y filter]                     Filter and save to file\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r <file> -T text [-c n] [-Y filter]                   CLI text output\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r <file> -T json [-c n] [-Y filter]                   CLI JSON output\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r <file> -T fields -e <field> [-e <field>...]         Field extraction\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r <file> -z endpoints                                 Endpoint statistics\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r <file> -z conv,tcp                                  TCP conversations\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r <file> -z io,stat,1                                 I/O statistics (1s interval)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r <file> -S -z follow,tcp,ascii,1                     Follow TCP stream #1\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r <file> -z expert                                    Expert analysis (anomaly detection)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -D                                                     List interfaces\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -G fields                                              List available fields\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nDisplay Filter (-Y) Examples:\n")
		fmt.Fprintf(os.Stderr, "  tcp.dstport == 443                  TCP packets to port 443\n")
		fmt.Fprintf(os.Stderr, "  ip.src == \"192.168.1.1\"             Packets from specific IP\n")
		fmt.Fprintf(os.Stderr, "  dns.qry.name contains \"google\"      DNS queries containing google\n")
		fmt.Fprintf(os.Stderr, "  tcp and not tcp.dstport == 22       TCP but not SSH\n")
		fmt.Fprintf(os.Stderr, "  frame.len > 1000                    Large packets\n")
		fmt.Fprintf(os.Stderr, "\nTLS Decryption:\n")
		fmt.Fprintf(os.Stderr, "  To decrypt HTTPS traffic, export TLS keys using SSLKEYLOGFILE:\n")
		fmt.Fprintf(os.Stderr, "    export SSLKEYLOGFILE=~/sslkeys.log\n")
		fmt.Fprintf(os.Stderr, "    /Applications/Google\\ Chrome.app/Contents/MacOS/Google\\ Chrome\n")
		fmt.Fprintf(os.Stderr, "  Then use -k flag to specify the key log file.\n")
		fmt.Fprintf(os.Stderr, "\nTCP Stream Reassembly:\n")
		fmt.Fprintf(os.Stderr, "  Use -S flag to enable TCP stream tracking and reassembly.\n")
		fmt.Fprintf(os.Stderr, "  Press 's' in TUI to view TCP streams and reassembled data.\n")
		fmt.Fprintf(os.Stderr, "\nAI Assistant:\n")
		fmt.Fprintf(os.Stderr, "  Use -A flag to enable AI-powered packet analysis.\n")
		fmt.Fprintf(os.Stderr, "  Requires ANTHROPIC_API_KEY (Claude) or OPENAI_API_KEY environment variable.\n")
		fmt.Fprintf(os.Stderr, "  Press 'a' in TUI to open AI chat, 'i' to input, Tab for split view.\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  sudo %s -i en0                                   Capture on en0 (TUI)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r capture.pcapng -T text -c 10               First 10 packets as text\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r capture.pcapng -T json -Y 'tcp.dstport == 443' -c 5   JSON filtered\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r capture.pcapng -T fields -e frame.number -e ip.src -e ip.dst\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r capture.pcapng -V -c 1                     Detailed first packet\n", os.Args[0])
	}

	flag.Parse()

	// Handle -G fields
	if *listFields {
		args := flag.Args()
		if len(args) > 0 && args[0] == "fields" {
			listAvailableFields()
			return
		}
		fmt.Fprintf(os.Stderr, "Usage: %s -G fields\n", os.Args[0])
		os.Exit(1)
	}

	// List interfaces
	if *listIfaces {
		ifaces, err := capture.ListInterfaces()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing interfaces: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Available network interfaces:")
		fmt.Println(strings.Repeat("-", 60))
		for i, iface := range ifaces {
			fmt.Printf("%d. %s\n", i+1, iface.Name)
			if iface.Description != "" {
				fmt.Printf("   Description: %s\n", iface.Description)
			}
			for _, addr := range iface.Addresses {
				fmt.Printf("   Address: %s\n", addr.IP)
			}
			fmt.Println()
		}
		return
	}

	// Validate input
	if *iface == "" && *file == "" {
		fmt.Fprintf(os.Stderr, "Error: Must specify either -i (interface) or -r (file)\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if *iface != "" && *file != "" {
		fmt.Fprintf(os.Stderr, "Error: Cannot specify both -i and -r\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Determine if CLI mode (non-interactive output)
	cliMode := *outputFormat != "" || *showDetail || *showHex || *statsOption != "" || *outputFile != ""

	// Load TLS key log if specified
	var tlsDecryptor *tls.Decryptor
	if *keyLogFile != "" {
		keyLog, err := tls.LoadKeyLogFile(*keyLogFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to load key log file: %v\n", err)
		} else {
			tlsDecryptor = tls.NewDecryptor(keyLog)
			if !cliMode {
				fmt.Printf("Loaded %d TLS session keys from %s\n", keyLog.SessionCount(), *keyLogFile)
			}
		}
	}

	var capturer *capture.Capturer
	var err error
	var isLive bool

	if *iface != "" {
		// Live capture
		capturer, err = capture.NewLiveCapturer(*iface, *bpfFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error starting capture: %v\n", err)
			fmt.Fprintf(os.Stderr, "Note: Live capture requires root privileges. Try: sudo %s\n", strings.Join(os.Args, " "))
			os.Exit(1)
		}
		isLive = true
		if !cliMode {
			fmt.Printf("Starting capture on interface %s...\n", *iface)
		}
	} else {
		// File capture
		capturer, err = capture.NewFileCapturer(*file, *bpfFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
			os.Exit(1)
		}
		isLive = false
		if !cliMode {
			fmt.Printf("Reading packets from %s...\n", *file)
		}
	}

	// Set TLS decryptor if available
	if tlsDecryptor != nil {
		capturer.SetDecryptor(tlsDecryptor)
	}

	// Enable stream reassembly if requested or if follow stream is needed
	needStreams := *enableStreams || strings.HasPrefix(*statsOption, "follow,")
	if needStreams {
		streamMgr := stream.NewStreamManager()
		capturer.SetStreamManager(streamMgr)
		if !cliMode && *enableStreams {
			fmt.Println("TCP stream reassembly enabled. Press 's' to view streams.")
		}
	}

	// Start capture
	packetChan := capturer.Start()

	// Statistics mode - -z option
	if *statsOption != "" {
		runStatsMode(packetChan, capturer, *statsOption, *displayFilter)
		return
	}

	// Write mode - save packets to file
	if *outputFile != "" {
		runWriteMode(packetChan, capturer, *outputFile, *maxCount, *displayFilter)
		return
	}

	// CLI mode - non-interactive output
	if cliMode {
		runCLIMode(packetChan, capturer, *outputFormat, *maxCount, *showDetail, *showHex, extractFields, *displayFilter)
		return
	}

	// Initialize AI agent if requested
	var aiAgent *agent.Agent
	if *enableAI {
		provider := llm.DetectProvider()
		if provider == "" {
			fmt.Fprintf(os.Stderr, "Warning: AI enabled but no API key found.\n")
			fmt.Fprintf(os.Stderr, "Set ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, or OLLAMA_BASE_URL.\n")
		} else {
			var err error
			aiAgent, err = agent.NewAgent(provider)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to initialize AI agent: %v\n", err)
			} else {
				fmt.Printf("AI assistant enabled (using %s). Press 'a' to chat.\n", provider)
				aiAgent.SetCapturer(capturer)
			}
		}
	}

	// Run TUI
	if aiAgent != nil {
		if err := ui.RunWithAI(packetChan, capturer, isLive, aiAgent); err != nil {
			fmt.Fprintf(os.Stderr, "Error running UI: %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := ui.Run(packetChan, capturer, isLive); err != nil {
			fmt.Fprintf(os.Stderr, "Error running UI: %v\n", err)
			os.Exit(1)
		}
	}
}

// runCLIMode runs in non-interactive CLI mode
func runCLIMode(packetChan <-chan capture.PacketInfo, capturer *capture.Capturer, outputFormat string, maxCount int, showDetail, showHex bool, extractFields []string, displayFilter string) {
	defer capturer.Stop()

	// Determine output format
	var format export.OutputFormat
	switch outputFormat {
	case "json":
		format = export.FormatJSON
	case "fields":
		format = export.FormatFields
	case "text", "":
		format = export.FormatText
	default:
		fmt.Fprintf(os.Stderr, "Unknown output format: %s\n", outputFormat)
		os.Exit(1)
	}

	// Create exporter
	exporter := export.NewExporter(os.Stdout, format)
	exporter.SetMaxCount(maxCount)
	exporter.SetShowDetail(showDetail)
	exporter.SetShowHex(showHex)

	if len(extractFields) > 0 {
		exporter.SetFields(extractFields)
	}

	// Compile display filter if specified
	var filterFunc func(*capture.PacketInfo) bool
	if displayFilter != "" {
		var err error
		filterFunc, err = compileDisplayFilter(displayFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error compiling display filter: %v\n", err)
			os.Exit(1)
		}
	}

	// Start output
	if err := exporter.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting export: %v\n", err)
		os.Exit(1)
	}

	// Process packets
	for pkt := range packetChan {
		// Apply display filter
		if filterFunc != nil && !filterFunc(&pkt) {
			continue
		}

		// Export packet
		if err := exporter.ExportPacket(&pkt); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting packet: %v\n", err)
		}

		// Check if we've reached the limit
		if exporter.ShouldStop() {
			break
		}
	}

	// Finish output
	if err := exporter.Finish(); err != nil {
		fmt.Fprintf(os.Stderr, "Error finishing export: %v\n", err)
	}
}

// runWriteMode writes packets to a pcapng file
func runWriteMode(packetChan <-chan capture.PacketInfo, capturer *capture.Capturer, outputFile string, maxCount int, displayFilter string) {
	defer capturer.Stop()

	// Create pcap writer
	writer, err := capture.NewPcapWriter(outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer writer.Close()

	// Compile display filter if specified
	var filterFunc func(*capture.PacketInfo) bool
	if displayFilter != "" {
		var err error
		filterFunc, err = compileDisplayFilter(displayFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error compiling display filter: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Writing packets to %s...\n", outputFile)

	count := 0
	for pkt := range packetChan {
		// Apply display filter
		if filterFunc != nil && !filterFunc(&pkt) {
			continue
		}

		// Write packet
		if err := writer.WritePacket(&pkt); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing packet: %v\n", err)
			continue
		}

		count++

		// Progress indicator every 1000 packets
		if count%1000 == 0 {
			fmt.Printf("\rWritten %d packets...", count)
		}

		// Check if we've reached the limit
		if maxCount > 0 && count >= maxCount {
			break
		}
	}

	// Final flush
	if err := writer.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "Error flushing output: %v\n", err)
	}

	fmt.Printf("\rWritten %d packets to %s\n", count, outputFile)
}

// listAvailableFields prints all available fields
func listAvailableFields() {
	registry := fields.NewRegistry()
	fieldList := registry.List()

	// Sort fields
	sortStrings(fieldList)

	fmt.Println("Available fields:")
	fmt.Println("Name\t\t\tType\tDescription")
	fmt.Println(strings.Repeat("-", 70))

	for _, name := range fieldList {
		info := registry.GetFieldInfo(name)
		if info != "" {
			fmt.Println(info)
		}
	}
}

// compileDisplayFilter compiles a display filter expression using expr-lang/expr
func compileDisplayFilter(filterStr string) (func(*capture.PacketInfo) bool, error) {
	// Create a filter using the filter package
	return filter.Compile(filterStr)
}

// sortStrings sorts a string slice
func sortStrings(s []string) {
	for i := 0; i < len(s)-1; i++ {
		for j := i + 1; j < len(s); j++ {
			if s[i] > s[j] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

// runStatsMode runs in statistics mode (-z option)
func runStatsMode(packetChan <-chan capture.PacketInfo, capturer *capture.Capturer, statsOption string, displayFilter string) {
	defer capturer.Stop()

	// Compile display filter if specified
	var filterFunc func(*capture.PacketInfo) bool
	if displayFilter != "" {
		var err error
		filterFunc, err = compileDisplayFilter(displayFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error compiling display filter: %v\n", err)
			os.Exit(1)
		}
	}

	// Check if expert mode
	if statsOption == "expert" || strings.HasPrefix(statsOption, "expert,") {
		runExpertMode(packetChan, filterFunc, statsOption)
		return
	}

	// Parse stats option
	statsMgr := stats.NewManager()

	// Parse io,stat interval if present
	interval := 1.0 // default 1 second
	if strings.HasPrefix(statsOption, "io,stat,") {
		parts := strings.Split(statsOption, ",")
		if len(parts) >= 3 {
			if v, err := strconv.ParseFloat(parts[2], 64); err == nil {
				interval = v
			}
		}
		statsMgr.SetBucketSize(time.Duration(interval * float64(time.Second)))
	}

	// Process all packets
	for pkt := range packetChan {
		// Apply display filter
		if filterFunc != nil && !filterFunc(&pkt) {
			continue
		}
		statsMgr.ProcessPacket(&pkt)
	}

	// Print statistics based on option
	switch {
	case statsOption == "endpoints" || statsOption == "endpoints,ip":
		statsMgr.PrintEndpoints(os.Stdout, "ip")
	case strings.HasPrefix(statsOption, "conv,"):
		proto := strings.TrimPrefix(statsOption, "conv,")
		statsMgr.PrintConversations(os.Stdout, proto)
	case strings.HasPrefix(statsOption, "io,stat"):
		statsMgr.PrintIOStats(os.Stdout, interval)
	case strings.HasPrefix(statsOption, "follow,"):
		runFollowStream(capturer, statsOption)
	default:
		fmt.Fprintf(os.Stderr, "Unknown statistics option: %s\n", statsOption)
		fmt.Fprintf(os.Stderr, "Supported options: endpoints, conv,tcp, conv,udp, io,stat,<interval>, follow,tcp,ascii,<stream>, expert\n")
		os.Exit(1)
	}
}

// runExpertMode runs expert analysis on packets
func runExpertMode(packetChan <-chan capture.PacketInfo, filterFunc func(*capture.PacketInfo) bool, statsOption string) {
	analyzer := expert.NewAnalyzer()

	// Parse expert options: expert or expert,<severity>
	minSeverity := expert.SeverityNote // Default to showing Note and above
	if strings.HasPrefix(statsOption, "expert,") {
		severityStr := strings.TrimPrefix(statsOption, "expert,")
		switch strings.ToLower(severityStr) {
		case "chat":
			minSeverity = expert.SeverityChat
		case "note":
			minSeverity = expert.SeverityNote
		case "warning", "warn":
			minSeverity = expert.SeverityWarning
		case "error":
			minSeverity = expert.SeverityError
		default:
			fmt.Fprintf(os.Stderr, "Unknown severity level: %s (use: chat, note, warning, error)\n", severityStr)
			os.Exit(1)
		}
	}

	// Process all packets
	packetCount := 0
	for pkt := range packetChan {
		packetCount++

		// Apply display filter
		if filterFunc != nil && !filterFunc(&pkt) {
			continue
		}

		// Analyze packet
		analyzer.Analyze(&pkt)
	}

	// Print results
	fmt.Printf("Analyzed %d packets\n\n", packetCount)
	analyzer.PrintSummary(os.Stdout)
	fmt.Println()
	analyzer.PrintDetails(os.Stdout, minSeverity)
}

// runFollowStream outputs the data for a specific TCP stream
func runFollowStream(capturer *capture.Capturer, statsOption string) {
	// Parse option: follow,tcp,ascii,<stream_id>
	parts := strings.Split(statsOption, ",")
	if len(parts) < 4 {
		fmt.Fprintf(os.Stderr, "Invalid follow syntax. Use: follow,tcp,ascii,<stream_id>\n")
		os.Exit(1)
	}

	proto := parts[1]
	format := parts[2]
	streamID, err := strconv.Atoi(parts[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid stream ID: %s\n", parts[3])
		os.Exit(1)
	}

	if proto != "tcp" {
		fmt.Fprintf(os.Stderr, "Only TCP follow is supported. Use: follow,tcp,ascii,<stream_id>\n")
		os.Exit(1)
	}

	if format != "ascii" && format != "hex" && format != "raw" {
		fmt.Fprintf(os.Stderr, "Unsupported format: %s. Use: ascii, hex, or raw\n", format)
		os.Exit(1)
	}

	streamMgr := capturer.GetStreamManager()
	if streamMgr == nil {
		fmt.Fprintf(os.Stderr, "Stream reassembly not enabled. Use -S flag or it will be enabled automatically with follow.\n")
		os.Exit(1)
	}

	// Find the stream by ID
	targetStream := streamMgr.GetStreamByID(streamID)
	if targetStream == nil {
		// List available streams
		streams := streamMgr.GetStreams()
		fmt.Fprintf(os.Stderr, "Stream #%d not found. Available streams:\n", streamID)
		for _, s := range streams {
			fmt.Fprintf(os.Stderr, "  #%d: %s <-> %s (%d bytes)\n", s.ID, s.ClientAddr, s.ServerAddr, s.TotalBytes())
		}
		os.Exit(1)
	}

	// Print stream info header
	fmt.Printf("================================================================================\n")
	fmt.Printf("Follow TCP Stream #%d\n", targetStream.ID)
	fmt.Printf("================================================================================\n")
	fmt.Printf("Client: %s\n", targetStream.ClientAddr)
	fmt.Printf("Server: %s\n", targetStream.ServerAddr)
	fmt.Printf("State:  %s\n", targetStream.State)
	fmt.Printf("================================================================================\n\n")

	// Output the stream data
	clientData := targetStream.GetClientData()
	serverData := targetStream.GetServerData()

	switch format {
	case "ascii":
		// Client -> Server (red in tshark, we'll use markers)
		if len(clientData) > 0 {
			fmt.Println("=== Client -> Server ===")
			printASCII(clientData)
			fmt.Println()
		}

		// Server -> Client (blue in tshark)
		if len(serverData) > 0 {
			fmt.Println("=== Server -> Client ===")
			printASCII(serverData)
			fmt.Println()
		}

	case "hex":
		if len(clientData) > 0 {
			fmt.Println("=== Client -> Server ===")
			printHexDump(clientData)
			fmt.Println()
		}
		if len(serverData) > 0 {
			fmt.Println("=== Server -> Client ===")
			printHexDump(serverData)
			fmt.Println()
		}

	case "raw":
		// Just output raw data to stdout
		os.Stdout.Write(clientData)
		os.Stdout.Write(serverData)
	}

	fmt.Printf("================================================================================\n")
	fmt.Printf("Total: Client sent %d bytes, Server sent %d bytes\n", len(clientData), len(serverData))
}

// printASCII prints data in ASCII format, replacing non-printable chars with dots
func printASCII(data []byte) {
	for _, b := range data {
		if b >= 32 && b <= 126 {
			fmt.Printf("%c", b)
		} else if b == '\n' || b == '\r' || b == '\t' {
			fmt.Printf("%c", b)
		} else {
			fmt.Print(".")
		}
	}
}

// printHexDump prints data in hex dump format
func printHexDump(data []byte) {
	bytesPerLine := 16
	for i := 0; i < len(data); i += bytesPerLine {
		// Offset
		fmt.Printf("%08x  ", i)

		// Hex bytes
		for j := 0; j < bytesPerLine; j++ {
			if i+j < len(data) {
				fmt.Printf("%02x ", data[i+j])
			} else {
				fmt.Print("   ")
			}
			if j == 7 {
				fmt.Print(" ")
			}
		}

		// ASCII
		fmt.Print(" |")
		for j := 0; j < bytesPerLine && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}
