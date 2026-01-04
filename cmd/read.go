package cmd

import (
	"fmt"
	"os"

	"github.com/Zerofisher/pktanalyzer/agent"
	"github.com/Zerofisher/pktanalyzer/agent/llm"
	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/export"
	"github.com/Zerofisher/pktanalyzer/filter"
	"github.com/Zerofisher/pktanalyzer/stream"
	"github.com/Zerofisher/pktanalyzer/tls"
	"github.com/Zerofisher/pktanalyzer/ui"
	"github.com/spf13/cobra"
)

// read command flags
var (
	readDisplayFilter string
	readKeylogFile    string
	readEnableStreams bool
	readEnableAI      bool
	readBPFFilter     string
)

var readCmd = &cobra.Command{
	Use:   "read <file>",
	Short: "Read and analyze pcap/pcapng file",
	Long:  `Read packets from a pcap or pcapng file and display in TUI mode.`,
	Example: `  pktanalyzer read capture.pcap
  pktanalyzer read capture.pcap -S -A
  pktanalyzer read capture.pcap -k sslkeys.log
  pktanalyzer read capture.pcap -Y "tcp.port == 443"

For CLI output modes, use subcommands:
  pktanalyzer read text capture.pcap -c 10
  pktanalyzer read json capture.pcap
  pktanalyzer read fields capture.pcap -e ip.src -e ip.dst`,
	Args:    cobra.ExactArgs(1),
	GroupID: "input",
	RunE:    runRead,
}

// text subcommand flags
var (
	readTextCount   int
	readTextVerbose bool
	readTextHex     bool
)

var readTextCmd = &cobra.Command{
	Use:   "text <file>",
	Short: "Output packets as text",
	Long:  `Output packets in human-readable text format to stdout.`,
	Example: `  pktanalyzer read text capture.pcap
  pktanalyzer read text capture.pcap -c 10
  pktanalyzer read text capture.pcap -V -x`,
	Args: cobra.ExactArgs(1),
	RunE: runReadText,
}

// json subcommand flags
var readJSONCount int

var readJSONCmd = &cobra.Command{
	Use:   "json <file>",
	Short: "Output packets as JSON",
	Long:  `Output packets in JSON format to stdout.`,
	Example: `  pktanalyzer read json capture.pcap
  pktanalyzer read json capture.pcap -c 10`,
	Args: cobra.ExactArgs(1),
	RunE: runReadJSON,
}

// fields subcommand flags
var (
	readFieldsCount   int
	readFieldsExtract []string
)

var readFieldsCmd = &cobra.Command{
	Use:   "fields <file>",
	Short: "Extract specific fields from packets",
	Long:  `Extract and output specific fields from packets.`,
	Example: `  pktanalyzer read fields capture.pcap -e ip.src -e ip.dst
  pktanalyzer read fields capture.pcap -e frame.number -e tcp.port -c 100`,
	Args: cobra.ExactArgs(1),
	RunE: runReadFields,
}

func init() {
	// Persistent flags for read command (inherited by subcommands)
	readCmd.PersistentFlags().StringVarP(&readDisplayFilter, "filter", "Y", "",
		"Display filter expression (Wireshark-like)")
	readCmd.PersistentFlags().StringVarP(&readKeylogFile, "keylog", "k", "",
		"SSLKEYLOGFILE for TLS decryption")
	readCmd.PersistentFlags().BoolVarP(&readEnableStreams, "streams", "S", false,
		"Enable TCP stream reassembly")
	readCmd.PersistentFlags().BoolVarP(&readEnableAI, "ai", "A", false,
		"Enable AI assistant (requires API key)")
	readCmd.PersistentFlags().StringVarP(&readBPFFilter, "bpf", "f", "",
		"BPF filter expression (capture filter)")

	// text subcommand flags
	readTextCmd.Flags().IntVarP(&readTextCount, "count", "c", 0, "Stop after n packets (0 = unlimited)")
	readTextCmd.Flags().BoolVarP(&readTextVerbose, "verbose", "V", false, "Show packet details")
	readTextCmd.Flags().BoolVarP(&readTextHex, "hex", "x", false, "Show hex dump")

	// json subcommand flags
	readJSONCmd.Flags().IntVarP(&readJSONCount, "count", "c", 0, "Stop after n packets (0 = unlimited)")

	// fields subcommand flags
	readFieldsCmd.Flags().IntVarP(&readFieldsCount, "count", "c", 0, "Stop after n packets (0 = unlimited)")
	readFieldsCmd.Flags().StringArrayVarP(&readFieldsExtract, "field", "e", nil,
		"Field to extract (can be specified multiple times)")

	// Add subcommands
	readCmd.AddCommand(readTextCmd)
	readCmd.AddCommand(readJSONCmd)
	readCmd.AddCommand(readFieldsCmd)
}

// setupReadCapturer creates a file capturer with common configuration
func setupReadCapturer(file string) (*capture.Capturer, *tls.Decryptor, error) {
	capturer, err := capture.NewFileCapturer(file, readBPFFilter)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening file: %w", err)
	}

	// Load TLS key log if specified
	var tlsDecryptor *tls.Decryptor
	if readKeylogFile != "" {
		keyLog, err := tls.LoadKeyLogFile(readKeylogFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to load key log file: %v\n", err)
		} else {
			tlsDecryptor = tls.NewDecryptor(keyLog)
			capturer.SetDecryptor(tlsDecryptor)
		}
	}

	// Enable stream reassembly if requested
	if readEnableStreams {
		streamMgr := stream.NewStreamManager()
		capturer.SetStreamManager(streamMgr)
	}

	return capturer, tlsDecryptor, nil
}

// compileDisplayFilter compiles a display filter if specified
func compileDisplayFilter(filterStr string) (func(*capture.PacketInfo) bool, error) {
	if filterStr == "" {
		return nil, nil
	}
	return filter.Compile(filterStr)
}

// runRead runs the TUI mode for reading pcap files
func runRead(cmd *cobra.Command, args []string) error {
	file := args[0]

	capturer, tlsDecryptor, err := setupReadCapturer(file)
	if err != nil {
		return err
	}

	// Print info
	fmt.Printf("Reading packets from %s...\n", file)
	if tlsDecryptor != nil {
		fmt.Printf("Loaded TLS session keys from %s\n", readKeylogFile)
	}
	if readEnableStreams {
		fmt.Println("TCP stream reassembly enabled. Press 's' to view streams.")
	}

	// Start capture
	packetChan := capturer.Start()

	// Initialize AI agent if requested
	var aiAgent *agent.Agent
	if readEnableAI {
		provider := llm.DetectProvider()
		if provider == "" {
			fmt.Fprintf(os.Stderr, "Warning: AI enabled but no API key found.\n")
			fmt.Fprintf(os.Stderr, "Set ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, or OLLAMA_BASE_URL.\n")
		} else {
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
		return ui.RunWithAI(packetChan, capturer, false, aiAgent)
	}
	return ui.Run(packetChan, capturer, false)
}

// runReadText outputs packets as text
func runReadText(cmd *cobra.Command, args []string) error {
	file := args[0]

	capturer, _, err := setupReadCapturer(file)
	if err != nil {
		return err
	}

	// Compile display filter
	filterFunc, err := compileDisplayFilter(readDisplayFilter)
	if err != nil {
		capturer.Stop()
		return fmt.Errorf("error compiling display filter: %w", err)
	}

	// Create exporter
	exporter := export.NewExporter(os.Stdout, export.FormatText)
	exporter.SetMaxCount(readTextCount)
	exporter.SetShowDetail(readTextVerbose)
	exporter.SetShowHex(readTextHex)

	if err := exporter.Start(); err != nil {
		capturer.Stop()
		return fmt.Errorf("error starting export: %w", err)
	}

	// Start capture and process packets
	packetChan := capturer.Start()
	for pkt := range packetChan {
		if filterFunc != nil && !filterFunc(&pkt) {
			continue
		}
		if err := exporter.ExportPacket(&pkt); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting packet: %v\n", err)
		}
		if exporter.ShouldStop() {
			break
		}
	}

	if err := exporter.Finish(); err != nil {
		fmt.Fprintf(os.Stderr, "Error finishing export: %v\n", err)
	}
	capturer.Stop()
	return nil
}

// runReadJSON outputs packets as JSON
func runReadJSON(cmd *cobra.Command, args []string) error {
	file := args[0]

	capturer, _, err := setupReadCapturer(file)
	if err != nil {
		return err
	}

	filterFunc, err := compileDisplayFilter(readDisplayFilter)
	if err != nil {
		capturer.Stop()
		return fmt.Errorf("error compiling display filter: %w", err)
	}

	exporter := export.NewExporter(os.Stdout, export.FormatJSON)
	exporter.SetMaxCount(readJSONCount)

	if err := exporter.Start(); err != nil {
		capturer.Stop()
		return fmt.Errorf("error starting export: %w", err)
	}

	packetChan := capturer.Start()
	for pkt := range packetChan {
		if filterFunc != nil && !filterFunc(&pkt) {
			continue
		}
		if err := exporter.ExportPacket(&pkt); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting packet: %v\n", err)
		}
		if exporter.ShouldStop() {
			break
		}
	}

	if err := exporter.Finish(); err != nil {
		fmt.Fprintf(os.Stderr, "Error finishing export: %v\n", err)
	}
	capturer.Stop()
	return nil
}

// runReadFields extracts specific fields from packets
func runReadFields(cmd *cobra.Command, args []string) error {
	file := args[0]

	if len(readFieldsExtract) == 0 {
		return fmt.Errorf("at least one field must be specified with -e")
	}

	capturer, _, err := setupReadCapturer(file)
	if err != nil {
		return err
	}

	filterFunc, err := compileDisplayFilter(readDisplayFilter)
	if err != nil {
		capturer.Stop()
		return fmt.Errorf("error compiling display filter: %w", err)
	}

	exporter := export.NewExporter(os.Stdout, export.FormatFields)
	exporter.SetMaxCount(readFieldsCount)
	exporter.SetFields(readFieldsExtract)

	if err := exporter.Start(); err != nil {
		capturer.Stop()
		return fmt.Errorf("error starting export: %w", err)
	}

	packetChan := capturer.Start()
	for pkt := range packetChan {
		if filterFunc != nil && !filterFunc(&pkt) {
			continue
		}
		if err := exporter.ExportPacket(&pkt); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting packet: %v\n", err)
		}
		if exporter.ShouldStop() {
			break
		}
	}

	if err := exporter.Finish(); err != nil {
		fmt.Fprintf(os.Stderr, "Error finishing export: %v\n", err)
	}
	capturer.Stop()
	return nil
}
