package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/export"
	"github.com/Zerofisher/pktanalyzer/internal/app"
	"github.com/Zerofisher/pktanalyzer/pkg/ingest"
	"github.com/Zerofisher/pktanalyzer/ui"
	uiadapter "github.com/Zerofisher/pktanalyzer/ui/adapter"
	"github.com/spf13/cobra"
)

// read command flags
var (
	readDisplayFilter string
	readKeylogFile    string
	readEnableStreams bool
	readEnableAI      bool
	readBPFFilter     string
	readUseIndex      bool
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
	readCmd.Flags().BoolVarP(&readUseIndex, "index", "I", false,
		"Use indexed mode (SQLite-backed, supports large files)")

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
func setupReadCapturer(file string) (*capture.Capturer, error) {
	result, err := app.SetupCapturer(app.CaptureConfig{
		Source:        file,
		IsLive:        false,
		BPFFilter:     readBPFFilter,
		KeylogFile:    readKeylogFile,
		EnableStreams: readEnableStreams,
	})
	if err != nil {
		return nil, err
	}
	return result.Capturer, nil
}

// runRead runs the TUI mode for reading pcap files
func runRead(cmd *cobra.Command, args []string) error {
	file := args[0]

	// Check for indexed mode
	if readUseIndex {
		return runReadIndexed(file)
	}

	capturer, err := setupReadCapturer(file)
	if err != nil {
		return err
	}

	// Print info
	fmt.Printf("Reading packets from %s...\n", file)
	if readKeylogFile != "" {
		fmt.Printf("Loaded TLS session keys from %s\n", readKeylogFile)
	}
	if readEnableStreams {
		fmt.Println("TCP stream reassembly enabled. Press 's' to view streams.")
	}

	// Create MemoryStore for live capture
	store := uiadapter.NewMemoryStore()
	defer store.Close()

	// Start capture
	packetChan := capturer.Start()

	// Initialize AI agent if requested
	var ai uiadapter.AIAssistant
	if readEnableAI {
		ai = app.SetupAI(app.AIConfig{
			Capturer:     capturer,
			PacketReader: store,
		})
	}

	// Run TUI
	if ai != nil {
		return ui.RunWithAI(store, packetChan, capturer, false, ai)
	}
	return ui.Run(store, packetChan, capturer, false)
}

// runReadText outputs packets as text
func runReadText(cmd *cobra.Command, args []string) error {
	return app.RunExport(os.Stdout, app.ExportConfig{
		CaptureConfig: app.CaptureConfig{
			Source:        args[0],
			IsLive:        false,
			BPFFilter:     readBPFFilter,
			KeylogFile:    readKeylogFile,
			EnableStreams: readEnableStreams,
		},
		DisplayFilter: readDisplayFilter,
		Format:        export.FormatText,
		MaxCount:      readTextCount,
		ShowDetail:    readTextVerbose,
		ShowHex:       readTextHex,
	})
}

// runReadIndexed runs the TUI in indexed mode (SQLite-backed)
func runReadIndexed(file string) error {
	// Check if index exists and is valid
	needsIndex, err := ingest.NeedsReindex(file)
	if err != nil {
		return fmt.Errorf("check index: %w", err)
	}

	if needsIndex {
		fmt.Printf("Indexing %s...\n", file)
		result, err := ingest.IndexFile(file, func(processed, total int, elapsed time.Duration) {
			fmt.Printf("\rProcessed %d packets...", processed)
		})
		if err != nil {
			return fmt.Errorf("index file: %w", err)
		}
		fmt.Printf("\nIndexed %d packets, %d flows in %v\n\n", result.TotalPackets, result.TotalFlows, result.Duration.Round(time.Millisecond))
	}

	// Create indexed store
	store, err := uiadapter.NewIndexedStore(file)
	if err != nil {
		return fmt.Errorf("open index: %w", err)
	}
	defer store.Close()

	// Initialize AI agent if requested
	var ai uiadapter.AIAssistant
	if readEnableAI {
		ai = app.SetupAI(app.AIConfig{
			PacketReader: store,
		})
	}

	return ui.RunWithStore(store, ai)
}

// runReadJSON outputs packets as JSON
func runReadJSON(cmd *cobra.Command, args []string) error {
	return app.RunExport(os.Stdout, app.ExportConfig{
		CaptureConfig: app.CaptureConfig{
			Source:        args[0],
			IsLive:        false,
			BPFFilter:     readBPFFilter,
			KeylogFile:    readKeylogFile,
			EnableStreams: readEnableStreams,
		},
		DisplayFilter: readDisplayFilter,
		Format:        export.FormatJSON,
		MaxCount:      readJSONCount,
	})
}

// runReadFields extracts specific fields from packets
func runReadFields(cmd *cobra.Command, args []string) error {
	if err := app.ValidateFields(readFieldsExtract); err != nil {
		return err
	}

	return app.RunExport(os.Stdout, app.ExportConfig{
		CaptureConfig: app.CaptureConfig{
			Source:        args[0],
			IsLive:        false,
			BPFFilter:     readBPFFilter,
			KeylogFile:    readKeylogFile,
			EnableStreams: readEnableStreams,
		},
		DisplayFilter: readDisplayFilter,
		Format:        export.FormatFields,
		MaxCount:      readFieldsCount,
		Fields:        readFieldsExtract,
	})
}
