package cmd

import (
	"fmt"
	"os"

	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/internal/app"
	"github.com/Zerofisher/pktanalyzer/ui"
	uiadapter "github.com/Zerofisher/pktanalyzer/ui/adapter"
	"github.com/spf13/cobra"
)

// capture command flags
var (
	captureBPFFilter     string
	captureKeylogFile    string
	captureEnableStreams bool
	captureEnableAI      bool
)

var captureCmd = &cobra.Command{
	Use:   "capture <interface>",
	Short: "Live packet capture from network interface",
	Long: `Start live packet capture on a network interface and display in TUI mode.
Requires root privileges on most systems.`,
	Example: `  sudo pktanalyzer capture en0
  sudo pktanalyzer capture eth0 -f "tcp port 80"
  sudo pktanalyzer capture en0 -S -A

For writing to file:
  sudo pktanalyzer capture write en0 output.pcapng`,
	Args:    cobra.ExactArgs(1),
	GroupID: "input",
	RunE:    runCapture,
}

// write subcommand flags
var (
	captureWriteCount         int
	captureWriteDisplayFilter string
)

var captureWriteCmd = &cobra.Command{
	Use:   "write <interface> <file>",
	Short: "Write captured packets to pcapng file",
	Long:  `Capture packets from an interface and write them to a pcapng file.`,
	Example: `  sudo pktanalyzer capture write en0 output.pcapng
  sudo pktanalyzer capture write en0 output.pcapng -c 1000
  sudo pktanalyzer capture write eth0 output.pcapng -f "tcp port 443"`,
	Args: cobra.ExactArgs(2),
	RunE: runCaptureWrite,
}

func init() {
	// Persistent flags for capture command
	captureCmd.PersistentFlags().StringVarP(&captureBPFFilter, "bpf", "f", "",
		"BPF filter expression")
	captureCmd.PersistentFlags().StringVarP(&captureKeylogFile, "keylog", "k", "",
		"SSLKEYLOGFILE for TLS decryption")
	captureCmd.PersistentFlags().BoolVarP(&captureEnableStreams, "streams", "S", false,
		"Enable TCP stream reassembly")
	captureCmd.PersistentFlags().BoolVarP(&captureEnableAI, "ai", "A", false,
		"Enable AI assistant (requires API key)")

	// write subcommand flags
	captureWriteCmd.Flags().IntVarP(&captureWriteCount, "count", "c", 0,
		"Stop after n packets (0 = unlimited)")
	captureWriteCmd.Flags().StringVarP(&captureWriteDisplayFilter, "filter", "Y", "",
		"Display filter expression")

	captureCmd.AddCommand(captureWriteCmd)
}

// setupCaptureLive creates a live capturer with common configuration
func setupCaptureLive(iface string) (*capture.Capturer, error) {
	result, err := app.SetupCapturer(app.CaptureConfig{
		Source:        iface,
		IsLive:        true,
		BPFFilter:     captureBPFFilter,
		KeylogFile:    captureKeylogFile,
		EnableStreams: captureEnableStreams,
	})
	if err != nil {
		return nil, err
	}
	return result.Capturer, nil
}

// runCapture runs live capture in TUI mode
func runCapture(cmd *cobra.Command, args []string) error {
	iface := args[0]

	capturer, err := setupCaptureLive(iface)
	if err != nil {
		return err
	}

	// Print info
	fmt.Printf("Starting capture on interface %s...\n", iface)
	if captureKeylogFile != "" {
		fmt.Printf("Loaded TLS session keys from %s\n", captureKeylogFile)
	}
	if captureEnableStreams {
		fmt.Println("TCP stream reassembly enabled. Press 's' to view streams.")
	}

	// Create MemoryStore for live capture
	store := uiadapter.NewMemoryStore()
	defer store.Close()

	// Start capture
	packetChan := capturer.Start()

	// Initialize AI agent if requested
	var ai uiadapter.AIAssistant
	if captureEnableAI {
		ai = app.SetupAI(app.AIConfig{
			Capturer:     capturer,
			PacketReader: store,
		})
	}

	// Run TUI (isLive = true)
	if ai != nil {
		return ui.RunWithAI(store, packetChan, capturer, true, ai)
	}
	return ui.Run(store, packetChan, capturer, true)
}

// runCaptureWrite captures packets and writes to file
func runCaptureWrite(cmd *cobra.Command, args []string) error {
	iface := args[0]
	outputFile := args[1]

	capturer, err := setupCaptureLive(iface)
	if err != nil {
		return err
	}

	// Create pcap writer
	writer, err := capture.NewPcapWriter(outputFile)
	if err != nil {
		capturer.Stop()
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer writer.Close()

	// Compile display filter if specified
	filterFunc, err := app.CompileDisplayFilter(captureWriteDisplayFilter)
	if err != nil {
		capturer.Stop()
		return fmt.Errorf("error compiling display filter: %w", err)
	}

	fmt.Printf("Capturing on %s, writing to %s...\n", iface, outputFile)
	fmt.Println("Press Ctrl+C to stop.")

	// Start capture and process packets
	packetChan := capturer.Start()
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
		if captureWriteCount > 0 && count >= captureWriteCount {
			break
		}
	}

	// Final flush
	if err := writer.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "Error flushing output: %v\n", err)
	}

	fmt.Printf("\rWritten %d packets to %s\n", count, outputFile)
	capturer.Stop()
	return nil
}
