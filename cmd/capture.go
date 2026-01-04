package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/Zerofisher/pktanalyzer/agent"
	"github.com/Zerofisher/pktanalyzer/agent/llm"
	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/stream"
	"github.com/Zerofisher/pktanalyzer/tls"
	"github.com/Zerofisher/pktanalyzer/ui"
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
func setupCaptureLive(iface string) (*capture.Capturer, *tls.Decryptor, error) {
	capturer, err := capture.NewLiveCapturer(iface, captureBPFFilter)
	if err != nil {
		return nil, nil, fmt.Errorf("error starting capture: %w\nNote: Live capture requires root privileges. Try: sudo %s", err, strings.Join(os.Args, " "))
	}

	// Load TLS key log if specified
	var tlsDecryptor *tls.Decryptor
	if captureKeylogFile != "" {
		keyLog, err := tls.LoadKeyLogFile(captureKeylogFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to load key log file: %v\n", err)
		} else {
			tlsDecryptor = tls.NewDecryptor(keyLog)
			capturer.SetDecryptor(tlsDecryptor)
		}
	}

	// Enable stream reassembly if requested
	if captureEnableStreams {
		streamMgr := stream.NewStreamManager()
		capturer.SetStreamManager(streamMgr)
	}

	return capturer, tlsDecryptor, nil
}

// runCapture runs live capture in TUI mode
func runCapture(cmd *cobra.Command, args []string) error {
	iface := args[0]

	capturer, tlsDecryptor, err := setupCaptureLive(iface)
	if err != nil {
		return err
	}

	// Print info
	fmt.Printf("Starting capture on interface %s...\n", iface)
	if tlsDecryptor != nil {
		fmt.Printf("Loaded TLS session keys from %s\n", captureKeylogFile)
	}
	if captureEnableStreams {
		fmt.Println("TCP stream reassembly enabled. Press 's' to view streams.")
	}

	// Start capture
	packetChan := capturer.Start()

	// Initialize AI agent if requested
	var aiAgent *agent.Agent
	if captureEnableAI {
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

	// Run TUI (isLive = true)
	if aiAgent != nil {
		return ui.RunWithAI(packetChan, capturer, true, aiAgent)
	}
	return ui.Run(packetChan, capturer, true)
}

// runCaptureWrite captures packets and writes to file
func runCaptureWrite(cmd *cobra.Command, args []string) error {
	iface := args[0]
	outputFile := args[1]

	capturer, _, err := setupCaptureLive(iface)
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
	var filterFunc func(*capture.PacketInfo) bool
	if captureWriteDisplayFilter != "" {
		filterFunc, err = compileDisplayFilter(captureWriteDisplayFilter)
		if err != nil {
			capturer.Stop()
			return fmt.Errorf("error compiling display filter: %w", err)
		}
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
