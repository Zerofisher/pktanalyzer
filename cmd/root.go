// Package cmd provides the CLI commands for pktanalyzer using Cobra.
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "pktanalyzer",
	Short: "Network packet analyzer with TLS decryption and AI",
	Long: `PktAnalyzer is a powerful network packet analyzer that supports:

  - Live capture and pcap/pcapng file analysis
  - TLS traffic decryption via SSLKEYLOGFILE
  - TCP stream reassembly and following
  - AI-powered packet analysis assistant
  - Wireshark-compatible display filters

Examples:
  pktanalyzer read capture.pcap                    # Open in TUI
  pktanalyzer read capture.pcap text -c 10         # Print first 10 packets
  pktanalyzer capture en0                          # Live capture on en0
  pktanalyzer stats endpoints -r capture.pcap      # Show endpoints
  pktanalyzer list interfaces                      # List network interfaces`,
	Version: Version,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// Define command groups for organized help output
	rootCmd.AddGroup(
		&cobra.Group{ID: "input", Title: "Input Commands:"},
		&cobra.Group{ID: "analysis", Title: "Analysis Commands:"},
		&cobra.Group{ID: "info", Title: "Information Commands:"},
	)

	// Add subcommands
	rootCmd.AddCommand(readCmd)
	rootCmd.AddCommand(captureCmd)
	rootCmd.AddCommand(statsCmd)
	rootCmd.AddCommand(followCmd)
	rootCmd.AddCommand(listCmd)
}
