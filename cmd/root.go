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
	Short: "MCP server for AI-powered network packet analysis",
	Long: `PktAnalyzer is an MCP (Model Context Protocol) server that exposes
network packet analysis capabilities as structured tools for AI agents.

It supports:
  - Pcap/pcapng file analysis with SQLite indexing
  - TLS traffic decryption via SSLKEYLOGFILE
  - TCP stream reassembly and HTTP following
  - Wireshark-compatible display filters
  - Field extraction with 100+ protocol fields
  - Anomaly detection and expert analysis

MCP transports: stdio (default) and SSE.

Examples:
  pktanalyzer mcp capture.pcap                     # Start MCP server (stdio)
  pktanalyzer mcp capture.pcap --transport sse     # Start MCP server (SSE)
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
	rootCmd.AddGroup(
		&cobra.Group{ID: "server", Title: "Server Commands:"},
		&cobra.Group{ID: "info", Title: "Information Commands:"},
	)

	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(mcpCmd)
}
