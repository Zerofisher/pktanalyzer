package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	mcpPkg "github.com/Zerofisher/pktanalyzer/mcp"
	"github.com/Zerofisher/pktanalyzer/mcp/tools"
	"github.com/Zerofisher/pktanalyzer/pkg/ingest"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
	"github.com/Zerofisher/pktanalyzer/pkg/replay"
	"github.com/Zerofisher/pktanalyzer/pkg/security"
	pkgtls "github.com/Zerofisher/pktanalyzer/pkg/tls"

	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

var (
	mcpTransport   string
	mcpBind        string
	mcpPort        int
	mcpLive        bool
	mcpInterface   string
	mcpBPF         string
	mcpKeylogFile  string
	mcpEnableRaw   bool
	mcpRawMax      int
	mcpRedactIPs   bool
	mcpRedactMACs  bool
	mcpRedactCreds bool
	mcpRateLimit   int
	mcpVerbose     bool
)

var mcpCmd = &cobra.Command{
	Use:   "mcp [pcap-file]",
	Short: "Start MCP server for AI-powered packet analysis",
	Long: `Start an MCP (Model Context Protocol) server that exposes packet analysis
tools for AI agents. Optionally pre-loads a pcap file.

Supports stdio (default) and SSE transports.

Examples:
  pktanalyzer mcp capture.pcap
  pktanalyzer mcp capture.pcap --transport sse --port 9090
  pktanalyzer mcp --keylog-file sslkeys.log capture.pcap --enable-raw
  pktanalyzer mcp --live --interface en0 --bpf "tcp port 80"`,
	Args:    cobra.MaximumNArgs(1),
	GroupID: "server",
	RunE:    runMCP,
}

func init() {
	mcpCmd.Flags().StringVar(&mcpTransport, "transport", "stdio", "Transport: stdio or sse")
	mcpCmd.Flags().StringVar(&mcpBind, "bind", "127.0.0.1", "SSE bind address")
	mcpCmd.Flags().IntVar(&mcpPort, "port", 8080, "SSE listen port")
	mcpCmd.Flags().BoolVar(&mcpLive, "live", false, "Live capture mode (no pcap file needed)")
	mcpCmd.Flags().StringVar(&mcpInterface, "interface", "", "Capture interface (required with --live)")
	mcpCmd.Flags().StringVar(&mcpBPF, "bpf", "", "BPF filter expression")
	mcpCmd.Flags().StringVar(&mcpKeylogFile, "keylog-file", "", "SSLKEYLOGFILE path for TLS decryption")
	mcpCmd.Flags().BoolVar(&mcpEnableRaw, "enable-raw", false, "Allow raw packet data access")
	mcpCmd.Flags().IntVar(&mcpRawMax, "raw-max-bytes", 1024, "Max raw bytes per packet")
	mcpCmd.Flags().BoolVar(&mcpRedactIPs, "redact-ips", false, "Redact IP addresses in output")
	mcpCmd.Flags().BoolVar(&mcpRedactMACs, "redact-macs", false, "Redact MAC addresses")
	mcpCmd.Flags().BoolVar(&mcpRedactCreds, "redact-creds", false, "Redact HTTP credentials")
	mcpCmd.Flags().IntVar(&mcpRateLimit, "rate-limit", 100, "Max tool calls per minute")
	mcpCmd.Flags().BoolVar(&mcpVerbose, "verbose", false, "Enable debug logging")
}

func runMCP(cmd *cobra.Command, args []string) error {
	// Setup logging
	level := slog.LevelInfo
	if mcpVerbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	// Build security config
	secCfg := security.DefaultConfig()
	secCfg.EnableRaw = mcpEnableRaw
	secCfg.RawMaxBytes = mcpRawMax
	secCfg.KeylogFile = mcpKeylogFile
	secCfg.RedactIPs = mcpRedactIPs
	secCfg.RedactMACs = mcpRedactMACs
	secCfg.RedactCreds = mcpRedactCreds
	secCfg.RateLimit = mcpRateLimit

	// Setup TLS decryptor if keylog file provided
	var decryptor *pkgtls.Decryptor
	if mcpKeylogFile != "" {
		keyLog, err := pkgtls.LoadKeyLogFile(mcpKeylogFile)
		if err != nil {
			return fmt.Errorf("load keylog file: %w", err)
		}
		decryptor = pkgtls.NewDecryptor(keyLog)
		slog.Info("TLS decryption enabled", "keylog", mcpKeylogFile)
	}

	// Initialize ToolContext (engine and reader are nil until a pcap is loaded)
	tc := tools.NewToolContext(nil, nil, secCfg)

	// Validate flags
	if mcpLive && mcpInterface == "" {
		return fmt.Errorf("--interface is required with --live")
	}
	if !mcpLive && len(args) == 0 {
		slog.Info("starting MCP server with no pre-loaded capture — use open_pcap or capture_live tool")
	}

	// Pre-load pcap if provided
	if len(args) > 0 {
		pcapPath := args[0]
		slog.Info("loading pcap", "path", pcapPath)

		needsIndex, err := ingest.NeedsReindex(pcapPath)
		if err != nil {
			return fmt.Errorf("check index: %w", err)
		}
		if needsIndex {
			slog.Info("indexing pcap", "path", pcapPath)
			result, err := ingest.IndexFile(pcapPath, func(processed, total int, elapsed time.Duration) {
				slog.Debug("indexing progress", "processed", processed, "elapsed", elapsed)
			})
			if err != nil {
				return fmt.Errorf("index file: %w", err)
			}
			slog.Info("indexing complete",
				"packets", result.TotalPackets,
				"flows", result.TotalFlows,
				"duration", result.Duration.Round(time.Millisecond))
		}

		engine, err := query.NewFromPcap(pcapPath)
		if err != nil {
			return fmt.Errorf("open index: %w", err)
		}

		reader := replay.NewReader(pcapPath, decryptor)
		tc.SetCapture(engine, reader, pcapPath)
	}

	// Create MCP server
	mcpServer := mcpPkg.NewPktAnalyzerServer(tc, mcpPkg.ServerConfig{
		Transport: mcpTransport,
		Bind:      mcpBind,
		Port:      mcpPort,
		Version:   Version,
	})

	// Start server based on transport
	switch mcpTransport {
	case "sse":
		return runSSE(mcpServer, mcpBind, mcpPort)
	default:
		return runStdio(mcpServer)
	}
}

func runStdio(s *server.MCPServer) error {
	slog.Info("starting MCP server", "transport", "stdio")
	stdio := server.NewStdioServer(s)
	return stdio.Listen(context.Background(), os.Stdin, os.Stdout)
}

func runSSE(s *server.MCPServer, bind string, port int) error {
	addr := fmt.Sprintf("%s:%d", bind, port)
	slog.Info("starting MCP server", "transport", "sse", "addr", addr)

	sseServer := server.NewSSEServer(s)

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		slog.Info("shutting down SSE server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sseServer.Shutdown(shutdownCtx)
	}()

	if err := sseServer.Start(addr); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("SSE server: %w", err)
	}
	return nil
}
