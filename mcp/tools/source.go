package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/Zerofisher/pktanalyzer/pkg/capture"
	"github.com/Zerofisher/pktanalyzer/pkg/ingest"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
	"github.com/Zerofisher/pktanalyzer/pkg/replay"
	"github.com/Zerofisher/pktanalyzer/pkg/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// RegisterSourceTools registers the 4 source tools with the MCP server.
func RegisterSourceTools(s *server.MCPServer, tc *ToolContext) {
	s.AddTool(mcp.NewTool("open_pcap",
		mcp.WithDescription("Open and index a pcap/pcapng file. Replaces the currently loaded capture."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Path to pcap/pcapng file")),
	), HandleOpenPcap(tc))

	s.AddTool(mcp.NewTool("capture_live",
		mcp.WithDescription("Start live capture on a network interface. Blocks until count/duration reached."),
		mcp.WithString("interface", mcp.Required(), mcp.Description("Network interface name")),
		mcp.WithString("filter", mcp.Description("BPF filter expression")),
		mcp.WithNumber("count", mcp.Description("Max packets to capture (default 1000)")),
		mcp.WithString("duration", mcp.Description("Max capture duration, e.g. '30s' (default 30s)")),
	), HandleCaptureLive(tc))

	s.AddTool(mcp.NewTool("list_interfaces",
		mcp.WithDescription("List available network interfaces for capture"),
	), HandleListInterfaces(tc))

	s.AddTool(mcp.NewTool("get_overview",
		mcp.WithDescription("Get capture overview: total packets, time span, protocol distribution"),
	), HandleGetOverview(tc))
}

// HandleOpenPcap opens and indexes a pcap file, replacing the active capture.
func HandleOpenPcap(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path, err := requiredString(req, "path")
		if err != nil {
			return toolError("INVALID_PARAM", err.Error()), nil
		}

		// Check / create index
		needsIndex, err := ingest.NeedsReindex(path)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("check index: %v", err)), nil
		}

		if needsIndex {
			_, err := ingest.IndexFile(path, nil)
			if err != nil {
				return toolError("INTERNAL", fmt.Sprintf("index file: %v", err)), nil
			}
		}

		// Open query engine
		engine, err := query.NewFromPcap(path)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("open index: %v", err)), nil
		}

		// Create replay reader
		reader := replay.NewReader(path, nil)

		// Replace active capture
		tc.SetCapture(engine, reader, path)

		// Return overview
		overview, err := engine.GetOverview(ctx)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("get overview: %v", err)), nil
		}

		return mcp.NewToolResultText(toJSON(map[string]any{
			"status":   "opened",
			"path":     path,
			"overview": overview,
		})), nil
	}
}

// HandleCaptureLive captures packets to a temp file, indexes it, and opens it.
func HandleCaptureLive(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		iface, err := requiredString(req, "interface")
		if err != nil {
			return toolError("INVALID_PARAM", err.Error()), nil
		}
		bpf := optionalString(req, "filter", "")
		count := optionalInt(req, "count", 1000)
		count = security.ClampInt(count, 1, 100000)
		durStr := optionalString(req, "duration", "30s")
		dur, err := time.ParseDuration(durStr)
		if err != nil {
			dur = 30 * time.Second
		}
		if dur > 5*time.Minute {
			dur = 5 * time.Minute
		}

		// Create temp file for capture
		tmpFile := fmt.Sprintf("/tmp/pktanalyzer_capture_%d.pcapng", time.Now().UnixNano())

		// Capture packets
		capturer, err := capture.NewLiveCapturer(iface, bpf)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("open interface: %v", err)), nil
		}

		// Create PcapWriter to save captured packets
		writer, err := capture.NewPcapWriter(tmpFile)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("create pcap writer: %v", err)), nil
		}

		captured := 0
		deadline := time.After(dur)
		packets := capturer.Start()

	captureLoop:
		for {
			select {
			case pkt, ok := <-packets:
				if !ok {
					break captureLoop
				}
				// Write packet to pcap file
				if err := writer.WritePacket(&pkt); err != nil {
					// Log but don't fail — some packets may lack RawData
					continue
				}
				captured++
				if captured >= count {
					break captureLoop
				}
			case <-deadline:
				break captureLoop
			case <-ctx.Done():
				break captureLoop
			}
		}
		capturer.Stop()
		writer.Close()

		// Index the captured file
		_, err = ingest.IndexFile(tmpFile, nil)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("index capture: %v", err)), nil
		}

		// Open as active capture
		engine, err := query.NewFromPcap(tmpFile)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("open capture: %v", err)), nil
		}

		reader := replay.NewReader(tmpFile, nil)
		tc.SetCapture(engine, reader, tmpFile)

		overview, err := engine.GetOverview(ctx)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("get overview: %v", err)), nil
		}

		return mcp.NewToolResultText(toJSON(map[string]any{
			"status":   "captured",
			"packets":  captured,
			"path":     tmpFile,
			"overview": overview,
		})), nil
	}
}

// HandleListInterfaces lists available network interfaces.
func HandleListInterfaces(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ifaces, err := capture.ListInterfaces()
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("list interfaces: %v", err)), nil
		}

		type ifaceDTO struct {
			Name        string   `json:"name"`
			Description string   `json:"description,omitempty"`
			Addresses   []string `json:"addresses,omitempty"`
		}

		var result []ifaceDTO
		for _, iface := range ifaces {
			dto := ifaceDTO{
				Name:        iface.Name,
				Description: iface.Description,
			}
			for _, addr := range iface.Addresses {
				dto.Addresses = append(dto.Addresses, addr.IP.String())
			}
			result = append(result, dto)
		}

		return mcp.NewToolResultText(toJSON(map[string]any{
			"interfaces": result,
		})), nil
	}
}

// HandleGetOverview returns capture summary information.
func HandleGetOverview(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		engine := tc.GetQuery()
		if engine == nil {
			return toolError("NOT_FOUND", "no capture loaded — use open_pcap first"), nil
		}

		overview, err := engine.GetOverview(ctx)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("get overview: %v", err)), nil
		}

		return mcp.NewToolResultText(toJSON(overview)), nil
	}
}
