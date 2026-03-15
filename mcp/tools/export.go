package tools

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Zerofisher/pktanalyzer/pkg/capture"
	"github.com/Zerofisher/pktanalyzer/pkg/filter"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
	"github.com/Zerofisher/pktanalyzer/pkg/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// RegisterExportTools registers the export tool.
func RegisterExportTools(s *server.MCPServer, tc *ToolContext) {
	s.AddTool(mcp.NewTool("export_packets",
		mcp.WithDescription("Export filtered packets as a new pcap file"),
		mcp.WithString("output_path", mcp.Required(), mcp.Description("Path for the output pcap file")),
		mcp.WithString("display_filter", mcp.Description("Wireshark display filter to select packets")),
		mcp.WithString("packet_numbers", mcp.Description("Comma-separated packet numbers to export")),
	), HandleExportPackets(tc))
}

func HandleExportPackets(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		engine := tc.GetQuery()
		if engine == nil {
			return toolError("NOT_FOUND", "no capture loaded"), nil
		}
		replayReader := tc.GetReplay()
		if replayReader == nil {
			return toolError("INTERNAL", "replay not available"), nil
		}

		outputPath, err := requiredString(req, "output_path")
		if err != nil {
			return toolError("INVALID_PARAM", err.Error()), nil
		}
		outputPath = security.ValidateStringParam(outputPath, 1024)

		displayFilter := optionalString(req, "display_filter", "")
		packetNumbers := optionalString(req, "packet_numbers", "")

		var packetsToExport []*capture.PacketInfo
		var truncated bool

		if packetNumbers != "" {
			// Export specific packet numbers
			for _, numStr := range strings.Split(packetNumbers, ",") {
				num, err := strconv.Atoi(strings.TrimSpace(numStr))
				if err != nil || num <= 0 {
					continue
				}
				pkt, err := engine.GetPacket(ctx, num)
				if err != nil || pkt.Evidence.FileOffset <= 0 {
					continue
				}
				info, err := replayReader.ReadPacket(pkt.Evidence)
				if err != nil {
					continue
				}
				info.Number = pkt.Number
				packetsToExport = append(packetsToExport, info)
			}
		} else {
			// Export all packets (optionally filtered)
			allPkts, err := engine.GetPackets(ctx, query.PacketFilter{
				Limit: tc.Security.MaxLimit,
			})
			if err != nil {
				return toolError("INTERNAL", fmt.Sprintf("query packets: %v", err)), nil
			}

			totalCount, _ := engine.GetPacketCount(ctx)
			truncated = totalCount > tc.Security.MaxLimit

			var filterFn func(*capture.PacketInfo) bool
			if displayFilter != "" {
				compiled, err := filter.Compile(displayFilter)
				if err != nil {
					return toolError("INVALID_PARAM", fmt.Sprintf("invalid filter: %v", err)), nil
				}
				filterFn = compiled
			}

			for _, pkt := range allPkts {
				if pkt.Evidence.FileOffset <= 0 {
					continue
				}
				info, err := replayReader.ReadPacket(pkt.Evidence)
				if err != nil {
					continue
				}
				info.Number = pkt.Number
				if filterFn != nil && !filterFn(info) {
					continue
				}
				packetsToExport = append(packetsToExport, info)
			}
		}

		if len(packetsToExport) == 0 {
			return toolError("NOT_FOUND", "no packets matched the criteria"), nil
		}

		// Write to pcap file
		writer, err := capture.NewPcapWriter(outputPath)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("create writer: %v", err)), nil
		}
		defer writer.Close()

		written := 0
		for _, info := range packetsToExport {
			if err := writer.WritePacket(info); err != nil {
				continue
			}
			written++
		}

		resp := map[string]any{
			"status":          "exported",
			"output_path":     outputPath,
			"packets_written": written,
		}
		if truncated {
			resp["warning"] = fmt.Sprintf("export truncated to %d packets (total: more)", tc.Security.MaxLimit)
		}
		return mcp.NewToolResultText(toJSON(resp)), nil
	}
}
