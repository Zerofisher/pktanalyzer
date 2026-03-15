package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/Zerofisher/pktanalyzer/pkg/filter"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
	"github.com/Zerofisher/pktanalyzer/pkg/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// RegisterPacketTools registers the 5 packet tools.
func RegisterPacketTools(s *server.MCPServer, tc *ToolContext) {
	s.AddTool(mcp.NewTool("list_packets",
		mcp.WithDescription("List packets with pagination and sorting"),
		mcp.WithNumber("offset", mcp.Description("Pagination offset (default 0)")),
		mcp.WithNumber("limit", mcp.Description("Max results (default 50, max 200)")),
		mcp.WithString("sort_by", mcp.Description("Sort field: number, timestamp, protocol, length")),
		mcp.WithString("sort_order", mcp.Description("Sort order: asc or desc (default asc)")),
	), HandleListPackets(tc))

	s.AddTool(mcp.NewTool("filter_packets",
		mcp.WithDescription("Filter packets by various criteria"),
		mcp.WithString("src_ip", mcp.Description("Source IP address")),
		mcp.WithString("dst_ip", mcp.Description("Destination IP address")),
		mcp.WithNumber("src_port", mcp.Description("Source port")),
		mcp.WithNumber("dst_port", mcp.Description("Destination port")),
		mcp.WithNumber("port", mcp.Description("Either source or destination port")),
		mcp.WithString("protocol", mcp.Description("Protocol name (TCP, UDP, DNS, etc.)")),
		mcp.WithString("display_filter", mcp.Description("Wireshark-style display filter expression")),
		mcp.WithString("contains", mcp.Description("Substring search in packet info field")),
		mcp.WithNumber("offset", mcp.Description("Pagination offset")),
		mcp.WithNumber("limit", mcp.Description("Max results (default 50, max 200)")),
	), HandleFilterPackets(tc))

	s.AddTool(mcp.NewTool("get_packet",
		mcp.WithDescription("Get detailed analysis of a single packet"),
		mcp.WithNumber("number", mcp.Required(), mcp.Description("Packet number (1-based)")),
		mcp.WithBoolean("include_raw", mcp.Description("Include raw hex data (requires --enable-raw flag)")),
	), HandleGetPacket(tc))

	s.AddTool(mcp.NewTool("get_statistics",
		mcp.WithDescription("Protocol distribution, top IPs, top ports"),
		mcp.WithNumber("top_n", mcp.Description("Number of top entries (default 10)")),
	), HandleGetStatistics(tc))

	s.AddTool(mcp.NewTool("detect_anomalies",
		mcp.WithDescription("Detect anomalies using expert analysis engine"),
		mcp.WithNumber("min_severity", mcp.Description("Minimum severity: 1=note, 2=warning, 3=error, 4=critical")),
		mcp.WithString("categories", mcp.Description("Comma-separated categories: security,performance,tcp,dns,http,tls")),
		mcp.WithNumber("offset", mcp.Description("Pagination offset")),
		mcp.WithNumber("limit", mcp.Description("Max results")),
	), HandleDetectAnomalies(tc))
}

func HandleListPackets(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		engine := tc.GetQuery()
		if engine == nil {
			return toolError("NOT_FOUND", "no capture loaded"), nil
		}

		offset := optionalInt(req, "offset", 0)
		limit := optionalInt(req, "limit", 50)
		offset = security.ClampOffset(offset, tc.Security.MaxOffset)
		limit = security.ClampLimit(limit, tc.Security.MaxLimit)
		sortBy := optionalString(req, "sort_by", "")
		sortOrder := optionalString(req, "sort_order", "asc")

		packets, err := engine.GetPackets(ctx, query.PacketFilter{
			Offset:    offset,
			Limit:     limit,
			SortBy:    sortBy,
			SortOrder: sortOrder,
		})
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("query packets: %v", err)), nil
		}

		total, _ := engine.GetPacketCount(ctx)

		return mcp.NewToolResultText(toJSON(map[string]any{
			"total":   total,
			"offset":  offset,
			"limit":   limit,
			"packets": packets,
		})), nil
	}
}

func HandleFilterPackets(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		engine := tc.GetQuery()
		if engine == nil {
			return toolError("NOT_FOUND", "no capture loaded"), nil
		}

		offset := optionalInt(req, "offset", 0)
		limit := optionalInt(req, "limit", 50)
		offset = security.ClampOffset(offset, tc.Security.MaxOffset)
		limit = security.ClampLimit(limit, tc.Security.MaxLimit)

		f := query.PacketFilter{
			Offset:     offset,
			Limit:      limit,
			SrcIP:      security.ValidateStringParam(optionalString(req, "src_ip", ""), tc.Security.MaxStringLen),
			DstIP:      security.ValidateStringParam(optionalString(req, "dst_ip", ""), tc.Security.MaxStringLen),
			SrcPort:    optionalInt(req, "src_port", 0),
			DstPort:    optionalInt(req, "dst_port", 0),
			Port:       optionalInt(req, "port", 0),
			Protocol:   optionalString(req, "protocol", ""),
			SearchText: security.ValidateStringParam(optionalString(req, "contains", ""), tc.Security.MaxStringLen),
		}

		packets, err := engine.GetPackets(ctx, f)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("query packets: %v", err)), nil
		}

		// Post-filter with display filter if provided
		displayFilter := optionalString(req, "display_filter", "")
		if displayFilter != "" && tc.GetReplay() != nil {
			compiled, err := filter.Compile(displayFilter)
			if err != nil {
				return toolError("INVALID_PARAM", fmt.Sprintf("invalid display filter: %v", err)), nil
			}
			replayReader := tc.GetReplay()
			var matchedPackets []any
			for _, pkt := range packets {
				info, err := replayReader.ReadPacket(pkt.Evidence)
				if err != nil {
					continue
				}
				if compiled(info) {
					matchedPackets = append(matchedPackets, pkt)
				}
			}
			return mcp.NewToolResultText(toJSON(map[string]any{
				"total":          len(matchedPackets),
				"display_filter": displayFilter,
				"packets":        matchedPackets,
			})), nil
		}

		total, _ := engine.GetPacketCount(ctx)

		return mcp.NewToolResultText(toJSON(map[string]any{
			"total":   total,
			"offset":  offset,
			"limit":   limit,
			"packets": packets,
		})), nil
	}
}

func HandleGetPacket(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		engine := tc.GetQuery()
		if engine == nil {
			return toolError("NOT_FOUND", "no capture loaded"), nil
		}

		number := optionalInt(req, "number", 0)
		if number <= 0 {
			return toolError("INVALID_PARAM", "packet number must be > 0"), nil
		}
		includeRaw := optionalBool(req, "include_raw", false)

		pkt, err := engine.GetPacket(ctx, number)
		if err != nil {
			total, _ := engine.GetPacketCount(ctx)
			return toolError("NOT_FOUND", fmt.Sprintf("packet #%d not found (total: %d)", number, total)), nil
		}

		result := map[string]any{"packet": pkt}

		// Include raw data if requested and allowed
		if includeRaw {
			if !tc.Security.EnableRaw {
				return toolError("PERMISSION_DENIED", "raw packet data access requires --enable-raw flag"), nil
			}
			if tc.GetReplay() != nil && pkt.Evidence.FileOffset > 0 {
				info, err := tc.GetReplay().ReadPacket(pkt.Evidence)
				if err == nil && len(info.RawData) > 0 {
					maxBytes := tc.Security.RawMaxBytes
					data := info.RawData
					if len(data) > maxBytes {
						data = data[:maxBytes]
					}
					result["raw_hex"] = fmt.Sprintf("%x", data)
					result["raw_length"] = len(info.RawData)
				}
			}
		}

		return mcp.NewToolResultText(toJSON(result)), nil
	}
}

func HandleGetStatistics(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		engine := tc.GetQuery()
		if engine == nil {
			return toolError("NOT_FOUND", "no capture loaded"), nil
		}

		topN := optionalInt(req, "top_n", 10)
		topN = security.ClampInt(topN, 1, 100)

		protocols, err := engine.GetProtocolStats(ctx)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("protocol stats: %v", err)), nil
		}

		talkers, err := engine.GetTopTalkers(ctx, topN)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("top talkers: %v", err)), nil
		}

		return mcp.NewToolResultText(toJSON(map[string]any{
			"protocols":   protocols,
			"top_talkers": talkers,
		})), nil
	}
}

func HandleDetectAnomalies(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		engine := tc.GetQuery()
		if engine == nil {
			return toolError("NOT_FOUND", "no capture loaded"), nil
		}

		offset := optionalInt(req, "offset", 0)
		limit := optionalInt(req, "limit", 50)
		offset = security.ClampOffset(offset, tc.Security.MaxOffset)
		limit = security.ClampLimit(limit, tc.Security.MaxLimit)
		minSev := optionalInt(req, "min_severity", 0)

		var categories []string
		if c := optionalString(req, "categories", ""); c != "" {
			for _, cat := range splitComma(c) {
				categories = append(categories, cat)
			}
		}

		events, err := engine.GetExpertEvents(ctx, query.EventFilter{
			Offset:      offset,
			Limit:       limit,
			MinSeverity: minSev,
			Categories:  categories,
		})
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("query events: %v", err)), nil
		}

		return mcp.NewToolResultText(toJSON(map[string]any{
			"anomaly_count": len(events),
			"anomalies":     events,
		})), nil
	}
}

func splitComma(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
