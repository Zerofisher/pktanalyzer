package tools

import (
	"context"
	"fmt"
	"sort"

	"github.com/Zerofisher/pktanalyzer/pkg/fields"
	"github.com/Zerofisher/pktanalyzer/pkg/filter"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
	"github.com/Zerofisher/pktanalyzer/pkg/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// RegisterFieldTools registers the 3 field/filter tools.
func RegisterFieldTools(s *server.MCPServer, tc *ToolContext) {
	s.AddTool(mcp.NewTool("list_fields",
		mcp.WithDescription("List available protocol fields with types"),
		mcp.WithString("prefix", mcp.Description("Filter by prefix, e.g. 'tcp.'")),
	), HandleListFields(tc))

	s.AddTool(mcp.NewTool("extract_field",
		mcp.WithDescription("Extract a field value from a specific packet"),
		mcp.WithNumber("packet_number", mcp.Required(), mcp.Description("Packet number (1-based)")),
		mcp.WithString("field_name", mcp.Required(), mcp.Description("Field name, e.g. 'tcp.srcport'")),
	), HandleExtractField(tc))

	s.AddTool(mcp.NewTool("apply_display_filter",
		mcp.WithDescription("Apply Wireshark-compatible display filter expression"),
		mcp.WithString("expression", mcp.Required(), mcp.Description("Display filter, e.g. 'tcp.port == 80 && http'")),
		mcp.WithNumber("limit", mcp.Description("Max matching packets (default 50)")),
	), HandleApplyDisplayFilter(tc))
}

func HandleListFields(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		prefix := optionalString(req, "prefix", "")

		var fieldNames []string
		if prefix != "" {
			fieldNames = tc.Fields.ListByPrefix(prefix)
		} else {
			fieldNames = tc.Fields.List()
		}
		sort.Strings(fieldNames)

		type fieldDTO struct {
			Name        string `json:"name"`
			Description string `json:"description,omitempty"`
			Type        string `json:"type,omitempty"`
		}

		var result []fieldDTO
		for _, name := range fieldNames {
			fd := tc.Fields.Get(name)
			if fd == nil {
				continue
			}
			result = append(result, fieldDTO{
				Name:        fd.Name,
				Description: fd.Description,
				Type:        fieldTypeName(fd.Type),
			})
		}

		return mcp.NewToolResultText(toJSON(map[string]any{
			"count":  len(result),
			"fields": result,
		})), nil
	}
}

func HandleExtractField(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		engine := tc.GetQuery()
		if engine == nil {
			return toolError("NOT_FOUND", "no capture loaded"), nil
		}
		replayReader := tc.GetReplay()
		if replayReader == nil {
			return toolError("INTERNAL", "replay not available"), nil
		}

		number := optionalInt(req, "packet_number", 0)
		if number <= 0 {
			return toolError("INVALID_PARAM", "packet_number must be > 0"), nil
		}

		fieldName, err := requiredString(req, "field_name")
		if err != nil {
			return toolError("INVALID_PARAM", err.Error()), nil
		}
		fieldName = security.ValidateStringParam(fieldName, tc.Security.MaxStringLen)

		// Verify field exists
		fd := tc.Fields.Get(fieldName)
		if fd == nil {
			return toolError("NOT_FOUND", fmt.Sprintf("unknown field %q", fieldName)), nil
		}

		// Get packet from index
		pkt, err := engine.GetPacket(ctx, number)
		if err != nil {
			return toolError("NOT_FOUND", fmt.Sprintf("packet #%d not found", number)), nil
		}

		// Replay to get full PacketInfo
		if pkt.Evidence.FileOffset <= 0 {
			return toolError("INTERNAL", "packet has no raw data offset"), nil
		}
		info, err := replayReader.ReadPacket(pkt.Evidence)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("replay packet: %v", err)), nil
		}
		info.Number = pkt.Number

		// Extract field
		value, ok := tc.Fields.Extract(fieldName, info)
		if !ok {
			return mcp.NewToolResultText(toJSON(map[string]any{
				"packet_number": number,
				"field":         fieldName,
				"value":         nil,
				"present":       false,
			})), nil
		}

		return mcp.NewToolResultText(toJSON(map[string]any{
			"packet_number": number,
			"field":         fieldName,
			"value":         value,
			"present":       true,
		})), nil
	}
}

func HandleApplyDisplayFilter(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		engine := tc.GetQuery()
		if engine == nil {
			return toolError("NOT_FOUND", "no capture loaded"), nil
		}
		replayReader := tc.GetReplay()
		if replayReader == nil {
			return toolError("INTERNAL", "replay not available"), nil
		}

		expr, err := requiredString(req, "expression")
		if err != nil {
			return toolError("INVALID_PARAM", err.Error()), nil
		}
		expr = security.ValidateStringParam(expr, tc.Security.MaxStringLen)

		limit := optionalInt(req, "limit", 50)
		limit = security.ClampLimit(limit, tc.Security.MaxLimit)

		// Compile display filter
		compiled, err := filter.Compile(expr)
		if err != nil {
			return toolError("INVALID_PARAM", fmt.Sprintf("invalid filter: %v", err)), nil
		}

		// Get candidate packets from index (broad query)
		candidates, err := engine.GetPackets(ctx, query.PacketFilter{
			Limit: limit * 5, // over-fetch to account for post-filter
		})
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("query packets: %v", err)), nil
		}

		// Post-filter with display filter via replay
		var matchedPkts []any
		for _, pkt := range candidates {
			if pkt.Evidence.FileOffset <= 0 {
				continue
			}
			info, err := replayReader.ReadPacket(pkt.Evidence)
			if err != nil {
				continue
			}
			info.Number = pkt.Number
			if compiled(info) {
				matchedPkts = append(matchedPkts, pkt)
				if len(matchedPkts) >= limit {
					break
				}
			}
		}

		return mcp.NewToolResultText(toJSON(map[string]any{
			"expression": expr,
			"count":      len(matchedPkts),
			"packets":    matchedPkts,
		})), nil
	}
}

// fieldTypeName converts fields.FieldType to a human-readable string.
func fieldTypeName(ft fields.FieldType) string {
	switch ft {
	case fields.TypeString:
		return "string"
	case fields.TypeInt:
		return "int"
	case fields.TypeUint16:
		return "uint16"
	case fields.TypeUint32:
		return "uint32"
	case fields.TypeBool:
		return "bool"
	case fields.TypeBytes:
		return "bytes"
	case fields.TypeFloat:
		return "float"
	case fields.TypeTime:
		return "time"
	default:
		return "unknown"
	}
}
