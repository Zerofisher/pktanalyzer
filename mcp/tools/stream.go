package tools

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Zerofisher/pktanalyzer/pkg/query"
	"github.com/Zerofisher/pktanalyzer/pkg/security"
	"github.com/Zerofisher/pktanalyzer/pkg/stream"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// RegisterStreamTools registers the 5 stream tools.
func RegisterStreamTools(s *server.MCPServer, tc *ToolContext) {
	s.AddTool(mcp.NewTool("list_flows",
		mcp.WithDescription("List TCP/UDP flows with filtering and sorting"),
		mcp.WithString("ip", mcp.Description("Filter by IP address")),
		mcp.WithNumber("port", mcp.Description("Filter by port")),
		mcp.WithString("protocol", mcp.Description("Filter by protocol")),
		mcp.WithNumber("min_packets", mcp.Description("Minimum packet count")),
		mcp.WithString("sort_by", mcp.Description("Sort: packets, bytes, start_time, duration")),
		mcp.WithString("sort_order", mcp.Description("asc or desc (default desc)")),
		mcp.WithNumber("offset", mcp.Description("Pagination offset")),
		mcp.WithNumber("limit", mcp.Description("Max results")),
	), HandleListFlows(tc))

	s.AddTool(mcp.NewTool("get_flow",
		mcp.WithDescription("Get details of a single flow"),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow identifier")),
	), HandleGetFlow(tc))

	s.AddTool(mcp.NewTool("get_flow_packets",
		mcp.WithDescription("List packets within a flow"),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow identifier")),
		mcp.WithNumber("limit", mcp.Description("Max packets (default 50)")),
	), HandleGetFlowPackets(tc))

	s.AddTool(mcp.NewTool("reassemble_stream",
		mcp.WithDescription("TCP stream reassembly — reconstruct application-layer content"),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow identifier")),
		mcp.WithString("format", mcp.Description("Output format: text, hex, http (default text)")),
	), HandleReassembleStream(tc))

	s.AddTool(mcp.NewTool("follow_http",
		mcp.WithDescription("Follow HTTP session — parse request/response pairs"),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow identifier")),
	), HandleFollowHTTP(tc))
}

func HandleListFlows(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		engine := tc.GetQuery()
		if engine == nil {
			return toolError("NOT_FOUND", "no capture loaded"), nil
		}

		offset := optionalInt(req, "offset", 0)
		limit := optionalInt(req, "limit", 50)
		offset = security.ClampOffset(offset, tc.Security.MaxOffset)
		limit = security.ClampLimit(limit, tc.Security.MaxLimit)

		f := query.FlowFilter{
			Offset:     offset,
			Limit:      limit,
			IP:         optionalString(req, "ip", ""),
			Port:       optionalInt(req, "port", 0),
			Protocol:   optionalString(req, "protocol", ""),
			MinPackets: optionalInt(req, "min_packets", 0),
			SortBy:     optionalString(req, "sort_by", ""),
			SortOrder:  optionalString(req, "sort_order", "desc"),
		}

		flows, err := engine.GetFlows(ctx, f)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("query flows: %v", err)), nil
		}

		total, _ := engine.GetFlowCount(ctx)

		return mcp.NewToolResultText(toJSON(map[string]any{
			"total":  total,
			"offset": offset,
			"limit":  limit,
			"flows":  flows,
		})), nil
	}
}

func HandleGetFlow(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		engine := tc.GetQuery()
		if engine == nil {
			return toolError("NOT_FOUND", "no capture loaded"), nil
		}

		flowID, err := requiredString(req, "flow_id")
		if err != nil {
			return toolError("INVALID_PARAM", err.Error()), nil
		}

		flow, err := engine.GetFlow(ctx, flowID)
		if err != nil {
			return toolError("NOT_FOUND", fmt.Sprintf("flow %q not found", flowID)), nil
		}

		return mcp.NewToolResultText(toJSON(flow)), nil
	}
}

func HandleGetFlowPackets(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		engine := tc.GetQuery()
		if engine == nil {
			return toolError("NOT_FOUND", "no capture loaded"), nil
		}

		flowID, err := requiredString(req, "flow_id")
		if err != nil {
			return toolError("INVALID_PARAM", err.Error()), nil
		}

		limit := optionalInt(req, "limit", 50)
		limit = security.ClampLimit(limit, tc.Security.MaxLimit)

		packets, err := engine.GetFlowPackets(ctx, flowID, limit)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("query flow packets: %v", err)), nil
		}

		return mcp.NewToolResultText(toJSON(map[string]any{
			"flow_id": flowID,
			"count":   len(packets),
			"packets": packets,
		})), nil
	}
}

func HandleReassembleStream(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		engine := tc.GetQuery()
		if engine == nil {
			return toolError("NOT_FOUND", "no capture loaded"), nil
		}
		replayReader := tc.GetReplay()
		if replayReader == nil {
			return toolError("INTERNAL", "replay not available"), nil
		}

		flowID, err := requiredString(req, "flow_id")
		if err != nil {
			return toolError("INVALID_PARAM", err.Error()), nil
		}
		format := optionalString(req, "format", "text")

		// Get flow packets from index
		packets, err := engine.GetFlowPackets(ctx, flowID, 1000)
		if err != nil || len(packets) == 0 {
			return toolError("NOT_FOUND", fmt.Sprintf("no packets for flow %q", flowID)), nil
		}

		// Replay raw packets
		infos, err := replayReader.ReadFlowPackets(packets)
		if err != nil {
			return toolError("INTERNAL", fmt.Sprintf("replay packets: %v", err)), nil
		}

		if len(infos) == 0 {
			return toolError("NOT_FOUND", "no packets with raw data available for replay"), nil
		}

		// Reassemble TCP stream
		var fwdBuf, bwdBuf *stream.ReassemblyBuffer
		firstPkt := infos[0]
		fwdKey := firstPkt.SrcIP + ":" + firstPkt.SrcPort
		fwdBuf = stream.NewReassemblyBuffer(firstPkt.TCPSeq)

		for _, info := range infos {
			key := info.SrcIP + ":" + info.SrcPort
			if len(info.TCPPayload) == 0 {
				continue
			}
			if key == fwdKey {
				fwdBuf.AddSegment(info.TCPSeq, info.TCPPayload, info.Timestamp)
			} else {
				if bwdBuf == nil {
					bwdBuf = stream.NewReassemblyBuffer(info.TCPSeq)
				}
				bwdBuf.AddSegment(info.TCPSeq, info.TCPPayload, info.Timestamp)
			}
		}

		fwdData := fwdBuf.GetAssembled()
		var bwdData []byte
		if bwdBuf != nil {
			bwdData = bwdBuf.GetAssembled()
		}

		switch format {
		case "hex":
			return mcp.NewToolResultText(toJSON(map[string]any{
				"flow_id":      flowID,
				"format":       "hex",
				"forward_hex":  hex.EncodeToString(fwdData),
				"backward_hex": hex.EncodeToString(bwdData),
			})), nil
		case "http":
			return reassembleHTTP(flowID, fwdBuf, bwdBuf)
		default: // text
			return mcp.NewToolResultText(toJSON(map[string]any{
				"flow_id":        flowID,
				"format":         "text",
				"forward_text":   sanitizeText(fwdData),
				"backward_text":  sanitizeText(bwdData),
				"forward_bytes":  len(fwdData),
				"backward_bytes": len(bwdData),
			})), nil
		}
	}
}

func HandleFollowHTTP(tc *ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Inject format=http into the arguments and delegate to reassemble_stream.
		// GetArguments() returns the underlying map, so mutation is visible
		// to the downstream handler's optionalString call.
		args := req.GetArguments()
		if args == nil {
			// If arguments is nil, we need to set it to a new map
			req.Params.Arguments = map[string]any{"format": "http"}
		} else {
			args["format"] = "http"
		}
		return HandleReassembleStream(tc)(ctx, req)
	}
}

func reassembleHTTP(flowID string, fwdBuf, bwdBuf *stream.ReassemblyBuffer) (*mcp.CallToolResult, error) {
	// Build a TCPStream for the HTTPParser
	tcpStream := &stream.TCPStream{
		Key:        flowID,
		ClientData: fwdBuf,
		ServerData: bwdBuf,
	}
	// If backward buffer was nil, create an empty one so ParseStream doesn't panic
	if tcpStream.ServerData == nil {
		tcpStream.ServerData = stream.NewReassemblyBuffer(0)
	}

	parser := stream.NewHTTPParser()
	parser.ParseStream(tcpStream)

	type httpMsgDTO struct {
		Method      string            `json:"method,omitempty"`
		URI         string            `json:"uri,omitempty"`
		StatusCode  int               `json:"status_code,omitempty"`
		StatusText  string            `json:"status_text,omitempty"`
		Version     string            `json:"version"`
		Headers     map[string]string `json:"headers"`
		BodySize    int               `json:"body_size"`
		BodyPreview string            `json:"body_preview,omitempty"`
	}

	type httpPair struct {
		Request  *httpMsgDTO `json:"request,omitempty"`
		Response *httpMsgDTO `json:"response,omitempty"`
	}

	toDTO := func(msg *stream.HTTPMessage) *httpMsgDTO {
		preview := string(msg.Body)
		if len(preview) > 500 {
			preview = preview[:500] + "..."
		}
		return &httpMsgDTO{
			Method:      msg.Method,
			URI:         msg.URI,
			StatusCode:  msg.StatusCode,
			StatusText:  msg.StatusText,
			Version:     msg.Version,
			Headers:     msg.Headers,
			BodySize:    len(msg.Body),
			BodyPreview: preview,
		}
	}

	var pairs []httpPair
	maxLen := len(parser.Requests)
	if len(parser.Responses) > maxLen {
		maxLen = len(parser.Responses)
	}
	for i := range maxLen {
		pair := httpPair{}
		if i < len(parser.Requests) {
			pair.Request = toDTO(&parser.Requests[i])
		}
		if i < len(parser.Responses) {
			pair.Response = toDTO(&parser.Responses[i])
		}
		pairs = append(pairs, pair)
	}

	return mcp.NewToolResultText(toJSON(map[string]any{
		"flow_id":         flowID,
		"format":          "http",
		"pairs":           pairs,
		"total_requests":  len(parser.Requests),
		"total_responses": len(parser.Responses),
	})), nil
}

func sanitizeText(data []byte) string {
	maxSize := 10000
	if len(data) > maxSize {
		data = data[:maxSize]
	}
	var b strings.Builder
	for _, c := range data {
		if c >= 32 && c < 127 || c == '\n' || c == '\r' || c == '\t' {
			b.WriteByte(c)
		} else {
			b.WriteByte('.')
		}
	}
	return b.String()
}
