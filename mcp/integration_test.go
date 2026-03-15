package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zerofisher/pktanalyzer/mcp/tools"
	"github.com/Zerofisher/pktanalyzer/pkg/ingest"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
	"github.com/Zerofisher/pktanalyzer/pkg/replay"
	"github.com/Zerofisher/pktanalyzer/pkg/security"

	mcpLib "github.com/mark3labs/mcp-go/mcp"
)

// findTestPcap locates a test pcap file by walking up directories.
// Prefers .pcap (classic) over .pcapng since replay works better with classic pcap.
func findTestPcap(t *testing.T) string {
	t.Helper()
	dir, _ := os.Getwd()
	for i := 0; i < 5; i++ {
		// Look for classic .pcap first (exclude .pcapng)
		pattern := filepath.Join(dir, "examples", "*.pcap")
		matches, _ := filepath.Glob(pattern)
		var classicPcaps []string
		for _, m := range matches {
			if !strings.HasSuffix(m, ".pcapng") {
				classicPcaps = append(classicPcaps, m)
			}
		}
		if len(classicPcaps) > 0 {
			return classicPcaps[0]
		}
		// Fall back to .pcapng
		ngPattern := filepath.Join(dir, "examples", "*.pcapng")
		ngMatches, _ := filepath.Glob(ngPattern)
		if len(ngMatches) > 0 {
			return ngMatches[0]
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("no test pcap found in examples/")
	return ""
}

// setupIntegration creates a ToolContext backed by a real pcap for integration tests.
func setupIntegration(t *testing.T) *tools.ToolContext {
	t.Helper()
	pcapPath := findTestPcap(t)

	needsIndex, _ := ingest.NeedsReindex(pcapPath)
	if needsIndex {
		_, err := ingest.IndexFile(pcapPath, func(p, total int, d time.Duration) {})
		if err != nil {
			t.Fatalf("index: %v", err)
		}
	}

	engine, err := query.NewFromPcap(pcapPath)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { engine.Close() })

	reader := replay.NewReader(pcapPath, nil)
	tc := tools.NewToolContext(engine, reader, security.DefaultConfig())
	tc.PcapPath = pcapPath
	return tc
}

// TestIntegration_AllToolsRegistered verifies that all expected tools are registered
// through the full MCP server pipeline (HandleMessage → tools/list).
func TestIntegration_AllToolsRegistered(t *testing.T) {
	tc := setupIntegration(t)
	s := NewPktAnalyzerServer(tc, ServerConfig{Version: "test"})

	// Send tools/list request through HandleMessage
	ctx := context.Background()
	resp := s.HandleMessage(ctx, json.RawMessage(`{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "tools/list"
	}`))

	// Marshal the response back to JSON and re-parse.
	// We use JSON round-trip because JSONRPCResponse.Result is typed `any`,
	// so direct type assertion to ListToolsResult may not work from outside the package.
	respJSON, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var parsed struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respJSON, &parsed); err != nil {
		t.Fatalf("unmarshal response: %v\nraw: %s", err, string(respJSON))
	}
	if parsed.Error != nil {
		t.Fatalf("got error response (code=%d): %s", parsed.Error.Code, parsed.Error.Message)
	}

	// 4 source + 5 packet + 5 stream + 3 field + 1 export = 18 tools
	expectedTools := []string{
		// source tools (4)
		"open_pcap", "capture_live", "list_interfaces", "get_overview",
		// packet tools (5)
		"list_packets", "filter_packets", "get_packet", "get_statistics", "detect_anomalies",
		// stream tools (5)
		"list_flows", "get_flow", "get_flow_packets", "reassemble_stream", "follow_http",
		// field tools (3)
		"list_fields", "extract_field", "apply_display_filter",
		// export tools (1)
		"export_packets",
	}

	registeredNames := make(map[string]bool)
	for _, tool := range parsed.Result.Tools {
		registeredNames[tool.Name] = true
	}

	for _, name := range expectedTools {
		if !registeredNames[name] {
			t.Errorf("tool %q not registered", name)
		}
	}
	t.Logf("registered %d tools (expected %d)", len(parsed.Result.Tools), len(expectedTools))
}

// TestIntegration_GetOverview verifies that get_overview returns valid JSON
// with capture summary data.
func TestIntegration_GetOverview(t *testing.T) {
	tc := setupIntegration(t)
	handler := tools.HandleGetOverview(tc)

	result, err := handler(context.Background(), mcpLib.CallToolRequest{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool error: %v", result.Content[0].(mcpLib.TextContent).Text)
	}

	var resp map[string]any
	text := result.Content[0].(mcpLib.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v\nraw: %s", err, text)
	}
	if len(resp) == 0 {
		t.Error("overview response is empty")
	}
	t.Logf("overview keys: %v", mapKeys(resp))
}

// TestIntegration_ListPacketsThenGetPacket verifies the list→detail pipeline:
// list_packets returns packets, then get_packet returns details for the first one.
func TestIntegration_ListPacketsThenGetPacket(t *testing.T) {
	tc := setupIntegration(t)

	// Step 1: List packets
	listHandler := tools.HandleListPackets(tc)
	listReq := mcpLib.CallToolRequest{}
	listReq.Params.Arguments = map[string]any{"limit": float64(5)}

	listResult, err := listHandler(context.Background(), listReq)
	if err != nil {
		t.Fatalf("list_packets error: %v", err)
	}
	if listResult.IsError {
		t.Skipf("list_packets returned error: %s", listResult.Content[0].(mcpLib.TextContent).Text)
	}

	var listResp map[string]any
	text := listResult.Content[0].(mcpLib.TextContent).Text
	if err := json.Unmarshal([]byte(text), &listResp); err != nil {
		t.Fatalf("invalid list_packets JSON: %v", err)
	}

	packets, ok := listResp["packets"].([]any)
	if !ok || len(packets) == 0 {
		t.Skip("no packets returned by list_packets")
	}
	t.Logf("list_packets returned %d packets", len(packets))

	// Step 2: Get the first packet's details
	firstPkt, ok := packets[0].(map[string]any)
	if !ok {
		t.Fatal("first packet is not a JSON object")
	}
	number, ok := firstPkt["number"].(float64)
	if !ok {
		t.Fatal("packet 'number' field not found or not a number")
	}

	getHandler := tools.HandleGetPacket(tc)
	getReq := mcpLib.CallToolRequest{}
	getReq.Params.Arguments = map[string]any{"number": number}

	getResult, err := getHandler(context.Background(), getReq)
	if err != nil {
		t.Fatalf("get_packet error: %v", err)
	}
	if getResult.IsError {
		t.Errorf("get_packet failed for packet #%d: %s",
			int(number), getResult.Content[0].(mcpLib.TextContent).Text)
		return
	}

	var getResp map[string]any
	getText := getResult.Content[0].(mcpLib.TextContent).Text
	if err := json.Unmarshal([]byte(getText), &getResp); err != nil {
		t.Fatalf("invalid get_packet JSON: %v", err)
	}
	if _, ok := getResp["packet"]; !ok {
		t.Error("get_packet response missing 'packet' key")
	}
	t.Logf("get_packet #%d succeeded, keys: %v", int(number), mapKeys(getResp))
}

// TestIntegration_ToolCallViaHandleMessage verifies that tools/call dispatches
// correctly through the full HandleMessage pipeline.
func TestIntegration_ToolCallViaHandleMessage(t *testing.T) {
	tc := setupIntegration(t)
	s := NewPktAnalyzerServer(tc, ServerConfig{Version: "test"})

	ctx := context.Background()
	resp := s.HandleMessage(ctx, json.RawMessage(`{
		"jsonrpc": "2.0",
		"id": 2,
		"method": "tools/call",
		"params": {
			"name": "get_overview"
		}
	}`))

	respJSON, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var parsed struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respJSON, &parsed); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, string(respJSON))
	}
	if parsed.Error != nil {
		t.Fatalf("got JSON-RPC error (code=%d): %s", parsed.Error.Code, parsed.Error.Message)
	}
	if parsed.Result.IsError {
		t.Fatalf("tool returned error: %s", parsed.Result.Content[0].Text)
	}
	if len(parsed.Result.Content) == 0 {
		t.Fatal("no content in tool call response")
	}

	// Verify the content is valid JSON
	var overview map[string]any
	if err := json.Unmarshal([]byte(parsed.Result.Content[0].Text), &overview); err != nil {
		t.Fatalf("tool output is not valid JSON: %v", err)
	}
	t.Logf("get_overview via HandleMessage succeeded, keys: %v", mapKeys(overview))
}

// mapKeys returns the keys of a map for logging.
func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
