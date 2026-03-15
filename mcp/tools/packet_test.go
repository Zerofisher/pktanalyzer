package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Zerofisher/pktanalyzer/pkg/security"
	"github.com/mark3labs/mcp-go/mcp"
)

// setArgs sets the arguments on a CallToolRequest for testing.
func setArgs(t *testing.T, req *mcp.CallToolRequest, args map[string]any) {
	t.Helper()
	req.Params.Arguments = args
}

func TestHandleListPackets(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleListPackets(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"offset": float64(0),
		"limit":  float64(10),
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool error: %v", result.Content[0].(mcp.TextContent).Text)
	}

	// Parse response
	var resp map[string]any
	text := result.Content[0].(mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := resp["packets"]; !ok {
		t.Error("response missing 'packets' key")
	}
	if _, ok := resp["total"]; !ok {
		t.Error("response missing 'total' key")
	}
}

func TestHandleListPackets_NoCapture(t *testing.T) {
	tc := &ToolContext{Security: defaultSec()}
	handler := HandleListPackets(tc)

	req := mcp.CallToolRequest{}
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for no capture loaded")
	}
}

func TestHandleFilterPackets(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleFilterPackets(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"limit": float64(5),
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool error: %v", result.Content[0].(mcp.TextContent).Text)
	}

	var resp map[string]any
	text := result.Content[0].(mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := resp["packets"]; !ok {
		t.Error("response missing 'packets' key")
	}
}

func TestHandleGetPacket(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleGetPacket(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"number": float64(1),
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool error: %v", result.Content[0].(mcp.TextContent).Text)
	}

	var resp map[string]any
	text := result.Content[0].(mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := resp["packet"]; !ok {
		t.Error("response missing 'packet' key")
	}
}

func TestHandleGetPacket_InvalidNumber(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleGetPacket(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"number": float64(0),
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid packet number")
	}
}

func TestHandleGetPacket_RawDenied(t *testing.T) {
	tc := setupTestContext(t)
	// EnableRaw is false by default
	handler := HandleGetPacket(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"number":      float64(1),
		"include_raw": true,
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when raw access is disabled")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !contains(text, "PERMISSION_DENIED") {
		t.Errorf("expected PERMISSION_DENIED, got: %s", text)
	}
}

func TestHandleGetStatistics(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleGetStatistics(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"top_n": float64(5),
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool error: %v", result.Content[0].(mcp.TextContent).Text)
	}

	var resp map[string]any
	text := result.Content[0].(mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := resp["protocols"]; !ok {
		t.Error("response missing 'protocols' key")
	}
	if _, ok := resp["top_talkers"]; !ok {
		t.Error("response missing 'top_talkers' key")
	}
}

func TestHandleDetectAnomalies(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleDetectAnomalies(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"limit": float64(10),
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool error: %v", result.Content[0].(mcp.TextContent).Text)
	}

	var resp map[string]any
	text := result.Content[0].(mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := resp["anomaly_count"]; !ok {
		t.Error("response missing 'anomaly_count' key")
	}
}

func TestSplitComma(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"tcp", 1},
		{"tcp,dns,http", 3},
		{"tcp, dns , http", 3},
		{",,,", 0},
	}
	for _, tt := range tests {
		got := splitComma(tt.input)
		if len(got) != tt.want {
			t.Errorf("splitComma(%q) = %d items, want %d", tt.input, len(got), tt.want)
		}
	}
}

// contains checks if a string contains a substring (test helper).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// defaultSec returns a default security config for tests.
func defaultSec() *security.Config {
	return security.DefaultConfig()
}
