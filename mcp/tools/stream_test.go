package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestHandleListFlows(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleListFlows(tc)

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

	var resp map[string]any
	text := result.Content[0].(mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := resp["flows"]; !ok {
		t.Error("response missing 'flows' key")
	}
	if _, ok := resp["total"]; !ok {
		t.Error("response missing 'total' key")
	}
}

func TestHandleListFlows_NoCapture(t *testing.T) {
	tc := &ToolContext{Security: defaultSec()}
	handler := HandleListFlows(tc)

	req := mcp.CallToolRequest{}
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for no capture loaded")
	}
}

func TestHandleGetFlow_NoCapture(t *testing.T) {
	tc := &ToolContext{Security: defaultSec()}
	handler := HandleGetFlow(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"flow_id": "nonexistent",
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for no capture loaded")
	}
}

func TestHandleGetFlow_MissingFlowID(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleGetFlow(tc)

	req := mcp.CallToolRequest{}
	// No flow_id set

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing flow_id")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !contains(text, "INVALID_PARAM") {
		t.Errorf("expected INVALID_PARAM, got: %s", text)
	}
}

func TestHandleGetFlowPackets_NoCapture(t *testing.T) {
	tc := &ToolContext{Security: defaultSec()}
	handler := HandleGetFlowPackets(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"flow_id": "some-flow",
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for no capture loaded")
	}
}

func TestHandleReassembleStream_NoCapture(t *testing.T) {
	tc := &ToolContext{Security: defaultSec()}
	handler := HandleReassembleStream(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"flow_id": "some-flow",
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for no capture loaded")
	}
}

func TestHandleFollowHTTP_NoCapture(t *testing.T) {
	tc := &ToolContext{Security: defaultSec()}
	handler := HandleFollowHTTP(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"flow_id": "some-flow",
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for no capture loaded")
	}
}

func TestSanitizeText(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "printable ASCII",
			input: []byte("Hello, World!"),
			want:  "Hello, World!",
		},
		{
			name:  "with control chars",
			input: []byte("line1\r\nline2\ttab\x00null\x01soh"),
			want:  "line1\r\nline2\ttab.null.soh",
		},
		{
			name:  "empty",
			input: []byte{},
			want:  "",
		},
		{
			name:  "binary data",
			input: []byte{0x00, 0x01, 0x80, 0xFF},
			want:  "....",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeText(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeText(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeText_Truncation(t *testing.T) {
	// Create data larger than 10000 bytes
	data := make([]byte, 20000)
	for i := range data {
		data[i] = 'A'
	}
	result := sanitizeText(data)
	if len(result) != 10000 {
		t.Errorf("expected truncated length 10000, got %d", len(result))
	}
}
