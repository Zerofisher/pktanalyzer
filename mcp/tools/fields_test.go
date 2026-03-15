package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Zerofisher/pktanalyzer/pkg/fields"
	"github.com/mark3labs/mcp-go/mcp"
)

func TestHandleListFields(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleListFields(tc)

	req := mcp.CallToolRequest{}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool error: %v", result.Content[0].(mcp.TextContent).Text)
	}

	var resp map[string]any
	text := result.Content[0].(mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	fields, ok := resp["fields"].([]any)
	if !ok || len(fields) == 0 {
		t.Error("expected non-empty fields list")
	}
}

func TestHandleListFields_WithPrefix(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleListFields(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{"prefix": "tcp."})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	var resp map[string]any
	text := result.Content[0].(mcp.TextContent).Text
	json.Unmarshal([]byte(text), &resp)
	fields := resp["fields"].([]any)
	for _, f := range fields {
		fm := f.(map[string]any)
		name := fm["name"].(string)
		if len(name) < 4 || name[:4] != "tcp." {
			t.Errorf("expected tcp. prefix, got %q", name)
		}
	}
}

func TestHandleExtractField_NoCapture(t *testing.T) {
	tc := &ToolContext{
		Security: defaultSec(),
		Fields:   fields.NewRegistry(),
	}
	handler := HandleExtractField(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"packet_number": float64(1),
		"field_name":    "ip.src",
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for no capture loaded")
	}
}

func TestHandleExtractField_InvalidNumber(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleExtractField(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"packet_number": float64(0),
		"field_name":    "ip.src",
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid packet number")
	}
}

func TestHandleExtractField_UnknownField(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleExtractField(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"packet_number": float64(1),
		"field_name":    "nonexistent.field",
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for unknown field")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !contains(text, "NOT_FOUND") {
		t.Errorf("expected NOT_FOUND, got: %s", text)
	}
}

func TestHandleApplyDisplayFilter_NoCapture(t *testing.T) {
	tc := &ToolContext{Security: defaultSec()}
	handler := HandleApplyDisplayFilter(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"expression": "is_tcp",
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for no capture loaded")
	}
}

func TestHandleApplyDisplayFilter_InvalidExpression(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleApplyDisplayFilter(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"expression": "invalid ??? filter !!!",
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid filter expression")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !contains(text, "INVALID_PARAM") {
		t.Errorf("expected INVALID_PARAM, got: %s", text)
	}
}
