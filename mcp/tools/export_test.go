package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestHandleExportPackets(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleExportPackets(tc)

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "exported.pcapng")

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"output_path":    outPath,
		"packet_numbers": "1,2,3",
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool error: %s", result.Content[0].(mcp.TextContent).Text)
	}

	var resp map[string]any
	text := result.Content[0].(mcp.TextContent).Text
	json.Unmarshal([]byte(text), &resp)

	// Verify file was created
	if _, err := os.Stat(outPath); os.IsNotExist(err) {
		t.Error("export file not created")
	}

	// Verify response structure
	if resp["status"] != "exported" {
		t.Errorf("expected status=exported, got %v", resp["status"])
	}
	if resp["output_path"] != outPath {
		t.Errorf("expected output_path=%s, got %v", outPath, resp["output_path"])
	}
}

func TestHandleExportPackets_NoCapture(t *testing.T) {
	tc := &ToolContext{Security: defaultSec()}
	handler := HandleExportPackets(tc)

	req := mcp.CallToolRequest{}
	setArgs(t, &req, map[string]any{
		"output_path":    "/tmp/test.pcapng",
		"packet_numbers": "1,2,3",
	})

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for no capture loaded")
	}
}

func TestHandleExportPackets_MissingOutputPath(t *testing.T) {
	tc := setupTestContext(t)
	handler := HandleExportPackets(tc)

	req := mcp.CallToolRequest{}
	// No output_path set

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing output_path")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !contains(text, "INVALID_PARAM") {
		t.Errorf("expected INVALID_PARAM, got: %s", text)
	}
}
