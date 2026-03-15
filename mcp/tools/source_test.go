package tools

import (
	"context"
	"testing"

	"github.com/Zerofisher/pktanalyzer/pkg/security"
	"github.com/mark3labs/mcp-go/mcp"
)

func TestHandleListInterfaces(t *testing.T) {
	tc := &ToolContext{Security: security.DefaultConfig()}
	handler := HandleListInterfaces(tc)
	req := mcp.CallToolRequest{}
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.IsError {
		t.Fatalf("tool returned error: %v", result)
	}
	// Should contain JSON with interfaces array
	text := result.Content[0].(mcp.TextContent).Text
	if text == "" {
		t.Error("empty response")
	}
}
