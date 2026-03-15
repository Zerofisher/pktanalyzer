package mcp

import (
	"context"
	"log/slog"

	"github.com/Zerofisher/pktanalyzer/mcp/tools"
	"github.com/Zerofisher/pktanalyzer/pkg/security"

	mcpLib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// WrapWithRedaction wraps a tool handler to apply output redaction.
func WrapWithRedaction(handler server.ToolHandlerFunc, tc *tools.ToolContext) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcpLib.CallToolRequest) (*mcpLib.CallToolResult, error) {
		result, err := handler(ctx, req)
		if err != nil {
			return result, err
		}
		if result == nil || result.IsError {
			return result, nil
		}

		cfg := security.RedactConfigFromSecurityConfig(tc.Security)
		if cfg == nil || !cfg.Enabled {
			return result, nil
		}

		// Redact text content
		for i, content := range result.Content {
			if textContent, ok := content.(mcpLib.TextContent); ok {
				textContent.Text = security.RedactText(textContent.Text, cfg)
				result.Content[i] = textContent
			}
		}

		return result, nil
	}
}

// LogToolCall logs each tool invocation for debugging.
func LogToolCall(name string, handler server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcpLib.CallToolRequest) (*mcpLib.CallToolResult, error) {
		slog.Debug("tool call", "tool", name, "args", req.Params.Arguments)
		result, err := handler(ctx, req)
		if err != nil {
			slog.Error("tool error", "tool", name, "error", err)
		}
		return result, err
	}
}
