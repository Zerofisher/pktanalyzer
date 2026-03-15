// Package mcp provides the MCP server for pktanalyzer.
package mcp

import (
	"github.com/Zerofisher/pktanalyzer/mcp/tools"

	"github.com/mark3labs/mcp-go/server"
)

// ServerConfig holds MCP server configuration.
type ServerConfig struct {
	Transport string // "stdio" or "sse"
	Bind      string // SSE bind address
	Port      int    // SSE port
	Version   string // Server version
}

// NewPktAnalyzerServer creates a new MCP server with all tools registered.
func NewPktAnalyzerServer(tc *tools.ToolContext, cfg ServerConfig) *server.MCPServer {
	s := server.NewMCPServer(
		"pktanalyzer",
		cfg.Version,
		server.WithToolCapabilities(true),
		server.WithRecovery(),
	)

	tools.RegisterSourceTools(s, tc) // 4 tools
	tools.RegisterPacketTools(s, tc) // 5 tools
	tools.RegisterStreamTools(s, tc) // 5 tools
	tools.RegisterFieldTools(s, tc)  // 3 tools
	tools.RegisterExportTools(s, tc) // 1 tool

	return s
}
