// Package tools provides MCP tool handlers for the pktanalyzer MCP server.
package tools

import (
	"encoding/json"
	"sync"

	"github.com/Zerofisher/pktanalyzer/pkg/fields"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
	"github.com/Zerofisher/pktanalyzer/pkg/replay"
	"github.com/Zerofisher/pktanalyzer/pkg/security"
)

// ToolContext holds shared dependencies for all MCP tool handlers.
// A single instance is created at server startup and passed to each handler.
type ToolContext struct {
	mu       sync.RWMutex
	Query    query.QueryEngine // Structured queries on indexed data
	Replay   *replay.Reader    // Re-read raw packets for full PacketInfo
	Fields   *fields.Registry  // Field extraction
	Security *security.Config  // Security configuration
	PcapPath string            // Current pcap file path
}

// NewToolContext creates a ToolContext with the given dependencies.
func NewToolContext(engine query.QueryEngine, replayReader *replay.Reader, sec *security.Config) *ToolContext {
	return &ToolContext{
		Query:    engine,
		Replay:   replayReader,
		Fields:   fields.NewRegistry(),
		Security: sec,
	}
}

// SetCapture replaces the active capture (used by open_pcap and capture_live).
func (tc *ToolContext) SetCapture(engine query.QueryEngine, replayReader *replay.Reader, pcapPath string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Close previous engine if it implements io.Closer
	if closer, ok := tc.Query.(interface{ Close() error }); ok {
		closer.Close()
	}

	tc.Query = engine
	tc.Replay = replayReader
	tc.PcapPath = pcapPath
}

// GetQuery returns the current QueryEngine (thread-safe).
func (tc *ToolContext) GetQuery() query.QueryEngine {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.Query
}

// GetReplay returns the current replay Reader (thread-safe).
func (tc *ToolContext) GetReplay() *replay.Reader {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.Replay
}

// toJSON marshals v to a JSON string. Panics are caught by mcp-go recovery.
func toJSON(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return `{"error":"json_marshal_failed"}`
	}
	return string(data)
}
