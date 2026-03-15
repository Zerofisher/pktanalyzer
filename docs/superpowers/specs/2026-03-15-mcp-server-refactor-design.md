# PktAnalyzer MCP Server Refactor Design

Date: 2026-03-15
Status: Approved

## Goal

Refactor pktanalyzer from a CLI/TUI packet analyzer with built-in AI agent into an **MCP (Model Context Protocol) server** that exposes packet analysis capabilities as structured tools. External AI agents (Claude Code, Cursor, etc.) connect via MCP to safely analyze network traffic without needing raw shell access to tshark.

## Motivation

AI agents can already run tshark directly. What they lack is:

- **Structured data access**: tshark output is unstructured text that wastes tokens and loses information.
- **Security guardrails**: direct shell access to packet data has no safety boundaries.
- **Composable analysis**: TCP reassembly, TLS decryption, anomaly detection as callable tools rather than CLI pipelines.

PktAnalyzer's existing core libraries (capture, stream, tls, fields, filter, expert) provide all the analysis capability. The refactoring replaces the presentation layer (TUI, REST API, built-in AI agent) with a single MCP server transport.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| External interface | MCP Server (stdio + SSE) | AI-native protocol, supported by Claude Code, Cursor, etc. |
| MCP SDK | `github.com/mark3labs/mcp-go` | High reputation, 580+ snippets, active community |
| Modules to remove | `ui/`, `agent/`, `internal/api/`, `web/`, `internal/report/`, `internal/app/`, `cmd/read.go`, `cmd/capture.go`, `cmd/follow.go`, `cmd/stats.go`, `cmd/serve.go`, `cmd/report.go` | Replaced by MCP server; built-in LLM integration not needed when external agents call tools |
| Modules to keep | `capture/`, `stream/`, `tls/`, `fields/`, `filter/`, `expert/`, `stats/`, `export/`, `pkg/*` | Core analysis libraries, reused by MCP tool handlers |
| Security model | Startup-time configuration (flags) | No interactive TUI for authorization; policy set at launch |
| Output format | Structured JSON | AI agents parse JSON reliably; replaces formatted text output |
| Refactoring strategy | One-shot refactor on a feature branch | Clean break; remove unused modules, reorganize package structure |

## Directory Structure

```
pktanalyzer/
├── main.go                          # Entry point: cmd.Execute()
├── cmd/
│   ├── root.go                      # Root command with two subcommands
│   ├── mcp.go                       # `pktanalyzer mcp <pcap> [flags]`
│   └── list.go                      # `pktanalyzer list interfaces`
│
├── mcp/                             # MCP server layer
│   ├── server.go                    # Server creation, tool registration, transport selection
│   ├── tools/
│   │   ├── context.go               # ToolContext: shared dependency container
│   │   ├── source.go                # open_pcap, capture_live, list_interfaces, get_overview
│   │   ├── packet.go                # list_packets, filter_packets, get_packet, get_statistics, detect_anomalies
│   │   ├── stream.go                # list_flows, get_flow, get_flow_packets, reassemble_stream, follow_http
│   │   ├── fields.go                # list_fields, extract_field, apply_display_filter
│   │   └── export.go                # export_packets
│   └── middleware.go                # Parameter validation, rate limiting, output redaction
│
├── pkg/                             # Pure libraries, no MCP/CLI dependency
│   ├── capture/                     # Packet parsing, protocol identification (from capture/)
│   ├── stream/                      # TCP reassembly, HTTP/HTTP2/WebSocket (from stream/)
│   ├── tls/                         # TLS parsing, keylog decryption (from tls/)
│   ├── fields/                      # Field registry (from fields/)
│   ├── filter/                      # Display filter engine (from filter/)
│   ├── expert/                      # Anomaly detection (from expert/)
│   ├── stats/                       # Traffic statistics (from stats/)
│   ├── export/                      # Pcap export (from export/)
│   ├── security/                    # Validation, redaction, rate limiting (from agent/security.go)
│   ├── replay/                      # NEW: raw packet replay from pcap (for stream reassembly and field extraction)
│   ├── ingest/                      # Pcap indexing to SQLite (existing)
│   ├── query/                       # Structured query engine (existing)
│   ├── store/                       # SQLite storage (existing)
│   └── model/                       # Data models (existing)
│
├── internal/
│   └── format/                      # Byte formatting utilities (existing)
│
├── examples/                        # Test pcap files (existing)
└── docs/
```

## MCP Tools

### Source Tools (4)

| Tool | Description | Parameters |
|---|---|---|
| `open_pcap` | Open and index a pcap/pcapng file. Replaces the currently loaded capture. Only one capture active at a time. | `path` (required) |
| `capture_live` | Start live capture. Blocks until `count` or `duration` reached, then indexes the result. Not a streaming operation. | `interface` (required), `filter` (BPF), `count` (default 1000), `duration` (default "30s") |
| `list_interfaces` | List available network interfaces | none |
| `get_overview` | Get capture overview: total packets, time span, protocol distribution. Maps to `QueryEngine.GetOverview()`. | none |

### Packet Tools (5)

| Tool | Description | Parameters |
|---|---|---|
| `list_packets` | List packets with pagination and sorting | `offset`, `limit`, `sort_by` (number/timestamp/protocol/length), `sort_order` (asc/desc) |
| `filter_packets` | Filter packets by criteria. `display_filter` is post-filtered: SQLite returns candidates, then `filter.Compile()` evaluates each against the expression. `contains` matches against the `info` field (maps to `PacketFilter.SearchText`). | `src_ip`, `dst_ip`, `src_port`, `dst_port`, `port` (bidirectional), `protocol`, `display_filter` (Wireshark syntax), `contains` (substring in info field) |
| `get_packet` | Get detailed analysis of a single packet (all layers) | `number` (required), `include_raw` (requires `--enable-raw` flag at startup) |
| `get_statistics` | Protocol distribution, top IPs, top ports. Uses `QueryEngine.GetProtocolStats()` and `QueryEngine.GetTopTalkers()`. | `top_n` (default 10) |
| `detect_anomalies` | Detect anomalies. Uses `QueryEngine.GetExpertEvents()` for indexed pcaps. | `min_severity` (1-4), `categories` (comma-separated) |

### Stream Tools (5)

| Tool | Description | Parameters |
|---|---|---|
| `list_flows` | List TCP/UDP flows via `QueryEngine.GetFlows()` | `ip`, `port`, `protocol`, `min_packets`, `sort_by` (packets/bytes/start_time/duration) |
| `get_flow` | Get details of a single flow via `QueryEngine.GetFlow()` | `flow_id` (required) |
| `get_flow_packets` | List packets within a flow via `QueryEngine.GetFlowPackets()` | `flow_id` (required), `limit` |
| `reassemble_stream` | TCP stream reassembly. Uses `pkg/replay` to read raw packets from pcap file by `PacketEvidence.FileOffset`, feed them through `pkg/stream` reassembler, return application-layer content. | `flow_id` (required), `format` (text/hex/http, default "text") |
| `follow_http` | Follow HTTP session. Built on `reassemble_stream` with `format=http`, parses request/response pairs. | `flow_id` (required) |

### Field Tools (3)

| Tool | Description | Parameters |
|---|---|---|
| `list_fields` | List all available fields with types from `fields.Registry` | `prefix` (optional, e.g. "tcp.") |
| `extract_field` | Extract field value from a packet. Uses `pkg/replay` to re-read and re-parse the raw packet into `capture.PacketInfo`, then calls `fields.Registry.Extract()`. | `packet_number` (required), `field_name` (required) |
| `apply_display_filter` | Apply Wireshark-compatible filter. Uses `QueryEngine.GetPackets()` for broad candidates, then post-filters with `filter.Compile()` via `pkg/replay` for full `PacketInfo` evaluation. | `expression` (required), `limit` |

### Export Tool (1)

| Tool | Description | Parameters |
|---|---|---|
| `export_packets` | Export filtered packets as a new pcap file. Uses `pkg/replay` to re-read raw packets, then `capture.PcapWriter` (existing in `capture/writer.go`) to write them. | `output_path` (required), `display_filter` (optional), `packet_numbers` (optional, comma-separated) |

### Removed from Current Agent Tools

| Current Tool | Reason for Removal |
|---|---|
| `explain_protocol` | Pure knowledge; AI agent answers this natively |
| `lookup_rfc` | AI agent capability, not packet analysis |
| `web_search` | AI agent capability, not packet analysis |

## Replay Pipeline (New)

Three tools (`reassemble_stream`, `extract_field`, `apply_display_filter`) need full `capture.PacketInfo` objects, but the SQLite index only stores `model.PacketSummary`. These tools use a new `pkg/replay` package:

```go
// pkg/replay/replay.go

// Reader re-reads raw packets from a pcap file using stored offsets.
// Optionally applies TLS decryption if a keylog decryptor is configured.
type Reader struct {
    pcapPath  string
    decryptor *tls.Decryptor // nil if no --keylog-file; used for TLS decryption during replay
}

// NewReader creates a replay reader. decryptor may be nil.
func NewReader(pcapPath string, decryptor *tls.Decryptor) *Reader

// ReadPacket reads a single raw packet from the pcap file at the given offset,
// parses it with gopacket, applies TLS decryption if configured,
// and returns a full capture.PacketInfo.
func (r *Reader) ReadPacket(evidence model.PacketEvidence) (*capture.PacketInfo, error)

// ReadFlowPackets reads all packets for a flow by their evidence offsets,
// returns them in order for reassembly.
func (r *Reader) ReadFlowPackets(packets []*model.PacketSummary) ([]*capture.PacketInfo, error)
```

**Contract**: The replay pipeline depends on `PacketEvidence.FileOffset` being populated during indexing. This is verified: `ingest/pipeline.go` stores `summary.Evidence.FileOffset = p.fileOffset`, `store/sqlite/sqlite.go` persists it, and `query/sqlite_engine.go` reads it back. If a packet has `FileOffset == 0`, `ReadPacket` returns an error.

The pipeline for `reassemble_stream`:
1. `QueryEngine.GetFlowPackets(flowID)` returns `[]*model.PacketSummary` with `PacketEvidence.FileOffset`
2. `replay.Reader.ReadFlowPackets()` seeks to each offset in the pcap, re-parses raw bytes into `[]*capture.PacketInfo`
3. Feed `PacketInfo` objects through `stream.Reassembler` to produce application-layer content

The pipeline for `extract_field` and `apply_display_filter`:
1. Get `PacketSummary` from QueryEngine
2. `replay.Reader.ReadPacket()` re-parses into `capture.PacketInfo`
3. Use `fields.Registry.Extract()` or `filter.Compile()` on the full `PacketInfo`

## Security Layer

### Architecture

```
MCP Request --> Parameter Validation --> Rate Limiting --> Data Access --> Output Redaction --> Response
```

### Configuration

All security settings are configured at server startup via CLI flags. No interactive authorization (since the caller is an AI agent, not a human at a TUI).

```go
// pkg/security/config.go
type Config struct {
    // Parameter limits
    MaxLimit     int  // Max items per query (default 200)
    MaxOffset    int  // Max offset value (default 10000)
    MaxStringLen int  // Max filter string length (default 500)

    // Raw data access
    EnableRaw    bool // Allow raw packet data access (default false)
    RawMaxBytes  int  // Max raw bytes per packet (default 1024)

    // TLS decryption
    KeylogFile   string // Path to SSLKEYLOGFILE for TLS decryption (default "")

    // Output redaction
    RedactIPs    bool // Redact IP addresses (default false)
    RedactMACs   bool // Redact MAC addresses (default false)
    RedactCreds  bool // Redact HTTP credentials (default false)

    // Rate limiting
    RateLimit    int  // Max tool calls per minute (default 100)
}
```

### Reused Security Code

From `agent/security.go`:

- `ClampInt()`, `ClampString()`, `ValidateLimit()`, `ValidateOffset()`, `ValidateStringParam()` -- parameter validation
- `RedactIP()`, `RedactMAC()`, `RedactHTTPHeader()`, `RedactQueryParams()` -- output redaction
- `RedactConfig` struct and `RedactText()` -- redaction pipeline

Removed:

- `AuthorizationStore`, `ConfirmationRequest` -- TUI-interactive authorization
- `CheckRawDataAuthorization()` -- replaced by simple flag check (`Config.EnableRaw`)
- `Evidence` struct -- evidence now embedded in structured JSON responses

### CLI Flags

```
pktanalyzer mcp <pcap-file> [flags]

Flags:
  --transport string      Transport: stdio (default), sse
  --port int              SSE listen port (default 8080)
  --bind string           SSE bind address (default "127.0.0.1")
  --live                  Live capture mode (no pcap file needed)
  --interface string      Capture interface (required with --live)
  --bpf string            BPF filter expression
  --keylog-file string    SSLKEYLOGFILE path for TLS decryption
  --enable-raw            Allow raw packet data access
  --raw-max-bytes int     Max raw bytes per packet (default 1024)
  --redact-ips            Redact IP addresses in output
  --redact-macs           Redact MAC addresses in output
  --redact-creds          Redact HTTP credentials in output
  --rate-limit int        Max tool calls per minute (default 100)
```

## Error Handling

### Error Categories

All tool handlers classify errors into two categories returned via MCP:

1. **User errors** (invalid parameters, resource not found): returned as `mcp.NewToolResultError()` with a descriptive message. The MCP connection stays alive.
2. **Internal errors** (file I/O failure, index corruption): returned as `mcp.NewToolResultError()` with a generic message. Details logged to stderr.

### Structured Error Responses

```json
{
  "error": "packet_not_found",
  "message": "Packet #99999 does not exist (total: 1523)",
  "code": "NOT_FOUND"
}
```

Error codes: `INVALID_PARAM`, `NOT_FOUND`, `PERMISSION_DENIED` (raw data without `--enable-raw`), `RATE_LIMITED`, `INTERNAL`.

### Middleware Error Pipeline

The middleware wraps each tool handler:
1. **Parameter validation** catches invalid/out-of-range values before the handler runs
2. **Rate limiter** returns `RATE_LIMITED` if exceeded
3. **Handler errors** are caught, classified, and formatted
4. **Panics** are recovered (mcp-go's `server.WithRecovery()`)

## Data Flow

```
AI Agent (Claude Code / Cursor / ...)
    |
    v
MCP Transport (stdio / SSE)
    |
    v
mcp/server.go -- tool dispatch
    |
    v
mcp/middleware.go -- parameter validation, rate limiting
    |
    v
mcp/tools/*.go -- tool handler
    |
    |---> pkg/query/    (indexed pcap: SQLite queries for PacketSummary/Flow/ExpertEvent)
    |---> pkg/replay/   (NEW: re-read raw packets from pcap for full PacketInfo)
    |---> pkg/capture/  (live capture / packet parsing)
    |---> pkg/stream/   (TCP reassembly, HTTP parsing -- via replay)
    |---> pkg/tls/      (TLS decryption -- via replay + keylog)
    |---> pkg/fields/   (field extraction -- via replay + Registry)
    |---> pkg/filter/   (display filter -- via replay + Compile())
    |---> pkg/expert/   (anomaly detection -- via QueryEngine.GetExpertEvents())
    |---> pkg/stats/    (NOT used for indexed pcaps; QueryEngine has GetProtocolStats/GetTopTalkers)
    |
    v
mcp/middleware.go -- output redaction
    |
    v
Structured JSON --> MCP Transport --> AI Agent
```

### Two Data Paths

The system has two distinct data paths:

1. **Indexed path** (primary): `QueryEngine` queries SQLite for `PacketSummary`, `Flow`, `ExpertEvent`, `Overview`, `ProtocolStat`, `TopTalker`. Used by most tools.
2. **Replay path** (on-demand): `replay.Reader` re-reads raw packets from pcap file, parses into `capture.PacketInfo` for tools that need full packet data (`reassemble_stream`, `extract_field`, `apply_display_filter`, `get_packet` with `include_raw`).

### Live Capture Data Path

`capture_live` does NOT stream data to the caller. It:
1. Captures packets to a temporary pcap file (bounded by `count`/`duration`)
2. Indexes the temporary file via `pkg/ingest`
3. Opens it as the active capture via `QueryEngine`
4. Returns an overview of the captured data

This keeps the MCP tool model synchronous (request/response). The AI agent can then query the captured data with other tools.

## Tool Handler Pattern

All tool handlers share a dependency container:

```go
// mcp/tools/context.go
type ToolContext struct {
    Query    query.QueryEngine     // Structured queries on indexed data
    Replay   *replay.Reader        // Re-read raw packets for full PacketInfo
    Fields   *fields.Registry      // Field extraction
    Security *security.Config      // Security configuration
    PcapPath string                // Current pcap file path
}
```

Note: `filter.Compile()` is a package-level function, not a struct -- it does not appear in ToolContext. `stats.Manager` is a streaming collector; for indexed data, `QueryEngine.GetProtocolStats()` and `GetTopTalkers()` are used instead. `expert.Analyzer` is also a streaming processor; `QueryEngine.GetExpertEvents()` covers the indexed use case.

Example handler:

```go
// mcp/tools/packet.go
func HandleListPackets(tc *ToolContext) server.ToolHandlerFunc {
    return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        // 1. Extract and validate parameters
        offset, _ := req.GetInt("offset", 0)
        limit, _ := req.GetInt("limit", 50)
        limit = security.ClampLimit(limit, tc.Security.MaxLimit)

        // 2. Call QueryEngine
        packets, err := tc.Query.GetPackets(ctx, query.PacketFilter{
            Offset: offset,
            Limit:  limit,
        })
        if err != nil {
            return mcp.NewToolResultError(err.Error()), nil
        }

        // 3. Return structured JSON
        return mcp.NewToolResultText(toJSON(packets)), nil
    }
}
```

## Output Format

All tools return structured JSON instead of formatted text. Examples:

### list_packets response

```json
{
  "total": 1523,
  "offset": 0,
  "limit": 20,
  "packets": [
    {
      "number": 1,
      "timestamp": "2024-01-15T10:30:00.123456Z",
      "src_ip": "192.168.1.100",
      "dst_ip": "93.184.216.34",
      "src_port": 54321,
      "dst_port": 443,
      "protocol": "TLS",
      "length": 583,
      "info": "Client Hello, SNI=example.com"
    }
  ]
}
```

### detect_anomalies response

```json
{
  "anomaly_count": 2,
  "anomalies": [
    {
      "type": "port_scan",
      "severity": "high",
      "description": "192.168.1.50 sent SYN to 47 different ports",
      "evidence": {
        "packet_ids": [102, 105, 108, 112],
        "source_ip": "192.168.1.50",
        "target_ports_count": 47
      }
    }
  ]
}
```

## Tool Registration

```go
// mcp/server.go
func NewPktAnalyzerServer(tc *ToolContext, cfg ServerConfig) *server.MCPServer {
    s := server.NewMCPServer(
        "pktanalyzer",
        version,
        server.WithToolCapabilities(true),
        server.WithRecovery(),
    )

    registerSourceTools(s, tc)   // 4 tools
    registerPacketTools(s, tc)   // 5 tools
    registerStreamTools(s, tc)   // 5 tools
    registerFieldTools(s, tc)    // 3 tools
    registerExportTools(s, tc)   // 1 tool

    return s
}
```

## Integration Examples

### Claude Code (mcp.json) -- stdio

```json
{
  "mcpServers": {
    "pktanalyzer": {
      "command": "pktanalyzer",
      "args": ["mcp", "/path/to/capture.pcap"],
      "env": {}
    }
  }
}
```

### Claude Code with security flags and TLS decryption

```json
{
  "mcpServers": {
    "pktanalyzer": {
      "command": "pktanalyzer",
      "args": [
        "mcp", "/path/to/capture.pcap",
        "--enable-raw",
        "--keylog-file", "/path/to/sslkeylog.txt",
        "--redact-creds"
      ],
      "env": {}
    }
  }
}
```

## Reuse Mapping

| MCP Tool Handler | Reused Code | Notes |
|---|---|---|
| `list_packets`, `get_packet` | `pkg/query.QueryEngine.GetPackets()`, `GetPacket()` | Direct mapping to `PacketSummary` |
| `filter_packets` | `pkg/query.QueryEngine.GetPackets()` + `pkg/filter.Compile()` + `pkg/replay` | SQLite pre-filter, then post-filter with display filter via replay |
| `get_statistics` | `pkg/query.QueryEngine.GetProtocolStats()`, `GetTopTalkers()` | NOT `stats.Manager` (that is for streaming) |
| `detect_anomalies` | `pkg/query.QueryEngine.GetExpertEvents()` | NOT `expert.Analyzer` (that is for streaming) |
| `list_flows`, `get_flow`, `get_flow_packets` | `pkg/query.QueryEngine` flow methods | Direct mapping |
| `reassemble_stream`, `follow_http` | `pkg/replay.Reader` + `pkg/stream` reassembler | Replay pipeline: read raw packets, feed to reassembler |
| `apply_display_filter` | `pkg/replay.Reader` + `pkg/filter.Compile()` | Replay pipeline: re-parse packets for filter evaluation |
| `extract_field`, `list_fields` | `pkg/replay.Reader` + `pkg/fields.Registry` | Replay pipeline: re-parse packet for field extraction |
| `open_pcap` | `pkg/ingest.IndexFile()` + `pkg/query.NewFromPcap()` | Existing indexing pipeline |
| `export_packets` | `pkg/export` | Existing export functionality |
| Parameter validation, redaction | `pkg/security` (from `agent/security.go`) | ClampInt, RedactIP, etc. |

## Package Move Strategy

Moving top-level packages (`capture/`, `stream/`, `tls/`, `fields/`, `filter/`, `expert/`, `stats/`, `export/`) into `pkg/` changes all import paths. These packages have cross-dependencies:

- `filter/` imports `capture/`
- `fields/` imports `capture/`
- `expert/` imports `capture/`
- `stats/` imports `capture/` and `internal/format/`
- `export/` imports `capture/` and `fields/`
- `stream/` imports `capture/`

Strategy: **batch rename with `gofmt -w .` and `sed` on import paths**. All moves happen in a single commit. The cascading import updates are mechanical (find-and-replace `"github.com/Zerofisher/pktanalyzer/capture"` to `"github.com/Zerofisher/pktanalyzer/pkg/capture"` etc.). Run `go build ./...` after to verify.

## Testing Strategy

### Unit Tests

Each MCP tool handler gets a unit test file (`mcp/tools/*_test.go`). Tests use a mock `QueryEngine` (the interface is already designed for this) and a test pcap from `examples/`.

### Integration Tests

A test harness loads a real pcap via `ingest.IndexFile()`, creates a real `QueryEngine`, and calls each MCP tool handler. This tests the full pipeline from MCP request to JSON response.

### MCP Protocol Tests

Use `mcp-go`'s client library to test the full MCP protocol flow (initialize, list tools, call tool, verify response). This ensures the transport layer works correctly.

### Replay Pipeline Tests

`pkg/replay` gets dedicated tests using `examples/*.pcap` files:
- Read a packet by offset, verify it matches expected `PacketInfo`
- Read flow packets, verify reassembly produces expected HTTP content

### Existing Tests

Tests in `capture/`, `stream/`, `tls/`, `fields/`, `filter/`, `expert/`, `stats/`, `export/` are kept. Import paths updated during the package move.

## Logging

Structured logging to stderr via Go's `log/slog` (stdlib, no new dependency). MCP stdio transport uses stdin/stdout, so logs must go to stderr.

Log levels:
- `INFO`: server startup, pcap opened, capture started
- `WARN`: rate limited, parameter clamped
- `ERROR`: tool execution failure, file I/O error
- `DEBUG` (with `--verbose` flag): every tool call with parameters and response size

## Graceful Shutdown

- **stdio mode**: exits when stdin closes (standard MCP lifecycle)
- **SSE mode**: listens for SIGINT/SIGTERM, calls `sseServer.Shutdown()`, closes open file handles
- **Live capture**: if a `capture_live` is in progress, it is stopped and the partial capture is indexed before shutdown

## Migration Plan

### Branch Strategy

All work happens on a `refactor/mcp-server` feature branch. The `main` branch remains functional with the old CLI/TUI until the refactor is complete and merged.

### Acceptance Criteria for Merge

1. `go build ./...` passes with zero errors
2. `go test ./...` passes (existing tests with updated import paths + new MCP tests)
3. All 18 MCP tools callable via mcp-go client test harness
4. stdio transport works with Claude Code (manual test with a real pcap)
5. SSE transport starts and responds to MCP protocol handshake

### Breaking Changes

This is a **breaking change** to the CLI interface:
- Old: `pktanalyzer read capture.pcap`, `pktanalyzer capture en0`, `pktanalyzer stats ...`
- New: `pktanalyzer mcp capture.pcap`, `pktanalyzer list interfaces`

All other subcommands are removed. The binary's primary role changes from "interactive packet analyzer" to "MCP server for AI agents."

### Rollback

If the merge breaks something, `git revert` the merge commit. The old CLI/TUI is fully intact on `main` prior to merge.

### Implementation Note: SrcPort/DstPort SQL

The current `SQLiteEngine.GetPackets()` does not generate SQL WHERE clauses for `SrcPort`/`DstPort` (only `Port` is implemented). This needs to be added as part of the `filter_packets` tool implementation. The `PacketFilter` struct already has the fields; the SQL generation is the gap.

## Dependencies

### Added

- `github.com/mark3labs/mcp-go` -- MCP server SDK

### Removed

- `github.com/charmbracelet/bubbletea` -- TUI
- `github.com/charmbracelet/bubbles` -- TUI components
- `github.com/charmbracelet/lipgloss` -- TUI styling
- `github.com/anthropics/anthropic-sdk-go` -- Claude LLM client
- `github.com/openai/openai-go/v3` -- OpenAI LLM client
- `go.opentelemetry.io/otel*` -- Tracing (was for agent ReAct loop)

### Kept

- `github.com/google/gopacket` -- Packet parsing
- `github.com/expr-lang/expr` -- Display filter engine
- `github.com/mattn/go-sqlite3` -- Pcap index storage
- `github.com/spf13/cobra` -- CLI framework
