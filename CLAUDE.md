# PktAnalyzer

Go module root: `pktanalyzer/go.mod`. Test captures: `examples/*.pcap*`

## What (WHAT)

MCP (Model Context Protocol) server for AI-powered network packet analysis on `gopacket/pcap`:
- 18 tools across 5 categories: Source, Packet, Stream, Field, Export
- Transports: stdio (default) and SSE
- pcap/pcapng file analysis with SQLite indexing
- TLS decryption (`--keylog-file`), TCP reassembly, HTTP following
- Wireshark-compatible display filters, 100+ protocol fields
- Security: output redaction, raw data gating, rate limiting

## Why (WHY)

AI-native packet analysis — expose network analysis as structured MCP tools for AI agents (Claude Code, etc.) instead of building a monolithic CLI/TUI with built-in AI.

## How (HOW)

```bash
go build -o pktanalyzer                              # build
./pktanalyzer mcp examples/http_google.pcapng        # start MCP server (stdio)
./pktanalyzer mcp capture.pcap --transport sse       # start MCP server (SSE)
./pktanalyzer list interfaces                        # list network interfaces
go test ./...                                        # test
gofmt -w .                                           # format
```

## Docs (progressive disclosure)

Read only when relevant:
- `README.md` - user-facing features, MCP tools reference, Claude Code integration

## Repo map

| Path | Purpose |
|------|---------|
| `main.go` | Entry point |
| `cmd/root.go` | Cobra root command |
| `cmd/mcp.go` | MCP server command (flags, startup, transport) |
| `cmd/list.go` | `list interfaces` subcommand |
| `mcp/server.go` | MCP server assembly (NewPktAnalyzerServer, registers 18 tools) |
| `mcp/middleware.go` | Output redaction, tool call logging |
| `mcp/tools/context.go` | ToolContext — shared dependency container |
| `mcp/tools/helpers.go` | Parameter extraction, error formatting |
| `mcp/tools/source.go` | Source tools: open_pcap, capture_live, list_interfaces, get_overview |
| `mcp/tools/packet.go` | Packet tools: list_packets, filter_packets, get_packet, get_statistics, detect_anomalies |
| `mcp/tools/stream.go` | Stream tools: list_flows, get_flow, get_flow_packets, reassemble_stream, follow_http |
| `mcp/tools/fields.go` | Field tools: list_fields, extract_field, apply_display_filter |
| `mcp/tools/export.go` | Export tool: export_packets |
| `pkg/capture/` | Packet capture/parsing (gopacket) |
| `pkg/stream/` | TCP reassembly, HTTP/HTTP2/WebSocket parsing |
| `pkg/tls/` | TLS parsing, keylog decryption |
| `pkg/filter/` | Display filter (expr-lang) |
| `pkg/fields/` | Protocol field registry (100+ fields) |
| `pkg/expert/` | Anomaly detection (TCP/DNS/HTTP) |
| `pkg/stats/` | Statistical analysis |
| `pkg/export/` | Pcap write (PcapWriter) |
| `pkg/ingest/` | Pcap → SQLite indexing pipeline |
| `pkg/query/` | QueryEngine interface, SQLiteEngine |
| `pkg/store/` | SQLite storage backend |
| `pkg/model/` | Data models (PacketSummary, Flow, ExpertEvent) |
| `pkg/replay/` | Re-read raw packets from pcap for full PacketInfo |
| `pkg/security/` | Validation, clamping, redaction config |

## Constraints

- Packet data is **sensitive** — raw bytes gated behind `--enable-raw` flag
- MCP tools are **side-effect free** by default (read-only queries)
- Exceptions: `open_pcap`, `capture_live`, `export_packets` (explicit user action)
- All tools have **bounded output** (limit/size caps via security.Config)
- Output redaction available via `--redact-ips`, `--redact-macs`, `--redact-creds`
