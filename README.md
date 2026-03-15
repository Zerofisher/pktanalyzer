# PktAnalyzer

[English](./README.md) | [简体中文](./README.zh-CN.md)

An MCP (Model Context Protocol) server for AI-powered network packet analysis, written in Go. It exposes 18 structured tools for pcap/pcapng analysis, TCP stream reassembly, TLS decryption, display filtering, and anomaly detection — designed to be used by AI agents like Claude Code.

## Features

- **MCP Server**: 18 tools across 5 categories, accessible via stdio or SSE transport
- **AI-Native**: Designed for AI agents — structured JSON responses, evidence references, bounded output
- **Pcap Analysis**: Read pcap/pcapng files with automatic SQLite indexing for fast queries
- **Live Capture**: Capture packets from network interfaces (requires root privileges)
- **TLS Decryption**: Decrypt HTTPS traffic using `SSLKEYLOGFILE`
- **TCP Stream Reassembly**: Reconstruct application-layer content from TCP streams
- **HTTP Following**: Parse HTTP request/response pairs from TCP streams
- **Display Filters**: Wireshark-compatible filter syntax (`tcp.dstport == 443`, `ip.src == "1.2.3.4"`)
- **Field Extraction**: 100+ protocol fields with type-safe extraction
- **Anomaly Detection**: Expert analysis engine for TCP/DNS/HTTP anomalies
- **Security**: Output redaction, raw data gating, rate limiting

### Supported Protocols

| Layer           | Protocols                                                                                                           |
| --------------- | ------------------------------------------------------------------------------------------------------------------- |
| Data Link       | Ethernet                                                                                                            |
| Network         | IPv4, IPv6, ARP, ICMP, ICMPv6, IGMP                                                                                 |
| Transport       | TCP, UDP                                                                                                            |
| Application     | DNS, HTTP/1.1, HTTP/2, WebSocket, TLS/HTTPS, NBNS, LLMNR, mDNS, SSDP, SRVLOC, WS-Discovery, DHCP, NTP, SNMP       |

## Installation

### Prerequisites

```bash
# macOS
brew install libpcap

# Ubuntu/Debian
sudo apt-get install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel
```

### Build

```bash
cd pktanalyzer
go mod tidy
go build -o pktanalyzer
```

## Quick Start

### Start MCP Server

```bash
# Start with a pcap file (stdio transport, default)
./pktanalyzer mcp capture.pcap

# Start with SSE transport
./pktanalyzer mcp capture.pcap --transport sse --port 9090

# Start without a pre-loaded capture (use open_pcap tool later)
./pktanalyzer mcp

# With TLS decryption
./pktanalyzer mcp capture.pcap --keylog-file ~/sslkeys.log

# With security options
./pktanalyzer mcp capture.pcap --enable-raw --redact-ips --rate-limit 50
```

### List Network Interfaces

```bash
./pktanalyzer list interfaces
```

## Integration with Claude Code

PktAnalyzer is designed to work as an MCP server for Claude Code. Add it to your Claude Code configuration:

### Configuration

Add the following to your Claude Code MCP settings (`~/.claude/settings.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "pktanalyzer": {
      "command": "/path/to/pktanalyzer",
      "args": ["mcp", "/path/to/capture.pcap"]
    }
  }
}
```

With TLS decryption and security options:

```json
{
  "mcpServers": {
    "pktanalyzer": {
      "command": "/path/to/pktanalyzer",
      "args": [
        "mcp",
        "/path/to/capture.pcap",
        "--keylog-file", "/path/to/sslkeys.log",
        "--enable-raw",
        "--verbose"
      ]
    }
  }
}
```

Without a pre-loaded capture (use `open_pcap` tool to load files on demand):

```json
{
  "mcpServers": {
    "pktanalyzer": {
      "command": "/path/to/pktanalyzer",
      "args": ["mcp"]
    }
  }
}
```

### Example Conversations with Claude Code

Once configured, you can ask Claude to analyze network traffic:

```
You: Open examples/http_google.pcapng and give me an overview

Claude: [Calls open_pcap, then get_overview]
       The capture contains 43 packets over 2.3 seconds.
       Protocol distribution: TCP 82%, UDP 14%, DNS 4%.
       ...

You: Show me the DNS queries

Claude: [Calls filter_packets with protocol="DNS"]
       Found 4 DNS packets:
       1. Query: www.google.com (A record)
       2. Response: 74.125.95.104
       ...

You: Are there any anomalies?

Claude: [Calls detect_anomalies]
       Found 2 warnings:
       - TCP Retransmission on packet #12 (flow 192.168.1.1:1606 → 74.125.95.104:80)
       - DNS Query No Response for packet #8
       ...

You: Follow the HTTP traffic on the main flow

Claude: [Calls list_flows, then follow_http]
       HTTP Session (flow abc123):
       Request: GET / HTTP/1.1 Host: www.google.com
       Response: HTTP/1.1 200 OK Content-Type: text/html ...

You: Extract the TTL values for all packets from 192.168.1.1

Claude: [Calls filter_packets, then extract_field for each]
       Packet #1: TTL=64, Packet #3: TTL=64, Packet #5: TTL=64 ...
```

## MCP Tools Reference

### Source Tools (4)

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `open_pcap` | Open and index a pcap/pcapng file | `path` (required) |
| `capture_live` | Start live capture on a network interface | `interface` (required), `bpf`, `count`, `duration` |
| `list_interfaces` | List available network interfaces | — |
| `get_overview` | Capture overview: packets, time span, protocol distribution | — |

### Packet Tools (5)

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `list_packets` | List packets with pagination and sorting | `limit`, `offset`, `sort_by`, `sort_order` |
| `filter_packets` | Filter packets by various criteria | `src_ip`, `dst_ip`, `protocol`, `src_port`, `dst_port`, `search` |
| `get_packet` | Detailed analysis of a single packet | `number` (required) |
| `get_statistics` | Protocol distribution, top IPs, top ports | — |
| `detect_anomalies` | Detect anomalies using expert analysis engine | `severity` |

### Stream Tools (5)

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `list_flows` | List TCP/UDP flows with filtering and sorting | `protocol`, `ip`, `limit`, `sort_by` |
| `get_flow` | Get details of a single flow | `flow_id` (required) |
| `get_flow_packets` | List packets within a flow | `flow_id` (required), `limit` |
| `reassemble_stream` | TCP stream reassembly — reconstruct content | `flow_id` (required), `format` (text/hex/http) |
| `follow_http` | Follow HTTP session — parse request/response pairs | `flow_id` (required) |

### Field Tools (3)

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `list_fields` | List available protocol fields with types | `prefix` |
| `extract_field` | Extract a field value from a specific packet | `field` (required), `packet_number` (required) |
| `apply_display_filter` | Apply Wireshark-compatible display filter | `expression` (required), `limit` |

### Export Tools (1)

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `export_packets` | Export filtered packets as a new pcap file | `output_path` (required), `packet_numbers`, `display_filter` |

## CLI Flags

```
pktanalyzer mcp [pcap-file] [flags]

Flags:
      --transport string     Transport: stdio or sse (default "stdio")
      --bind string          SSE bind address (default "127.0.0.1")
      --port int             SSE listen port (default 8080)
      --live                 Live capture mode (no pcap file needed)
      --interface string     Capture interface (required with --live)
      --bpf string           BPF filter expression
      --keylog-file string   SSLKEYLOGFILE path for TLS decryption
      --enable-raw           Allow raw packet data access
      --raw-max-bytes int    Max raw bytes per packet (default 1024)
      --redact-ips           Redact IP addresses in output
      --redact-macs          Redact MAC addresses
      --redact-creds         Redact HTTP credentials
      --rate-limit int       Max tool calls per minute (default 100)
      --verbose              Enable debug logging
```

## TLS/HTTPS Decryption

1. Set environment variable to let the browser export TLS keys:

```bash
export SSLKEYLOGFILE=~/sslkeys.log
```

2. Start the browser from the terminal:

```bash
# Chrome
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Firefox
/Applications/Firefox.app/Contents/MacOS/firefox
```

3. Browse websites, then use the key file to decrypt:

```bash
./pktanalyzer mcp capture.pcap --keylog-file ~/sslkeys.log
```

## Anomaly Detection

The `detect_anomalies` tool uses the expert analysis engine to identify network issues:

### TCP Anomalies

| Type | Severity | Description |
|------|----------|-------------|
| TCP Retransmission | Warning | Resending same sequence > 200ms |
| TCP Fast Retransmission | Warning | Triggered by 3 duplicate ACKs |
| TCP Out-of-Order | Warning | Sequence number less than expected |
| TCP Zero Window | Warning | Receiver buffer full |
| TCP RST | Warning | Connection Reset |
| TCP Connection Refused | Error | RST received after SYN |
| TCP SYN Flood Suspected | Error | Suspected SYN Flood Attack |

### DNS Anomalies

| Type | Severity | Description |
|------|----------|-------------|
| DNS Query No Response | Warning | No response within 5s |
| DNS NXDOMAIN | Note | Domain does not exist |
| DNS SERVFAIL | Warning | Server failure |

### HTTP Anomalies

| Type | Severity | Description |
|------|----------|-------------|
| HTTP 4xx Client Error | Warning | Client Error (400-499) |
| HTTP 5xx Server Error | Error | Server Error (500-599) |
| HTTP Slow Response | Warning | Response > 3 seconds |

## Display Filter Syntax

The `apply_display_filter` tool supports Wireshark-compatible filter expressions:

```
# Basic comparison
tcp.dstport == 80
ip.src == "192.168.1.1"

# Logical operators
ip.src == "192.168.1.1" and tcp
tcp or udp

# String containment
dns.qry.name contains "google"

# Protocol filtering
dns
http
tls

# Range matching
tcp.dstport in [80, 443, 8080]
```

Use `list_fields` to see all available filter fields.

## Project Structure

```
pktanalyzer/
├── main.go                  # Entry point
├── cmd/                     # CLI commands (Cobra)
│   ├── root.go              # Root command
│   ├── mcp.go               # MCP server command
│   └── list.go              # List interfaces command
├── mcp/                     # MCP server layer
│   ├── server.go            # Server assembly (18 tools)
│   ├── middleware.go         # Output redaction, logging
│   └── tools/               # Tool handlers
│       ├── context.go       # Shared dependency container
│       ├── helpers.go       # Parameter extraction
│       ├── source.go        # Source tools (4)
│       ├── packet.go        # Packet tools (5)
│       ├── stream.go        # Stream tools (5)
│       ├── fields.go        # Field tools (3)
│       └── export.go        # Export tool (1)
├── pkg/                     # Core packages
│   ├── capture/             # Packet capture/parsing
│   ├── stream/              # TCP reassembly, HTTP/H2/WS
│   ├── tls/                 # TLS parsing, decryption
│   ├── filter/              # Display filter (expr-lang)
│   ├── fields/              # Protocol field registry
│   ├── expert/              # Anomaly detection
│   ├── stats/               # Statistical analysis
│   ├── export/              # Pcap writer
│   ├── ingest/              # Pcap → SQLite indexing
│   ├── query/               # Query engine
│   ├── store/               # SQLite storage
│   ├── model/               # Data models
│   ├── replay/              # Raw packet re-reading
│   └── security/            # Validation, redaction
└── examples/                # Test capture files
```

## Tech Stack

- [mcp-go](https://github.com/mark3labs/mcp-go) - MCP server SDK
- [cobra](https://github.com/spf13/cobra) - CLI framework
- [gopacket](https://github.com/google/gopacket) - Packet capture and parsing
- [expr-lang/expr](https://github.com/expr-lang/expr) - Display filter expression engine
- [go-sqlite3](https://github.com/mattn/go-sqlite3) - SQLite indexing backend

## Notes

- Live capture requires root privileges
- TLS decryption only supports sessions with available keys
- Requires capturing the complete TLS handshake to decrypt
- Supported cipher suites: AES-128/256-GCM, AES-128/256-CBC
- Output is bounded by security config (default max 200 packets per response)
- Raw packet data access requires `--enable-raw` flag

## License

MIT
