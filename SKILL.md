---
name: pktanalyzer
description: Use when analyzing network traffic, pcap/pcapng files, TCP streams, DNS queries, HTTP sessions, TLS decryption, or detecting network anomalies. Also use when the user mentions Wireshark, tcpdump, packet capture, or network debugging.
---

# PktAnalyzer — AI Network Packet Analysis

MCP server exposing 18 structured tools for pcap/pcapng analysis, TCP stream reassembly, TLS decryption, Wireshark-compatible display filtering, and anomaly detection.

## Setup

### Install Binary

```bash
# macOS (Apple Silicon)
curl -L https://github.com/Zerofisher/pktanalyzer/releases/latest/download/pktanalyzer_v0.1.0_darwin_arm64.tar.gz | tar xz
sudo mv pktanalyzer /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/Zerofisher/pktanalyzer/releases/latest/download/pktanalyzer_v0.1.0_darwin_amd64.tar.gz | tar xz
sudo mv pktanalyzer /usr/local/bin/

# Linux (amd64)
curl -L https://github.com/Zerofisher/pktanalyzer/releases/latest/download/pktanalyzer_v0.1.0_linux_amd64.tar.gz | tar xz
sudo mv pktanalyzer /usr/local/bin/
```

> Replace `v0.1.0` with the actual version from [GitHub Releases](https://github.com/Zerofisher/pktanalyzer/releases).

### Configure in Claude Code

Add to `~/.claude/settings.json` or project `.mcp.json`:

```json
{
  "mcpServers": {
    "pktanalyzer": {
      "command": "pktanalyzer",
      "args": ["mcp", "/path/to/capture.pcap"]
    }
  }
}
```

With TLS decryption:

```json
{
  "mcpServers": {
    "pktanalyzer": {
      "command": "pktanalyzer",
      "args": [
        "mcp", "/path/to/capture.pcap",
        "--keylog-file", "/path/to/sslkeys.log",
        "--enable-raw"
      ]
    }
  }
}
```

Without pre-loaded capture (load via `open_pcap` tool later):

```json
{
  "mcpServers": {
    "pktanalyzer": {
      "command": "pktanalyzer",
      "args": ["mcp"]
    }
  }
}
```

## MCP Tools Quick Reference

### Source Tools (4)

| Tool | Purpose | Key Params |
|------|---------|------------|
| `open_pcap` | Open and index a pcap/pcapng file | `path` |
| `capture_live` | Live capture from interface | `interface`, `bpf`, `count`, `duration` |
| `list_interfaces` | List network interfaces | — |
| `get_overview` | Capture summary: packets, time span, protocols | — |

### Packet Tools (5)

| Tool | Purpose | Key Params |
|------|---------|------------|
| `list_packets` | Paginated packet list | `limit`, `offset`, `sort_by`, `sort_order` |
| `filter_packets` | Filter by IP/port/protocol | `src_ip`, `dst_ip`, `protocol`, `src_port`, `dst_port`, `search` |
| `get_packet` | Full detail of one packet | `number` |
| `get_statistics` | Protocol distribution, top IPs/ports | — |
| `detect_anomalies` | TCP/DNS/HTTP anomaly detection | `severity` |

### Stream Tools (5)

| Tool | Purpose | Key Params |
|------|---------|------------|
| `list_flows` | List TCP/UDP flows | `protocol`, `ip`, `limit`, `sort_by` |
| `get_flow` | Single flow details | `flow_id` |
| `get_flow_packets` | Packets within a flow | `flow_id`, `limit` |
| `reassemble_stream` | TCP stream reassembly | `flow_id`, `format` (text/hex/http) |
| `follow_http` | Parse HTTP request/response pairs | `flow_id` |

### Field Tools (3)

| Tool | Purpose | Key Params |
|------|---------|------------|
| `list_fields` | List 100+ protocol fields | `prefix` |
| `extract_field` | Extract field from a packet | `field`, `packet_number` |
| `apply_display_filter` | Wireshark-compatible filter | `expression`, `limit` |

### Export Tools (1)

| Tool | Purpose | Key Params |
|------|---------|------------|
| `export_packets` | Export filtered packets to new pcap | `output_path`, `packet_numbers`, `display_filter` |

## Common Analysis Workflows

### 1. Overview First

```
open_pcap → get_overview → get_statistics → detect_anomalies
```

Start broad: open the file, check summary, see protocol distribution, then scan for anomalies.

### 2. Filter and Drill Down

```
filter_packets (by protocol/IP/port) → get_packet (specific number) → extract_field
```

Narrow to interesting traffic, then inspect individual packets in detail.

### 3. Follow a Conversation

```
list_flows → get_flow → reassemble_stream / follow_http
```

Find the TCP/UDP flow, then reconstruct the application-layer content or HTTP session.

### 4. Display Filter Query

```
apply_display_filter("tcp.dstport == 443 and ip.src == \"10.0.0.1\"") → get_packet
```

Use Wireshark-style filters for precise matching across all indexed fields.

### 5. TLS Decryption

Requires `--keylog-file` flag at startup. Then `follow_http` on HTTPS flows returns decrypted content.

### 6. Export Subset

```
export_packets(output_path="subset.pcap", display_filter="dns")
```

Save filtered packets to a new pcap file for sharing or further analysis.

## Display Filter Syntax

Wireshark-compatible expressions:

```
tcp.dstport == 80                              # exact match
ip.src == "192.168.1.1"                        # IP match
ip.src == "192.168.1.1" and tcp                # logical AND
tcp or udp                                     # logical OR
dns.qry.name contains "google"                 # string containment
tcp.dstport in [80, 443, 8080]                 # range match
dns                                            # protocol filter
```

Use `list_fields` to discover all available filter fields (100+).

## CLI Flags

```
pktanalyzer mcp [pcap-file] [flags]

Transport:
  --transport string     stdio (default) or sse
  --bind string          SSE bind address (default "127.0.0.1")
  --port int             SSE port (default 8080)

Capture:
  --live                 Live capture mode
  --interface string     Capture interface (with --live)
  --bpf string           BPF filter expression

Decryption:
  --keylog-file string   SSLKEYLOGFILE for TLS decryption

Security:
  --enable-raw           Allow raw packet data access
  --raw-max-bytes int    Max raw bytes (default 1024)
  --redact-ips           Redact IP addresses
  --redact-macs          Redact MAC addresses
  --redact-creds         Redact HTTP credentials
  --rate-limit int       Max tool calls/minute (default 100)

Debug:
  --verbose              Debug logging
```

## Anomaly Detection Reference

| Type | Severity | Trigger |
|------|----------|---------|
| TCP Retransmission | Warning | Same seq resent > 200ms |
| TCP Fast Retransmission | Warning | Triggered by 3 dup ACKs |
| TCP Out-of-Order | Warning | Seq < expected |
| TCP Zero Window | Warning | Receiver buffer full |
| TCP RST | Warning | Connection reset |
| TCP Connection Refused | Error | RST after SYN |
| TCP SYN Flood Suspected | Error | SYN flood pattern |
| DNS Query No Response | Warning | No reply in 5s |
| DNS NXDOMAIN | Note | Domain not found |
| DNS SERVFAIL | Warning | Server failure |
| HTTP 4xx | Warning | Client error |
| HTTP 5xx | Error | Server error |
| HTTP Slow Response | Warning | Response > 3s |

## Supported Protocols

| Layer | Protocols |
|-------|-----------|
| L2 | Ethernet |
| L3 | IPv4, IPv6, ARP, ICMP, ICMPv6, IGMP |
| L4 | TCP, UDP |
| L7 | DNS, HTTP/1.1, HTTP/2, WebSocket, TLS/HTTPS, NBNS, LLMNR, mDNS, SSDP, SRVLOC, WS-Discovery, DHCP, NTP, SNMP |

## Important Notes

- Live capture requires root/sudo
- TLS decryption needs complete handshake captured + key log file
- Output is bounded (default max 200 packets per response)
- Raw packet bytes require `--enable-raw` flag
- Redaction flags mask sensitive data in all tool output
