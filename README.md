# PktAnalyzer

[English](./README.md) | [简体中文](./README.zh-CN.md)

A command-line network packet analysis tool written in Go, similar to tshark/Wireshark. It supports real-time packet capture, pcap file analysis, TLS/HTTPS decryption, TCP stream reassembly, CLI export, and AI-powered analysis.

## Features

- **Real-time Capture**: Capture packets from network interfaces (requires root privileges).
- **File Analysis**: Read capture files in pcap/pcapng format.
- **TLS Decryption**: Decrypt HTTPS traffic using `SSLKEYLOGFILE`.
- **TCP Stream Reassembly**: Track and reassemble TCP sessions to view complete data streams.
- **Display Filters**: Wireshark-like syntax for display filtering (`-Y`).
- **CLI Export**: tshark-compatible command-line output (`text`, `json`, `fields`).
- **Statistical Analysis**: Endpoint statistics, conversation statistics, I/O statistics (`stats` command).
- **Stream Following**: Export TCP stream data (`follow` command).
- **Expert Info**: An expert system for TCP/DNS/HTTP anomaly detection, similar to Wireshark Expert Info.
- **AI Analysis**: Integrated with Claude/OpenAI for intelligent interpretation of packets and network behavior.
- **TUI Interface**: Interactive terminal user interface with support for scrolling, filtering, detailed views, and split screens.

### Supported Protocols

| Layer           | Protocols                                                                                                           |
| --------------- | ------------------------------------------------------------------------------------------------------------------- |
| Data Link       | Ethernet                                                                                                            |
| Network         | IPv4, IPv6, ARP, ICMP, ICMPv6, IGMP                                                                                 |
| Transport       | TCP, UDP                                                                                                            |
| Application     | DNS, HTTP/1.1, **HTTP/2**, **WebSocket**, TLS/HTTPS, NBNS, LLMNR, mDNS, SSDP, SRVLOC, WS-Discovery, DHCP, NTP, SNMP |

### HTTP/2 Support

pktanalyzer supports complete HTTP/2 protocol parsing:

- **Frame Parsing**: Supports all 9 HTTP/2 frame types (DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION).
- **HPACK Decompression**: Full implementation of RFC 7541 header compression, including static table, dynamic table, and Huffman coding.
- **Stream Multiplexing**: Tracks and manages multiple concurrent streams within an HTTP/2 connection.
- **Request/Response Pairing**: Automatically associates requests and responses with their corresponding streams.
- **ALPN Detection**: Automatically detects HTTP/2 protocol negotiation via TLS ALPN extension.

### WebSocket Support

pktanalyzer supports complete WebSocket protocol parsing (RFC 6455):

- **Handshake Detection**: Automatically detects HTTP Upgrade handshakes and verifies Sec-WebSocket-Key/Accept.
- **Frame Parsing**: Supports all WebSocket frame types (TEXT, BINARY, CLOSE, PING, PONG, CONTINUATION).
- **Masking**: Automatically decodes masked data sent by clients.
- **Message Reassembly**: Reassembles fragmented frames into complete messages.
- **Extended Length**: Supports 16-bit and 64-bit extended payload lengths.
- **Close Code Parsing**: Parses and displays WebSocket close status codes and reasons.

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

## Usage

pktanalyzer uses a command-based structure. Use `pktanalyzer --help` to see all available commands.

### Basic Usage

```bash
# Show help
./pktanalyzer --help

# List available network interfaces
./pktanalyzer list interfaces

# List available fields
./pktanalyzer list fields

# Read pcap file (TUI mode)
./pktanalyzer read capture.pcapng

# Real-time capture (requires root privileges)
sudo ./pktanalyzer capture en0

# Use BPF filter (capture filter)
./pktanalyzer read capture.pcapng --bpf "tcp port 80"
sudo ./pktanalyzer capture en0 --bpf "host 192.168.1.1"
```

### Save Packets

Capture live packets and save them to a pcapng file:

```bash
# Real-time capture and save to file
sudo ./pktanalyzer capture write en0 capture.pcapng

# Limit the number of packets
sudo ./pktanalyzer capture write en0 capture.pcapng -c 100

# With display filter
sudo ./pktanalyzer capture write en0 capture.pcapng -Y 'tcp.dstport == 443'
```

**TUI Mode Save**: In TUI mode (started with `capture` or `read`), press `w` to save the current (filtered) packets to a file. The filename is automatically generated in the format `capture_YYYYMMDD_HHMMSS.pcapng`.

### CLI Export Mode (tshark compatible)

```bash
# Text format output (one-line summary)
./pktanalyzer read text capture.pcapng -c 10

# JSON format output
./pktanalyzer read json capture.pcapng -c 5

# Field extraction
./pktanalyzer read fields capture.pcapng -e frame.number -e ip.src -e ip.dst -e tcp.dstport

# Detailed output (protocol layer information)
./pktanalyzer read text capture.pcapng -V -c 1

# Hex dump
./pktanalyzer read text capture.pcapng -x -c 1
```

### Display Filters (`-Y` / `--filter`)

Use Wireshark-like syntax to filter packets:

```bash
# Basic comparison
./pktanalyzer read text capture.pcapng -Y 'tcp.dstport == 80'

# IP address filtering
./pktanalyzer read text capture.pcapng -Y 'ip.src == "192.168.1.1"'

# Logical combination
./pktanalyzer read text capture.pcapng -Y 'ip.src == "192.168.1.1" and tcp'
./pktanalyzer read text capture.pcapng -Y 'tcp or udp'

# String containment
./pktanalyzer read text dns.pcapng -Y 'dns.qry.name contains "google"'

# Protocol filtering
./pktanalyzer read text capture.pcapng -Y 'dns'
./pktanalyzer read text capture.pcapng -Y 'http'

# Range matching
./pktanalyzer read text capture.pcapng -Y 'tcp.dstport in [80, 443, 8080]'

# Combine with JSON export
./pktanalyzer read json capture.pcapng -Y 'tcp.dstport == 443' -c 10
```

Supported filter fields can be listed with `pktanalyzer list fields`.

### Statistical Analysis (`stats`)

```bash
# Endpoint statistics
./pktanalyzer stats endpoints -r capture.pcapng

# TCP conversation statistics
./pktanalyzer stats conversations -r capture.pcapng --proto tcp

# UDP conversation statistics
./pktanalyzer stats conversations -r capture.pcapng --proto udp

# I/O statistics (1-second interval)
./pktanalyzer stats io -r capture.pcapng --interval 1

# I/O statistics (0.5-second interval)
./pktanalyzer stats io -r capture.pcapng --interval 0.5
```

### TCP Stream Following (`follow`)

First, identify a stream ID using the TUI or analysis tools, then follow it:

```bash
# ASCII format export for stream #1
./pktanalyzer follow 1 -r capture.pcapng --format ascii

# Hex format export
./pktanalyzer follow 1 -r capture.pcapng --format hex

# Raw format (direct byte output)
./pktanalyzer follow 1 -r capture.pcapng --format raw > stream.bin
```

### Expert Info System (`stats expert`)

Analyzes anomalies and issues in network packets, similar to Wireshark's Expert Information feature:

```bash
# Show all expert info
./pktanalyzer stats expert -r capture.pcapng

# Show warnings and errors only
./pktanalyzer stats expert -r capture.pcapng --severity warning

# Show errors only
./pktanalyzer stats expert -r capture.pcapng --severity error
```

**Detected TCP Anomalies**:

| Anomaly Type                | Severity | Description                                           |
| --------------------------- | -------- | ----------------------------------------------------- |
| TCP Retransmission          | Warning  | TCP Retransmission (resending same sequence > 200ms)  |
| TCP Fast Retransmission     | Warning  | Fast Retransmission (triggered by 3 duplicate ACKs)   |
| TCP Spurious Retransmission | Note     | Spurious Retransmission (data resent after ACK received) |
| TCP Duplicate ACK           | Note     | Duplicate ACK (ACK with same acknowledgment number)   |
| TCP Triple Duplicate ACK    | Warning  | Triple Duplicate ACK (triggers Fast Retransmission)   |
| TCP Out-of-Order            | Warning  | Out-of-Order Packet (sequence number less than expected)|
| TCP Zero Window             | Warning  | Zero Window (receiver buffer full)                    |
| TCP Window Update           | Note     | Window Update (recovery from Zero Window)             |
| TCP Zero Window Probe       | Note     | Zero Window Probe                                     |
| TCP Keep-Alive              | Note     | Keep-Alive Probe                                      |
| TCP Keep-Alive ACK          | Note     | Keep-Alive Response                                   |
| TCP RST                     | Warning  | Connection Reset                                      |
| TCP Connection Refused      | Error    | Connection Refused (RST received after SYN)           |
| TCP SYN Flood Suspected     | Error    | Suspected SYN Flood Attack                            |
| TCP Port Scan Suspected     | Warning  | Suspected Port Scan                                   |

**Detected DNS Anomalies**:

| Anomaly Type          | Severity | Description                     |
| --------------------- | -------- | ------------------------------- |
| DNS Query No Response | Warning  | DNS Query No Response (5s timeout) |
| DNS NXDOMAIN          | Note     | Domain Name Does Not Exist      |
| DNS SERVFAIL          | Warning  | Server Failure                  |
| DNS Query Refused     | Warning  | Query Refused                   |

**Detected HTTP Anomalies**:

| Anomaly Type             | Severity | Description                     |
| ------------------------ | -------- | ------------------------------- |
| HTTP 4xx Client Error    | Warning  | Client Error (400-499)          |
| HTTP 5xx Server Error    | Error    | Server Error (500-599)          |
| HTTP Redirect            | Note     | Redirect (300-399)              |
| HTTP Slow Response       | Warning  | Slow Response (> 3 seconds)     |
| HTTP Request No Response | Warning  | Request No Response             |

### TCP Stream Reassembly (TUI)

View complete TCP session data streams in the TUI:

```bash
# Read file and enable stream reassembly
./pktanalyzer read capture.pcapng -S

# Press 's' in TUI to switch to stream list view
```

### HTTP/2 Stream Analysis (TUI)

In TCP stream reassembly mode, pktanalyzer automatically detects and parses HTTP/2 traffic:

```bash
# Enable stream reassembly to analyze HTTP/2 traffic
./pktanalyzer read https_capture.pcapng -S

# Combine with TLS decryption to analyze encrypted HTTP/2 traffic
./pktanalyzer read https_capture.pcapng -S -k ~/sslkeys.log
```

**TUI Steps**:

1. Press `s` to enter the TCP Stream List view.
2. The stream list shows detected protocol types (HTTP/1.1, HTTP/2, TLS, etc.).
3. HTTP/2 streams are highlighted in pink.
4. Select a stream and press `Enter` to view details.

**HTTP/2 Stream Detail View**:

- **Connection Summary**: Stream count, frame count.
- **Frame List**: Summary of all HTTP/2 frames (type, stream ID, flags).
  - e.g.: `[1] SETTINGS len=18`
  - e.g.: `[2] HEADERS stream=1 len=45 flags=END_HEADERS`
  - e.g.: `[3] DATA stream=1 len=1024 flags=END_STREAM`
- **Stream Details**: Request and response for each HTTP/2 stream.
  - Request: Method, path, host, headers.
  - Response: Status code, headers.
  - Data: Request/response body size.

**HTTP/2 Frame Types**:

| Frame Type    | Description                                 |
| ------------- | ------------------------------------------- |
| DATA          | Transmits request/response body data        |
| HEADERS       | Transmits HTTP headers (HPACK compressed)   |
| PRIORITY      | Sets stream priority                        |
| RST_STREAM    | Abnormally terminates a stream              |
| SETTINGS      | Connection configuration parameters         |
| PUSH_PROMISE  | Server push promise                         |
| PING          | Connection keep-alive/latency measurement   |
| GOAWAY        | Gracefully closes connection                |
| WINDOW_UPDATE | Flow control window update                  |
| CONTINUATION  | Continuation of HEADERS/PUSH_PROMISE        |

### TLS/HTTPS Decryption

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
# Analyze saved capture file
./pktanalyzer read https_capture.pcapng -k ~/sslkeys.log

# Real-time capture and decrypt
sudo ./pktanalyzer capture en0 -k ~/sslkeys.log
```

### AI Intelligent Analysis

Use the AI assistant to analyze network packets. Supports multiple LLM providers and uses the ReAct (Reasoning and Acting) pattern for intelligent analysis.

#### Supported LLM Providers

| Provider   | Environment Variable | Default Model             | Description          |
| ---------- | -------------------- | ------------------------- | -------------------- |
| Claude     | `ANTHROPIC_API_KEY`  | claude-sonnet-4-20250514  | Anthropic Claude API |
| OpenAI     | `OPENAI_API_KEY`     | gpt-4o                    | OpenAI GPT API       |
| OpenRouter | `OPENROUTER_API_KEY` | anthropic/claude-sonnet-4 | Multi-model platform |
| Ollama     | `OLLAMA_BASE_URL`    | llama3.2                  | Locally hosted model |

**Provider Detection Priority**: `AI_PROVIDER` > `OPENROUTER_API_KEY` > `ANTHROPIC_API_KEY` > `OPENAI_API_KEY` > `OLLAMA_BASE_URL`

#### Basic Usage

```bash
# Use Claude
export ANTHROPIC_API_KEY="your-claude-api-key"
./pktanalyzer read capture.pcapng -A

# Use OpenAI
export OPENAI_API_KEY="your-openai-api-key"
./pktanalyzer read capture.pcapng -A

# Use OpenRouter
export OPENROUTER_API_KEY="your-openrouter-api-key"
./pktanalyzer read capture.pcapng -A

# Use local Ollama
export OLLAMA_BASE_URL="http://localhost:11434/v1"
./pktanalyzer read capture.pcapng -A

# Explicitly specify Provider
export AI_PROVIDER="ollama"
export OLLAMA_BASE_URL="http://localhost:11434/v1"
./pktanalyzer read capture.pcapng -A

# Real-time capture + AI analysis
sudo ./pktanalyzer capture en0 -A
```

#### AI Tool Capabilities

The AI assistant interacts with packets using the following built-in tools:

| Tool                 | Function                               | Parameters                                                                  |
| -------------------- | -------------------------------------- | --------------------------------------------------------------------------- |
| `get_packets`        | Get list of captured packets           | `limit`, `offset`, `protocol`                                               |
| `filter_packets`     | Filter packets by condition            | `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `contains`, `limit` |
| `analyze_packet`     | Analyze specific packet details        | `packet_number` (required)                                                  |
| `get_statistics`     | Get traffic statistics                 | -                                                                           |
| `explain_protocol`   | Explain protocol mechanics             | `protocol` (required), `topic`                                              |
| `find_connections`   | Find TCP connections                   | `ip`, `port`                                                                |
| `find_dns_queries`   | Find DNS query records                 | `domain`, `limit`                                                           |
| `find_http_requests` | Find HTTP requests                     | `url`, `method`, `limit`                                                    |
| `detect_anomalies`   | Detect anomalous patterns              | -                                                                           |

#### Example Conversation

Press `a` in TUI to enter AI chat mode, then converse like this:

```
You: What HTTP requests are in this capture file?
AI: [Calls find_http_requests tool]
    Found 5 HTTP requests:
    1. GET / HTTP/1.1 (google.com)
    2. GET /images/logo.png HTTP/1.1
    ...

You: Analyze packet #4
AI: [Calls analyze_packet tool]
    Packet #4 is an HTTP GET request:
    - Source: 172.16.16.128:1606
    - Destination: 74.125.95.104:80
    - Method: GET
    - URI: /
    - Host: www.google.com
    ...

You: Is there any anomalous traffic?
AI: [Calls detect_anomalies tool]
    No obvious anomalies detected. Traffic patterns are normal:
    - No signs of port scanning
    - TCP retransmission rate within normal range
    - No abnormal connection patterns

You: Explain the TCP three-way handshake
AI: [Calls explain_protocol tool]
    The TCP three-way handshake is the process of establishing a reliable connection:
    1. SYN: Client sends SYN packet, requesting connection
    2. SYN-ACK: Server responds with SYN-ACK, acknowledging request
    3. ACK: Client sends ACK, connection established
    ...
```

#### ReAct Agent Configuration

The AI uses the ReAct pattern with the following default safety policies:

| Config          | Default | Description                                 |
| --------------- | ------- | ------------------------------------------- |
| MaxIterations   | 10      | Max reasoning loops per conversation turn   |
| MaxToolsPerTurn | 5       | Max tool calls per turn                     |
| ToolTimeout     | 30s     | Timeout for single tool execution           |
| ContinueOnError | true    | Continue execution if a tool fails          |

## Command Line Arguments

pktanalyzer now uses a subcommand structure.

- `read`: Read and analyze pcap/pcapng file
  - `text`: Output packets as text
  - `json`: Output packets as JSON
  - `fields`: Extract specific fields
- `capture`: Live packet capture
  - `write`: Write captured packets to file
- `stats`: Packet statistics and analysis
  - `endpoints`: Show endpoint statistics
  - `conversations`: Show conversation statistics
  - `io`: Show I/O statistics
  - `expert`: Expert analysis
- `follow`: Follow TCP stream
- `list`: List available resources
  - `interfaces`: List network interfaces
  - `fields`: List available packet fields

Use `pktanalyzer [command] --help` for detailed usage of each command.

## TUI Shortcuts

### General Shortcuts

| Key          | Function                      |
| ------------ | ----------------------------- |
| `↑` / `k`    | Move up                       |
| `↓` / `j`    | Move down                     |
| `PgUp`       | Page up                       |
| `PgDn`       | Page down                     |
| `Home` / `g` | Jump to first packet          |
| `End` / `G`  | Jump to last packet           |
| `Enter`      | View packet details           |
| `x`          | View Hex dump                 |
| `w`          | Save packets to pcapng file   |
| `Esc`        | Return to list view           |
| `/`          | Input filter                  |
| `Space`      | Pause/Resume capture (Real-time) |
| `?`          | Show help                     |
| `q`          | Quit                          |

### TCP Stream Reassembly Shortcuts

| Key     | Function               |
| ------- | ---------------------- |
| `s`     | Switch to TCP stream list |
| `Enter` | View stream details    |
| `c`     | View client data       |
| `S`     | View server data       |
| `Esc`   | Return to previous view |

### AI Assistant Shortcuts (requires -A)

| Key     | Function               |
| ----- | ---------------------- |
| `a`     | Toggle AI chat         |
| `Tab`   | Switch split view      |
| `i`     | Enter input mode       |
| `Enter` | Send message           |
| `Esc`   | Exit input mode        |

### Expert Info Shortcuts

| Key   | Function               |
| ----- | ---------------------- |
| `e`   | Switch to expert info  |
| `1`   | Show all levels (Chat+)|
| `2`   | Show Note and above    |
| `3`   | Show Warning and above |
| `4`   | Show Error only        |
| `Esc` | Return to packet list  |

## Interface Description

### Packet List View

Displays all captured packets, including:

- Number, Timestamp
- Source/Destination Address
- Protocol Type
- Summary Information

Protocol Colors:

- TCP: Blue
- UDP: Green
- ICMP: Orange
- ARP: Purple
- DNS: Sky Blue
- HTTP: Light Green
- HTTP/2: Pink
- WebSocket: Purple
- TLS: Gold
- HTTPS (Decrypted): Bright Green

### Detail View

Press `Enter` to view details of the selected packet:

- Parsed results for each protocol layer
- TLS handshake info (ClientHello, ServerHello, SNI, etc.)
- Decrypted HTTP request/response

### Hex View

Press `x` to view the raw data in hexadecimal and ASCII representation.

## Project Structure

```
pktanalyzer/
├── main.go              # Program entry point
├── cmd/                 # CLI command definitions (Cobra)
│   ├── root.go          # Root command
│   ├── capture.go       # Capture command
│   ├── read.go          # Read command
│   ├── stats.go         # Stats command
│   ├── follow.go        # Follow command
│   └── list.go          # List command
├── capture/
│   ├── capture.go       # Capture engine and protocol parsing
│   ├── protocols.go     # Extended protocol parsers
│   └── stream.go        # TCP stream reassembly
├── stream/
│   ├── stream.go        # TCP stream management
│   ├── reassembly.go    # TCP reassembly buffer
│   ├── http.go          # HTTP/1.1 parsing
│   ├── http2.go         # HTTP/2 frame parser
│   ├── hpack.go         # HPACK header compression/decompression
│   ├── http2_stream.go  # HTTP/2 stream management and connection state
│   └── websocket.go     # WebSocket protocol parsing (RFC 6455)
├── filter/
│   └── filter.go        # Display filter (expr-lang/expr)
├── expert/
│   ├── types.go         # Expert info type definitions (Severity, Group, ExpertInfo)
│   ├── expert.go        # Expert analyzer main program
│   ├── tcp.go           # TCP anomaly detection (Retransmission, Out-of-Order, ZeroWindow, etc.)
│   ├── dns.go           # DNS anomaly detection (NXDOMAIN, Timeout, etc.)
│   └── http.go          # HTTP anomaly detection (4xx/5xx, Slow Response, etc.)
├── fields/
│   └── fields.go        # Protocol field registry
├── export/
│   └── export.go        # CLI export (text/json/fields)
├── stats/
│   └── stats.go         # Statistical analysis
├── tls/
│   ├── keylog.go        # SSLKEYLOGFILE parsing
│   ├── parser.go        # TLS protocol parsing (including ALPN extension)
│   ├── prf.go           # Key derivation function
│   └── decrypt.go       # TLS decryption engine
├── agent/
│   ├── agent.go         # AI Agent coordinator
│   ├── tools.go         # AI tool definitions and execution
│   ├── llm/
│   │   ├── types.go     # Unified LLM abstraction layer (Message, Tool, Client)
│   │   └── factory.go   # Provider detection and configuration
│   ├── providers/
│   │   ├── claude/      # Anthropic Claude implementation
│   │   ├── openai/      # OpenAI implementation (Base)
│   │   ├── openrouter/  # OpenRouter (Reuses OpenAI)
│   │   └── ollama/      # Ollama (OpenAI compatible)
│   └── react/
│       └── agent.go     # ReAct reasoning loop
├── ui/
│   ├── app.go           # TUI main program
│   ├── model.go         # Data model
│   ├── views.go         # View rendering (including HTTP/2 display)
│   └── styles.go        # Style definitions
├── go.mod
└── go.sum
```

## Tech Stack

- [cobra](https://github.com/spf13/cobra) - CLI framework
- [gopacket](https://github.com/google/gopacket) - Packet capture and parsing
- [bubbletea](https://github.com/charmbracelet/bubbletea) - TUI framework
- [lipgloss](https://github.com/charmbracelet/lipgloss) - Terminal styling
- [expr-lang/expr](https://github.com/expr-lang/expr) - Display filter expression engine

## Notes

- Real-time capture requires root privileges.
- TLS decryption only supports sessions with available keys.
- Requires capturing the complete TLS handshake process to decrypt.
- Supported cipher suites: AES-128/256-GCM, AES-128/256-CBC.
- AI assistant requires setting the environment variable for the corresponding LLM Provider.

## Environment Variables

| Variable             | Description                                                         |
| -------------------- | ------------------------------------------------------------------- |
| `AI_PROVIDER`        | Explicitly specify LLM Provider: `claude`, `openai`, `openrouter`, `ollama` |
| `AI_MODEL`           | Custom model name (overrides default)                               |
| `ANTHROPIC_API_KEY`  | Claude API Key                                                      |
| `ANTHROPIC_BASE_URL` | Claude API URL (default `https://api.anthropic.com/v1`)             |
| `OPENAI_API_KEY`     | OpenAI API Key                                                      |
| `OPENAI_BASE_URL`    | OpenAI API URL (default `https://api.openai.com/v1`, for compatible APIs) |
| `OPENROUTER_API_KEY` | OpenRouter API Key                                                  |
| `OLLAMA_BASE_URL`    | Ollama API URL (default `http://localhost:11434/v1`)                |
| `SSLKEYLOGFILE`      | TLS key log file path                                               |

## License

MIT
