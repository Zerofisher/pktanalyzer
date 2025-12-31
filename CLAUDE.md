# PktAnalyzer (Go module)

This `CLAUDE.md` is **high leverage**: it is loaded into every session. Keep it short and universally applicable.

`pktanalyzer/` is the **Go module root** (`pktanalyzer/go.mod`). The repo root (`..`) contains sample `.pcapng` captures for local testing.

## How to use this file (HumanLayer-style)

- **Less instructions is more**: avoid adding task-specific checklists here.
- Use **progressive disclosure**: keep details in separate docs and only read them when relevant.
- Prefer **pointers to sources of truth** (file paths / code) over copying snippets.
- Claude is **not a linter**: use deterministic tools (`gofmt`, `go test`, etc.) instead of manual style policing.

## Project: what it is (WHY/WHAT)

- A CLI/TUI packet analyzer (Wireshark-like) built on `gopacket/pcap`
- Inputs: live capture (`-i`) or `pcap/pcapng` file (`-r`)
- Filters:
  - capture-time BPF: `-f "tcp port 443"`
  - display filter: `filter/*` (expr-lang/expr)
- TLS keylog decryption: `-k <SSLKEYLOGFILE>` (best-effort)
- TCP stream reassembly: `-S` (`stream/*`)
- Optional AI assistant: `-A` (`agent/*`)

## Quick commands (HOW)

From `pktanalyzer/`:

- Build: `go build -o pktanalyzer`
- Run a capture: `./pktanalyzer -r ../http_google.pcapng`
- Stream reassembly: `./pktanalyzer -r ../http_google.pcapng -S`
- AI chat: `ANTHROPIC_API_KEY=... ./pktanalyzer -r ../http_google.pcapng -A`

Deterministic tools:

- Format: `gofmt -w .`
- Test: `go test ./...`

## Progressive disclosure: docs to consult

Before implementing, identify which docs are relevant and read only those:

- `README.md`: user-facing features, flags, examples
- `ROADMAP.md`: milestones + acceptance commands (also includes an **AI Agent minimal-change checklist**)
- `TESTING.md`: any existing test guidance/conventions

## Repo map (where to change what)

- `main.go`: flags and wiring (capture/stream/tls/agent/ui)
- `capture/*`: capture loop, packet parsing/heuristics
- `stream/*`: TCP stream tracking + reassembly; HTTP parsing on reassembled data
- `tls/*`: TLS parsing + keylog-based decryption
- `ui/*`: BubbleTea TUI (list/detail/hex/streams/chat)
- `agent/*`: LLM clients + ReAct loop + tool implementations
- `fields/*`: field registry
- `filter/*`: display filter compilation/eval

## Safety & privacy (captures + AI)

- Treat packet data as **sensitive** (tokens/cookies/passwords/internal IPs/hostnames).
- Never print or persist API keys; only read provider keys from env.
- Prefer **summaries/aggregations** over raw payloads when sending context to remote LLMs.
- Any new side-effectful capability (capture/export/write files/network) must require **explicit user confirmation**.

## AI assistant conventions (minimal, enforceable)

- Tools should be **deterministic**, **bounded** (`limit`/size caps), and **side-effect free by default**.
- Default outputs should avoid raw payload/hex unless the user explicitly asks.
- When making claims about traffic/anomalies, include **evidence references** (packet numbers / stream IDs) so users can jump to source.
