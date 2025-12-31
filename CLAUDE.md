# PktAnalyzer

This repo contains a Go network packet analyzer with a TUI and an optional AI assistant.

This `CLAUDE.md` lives in `pktanalyzer/`, which is also the **Go module root** (`pktanalyzer/go.mod`). The repo root (`..`) contains many sample `.pcapng` captures used for local testing.

## Principles (why this file exists)

- Treat the model as stateless: if a detail matters (how to run, where code lives, safety constraints), it must be written here or discovered from the repo each session.
- Keep instructions “high leverage”: prefer small, durable guidance over long checklists.

## What this project is

- CLI/TUI packet analyzer (Wireshark-like) built on `gopacket/pcap`
- Inputs: live capture (`-i`) or `pcap/pcapng` file (`-r`)
- Filtering:
  - capture-time BPF filter: `-f "tcp port 443"`
  - display filter (Wireshark-like): package `filter` (compiled via `expr-lang/expr`)
- TLS keylog decryption: `-k <SSLKEYLOGFILE>` (best-effort)
- TCP stream reassembly: `-S` (see `stream/*`)
- AI assistant: `-A` (Claude/OpenAI providers; see `agent/*`)

## Quick commands (local)

From `pktanalyzer/`:

- Build: `go build -o pktanalyzer`
- Run on a capture: `./pktanalyzer -r ../http_google.pcapng`
- Run with stream reassembly: `./pktanalyzer -r ../http_google.pcapng -S`
- Run with AI: `ANTHROPIC_API_KEY=... ./pktanalyzer -r ../http_google.pcapng -A`
- List interfaces: `./pktanalyzer -D`
- Live capture (needs privileges): `sudo ./pktanalyzer -i en0 -f 'tcp port 443'`

Tests/format:

- Format: `gofmt -w .`
- Test: `go test ./...`

## Repo map (where to change what)

- `main.go`: flags, wiring (capture/stream/tls/agent/ui)
- `capture/*`: capture loop, packet parsing, protocol heuristics
- `stream/*`: TCP stream tracking + reassembly; HTTP/1.1 parsing on reassembled data
- `tls/*`: TLS record/handshake parsing + (best-effort) decryption using keylog
- `ui/*`: BubbleTea TUI (list/detail/hex/streams/chat)
- `agent/*`: LLM client + tool loop + tool implementations
- `fields/*`: field registry (used by exporters/filters/agent-friendly extraction)
- `export/*`: exporters (`text/json/fields`) and verbose/hex output
- `filter/*`: display filter compilation/evaluation (`expr-lang/expr`)
- `ROADMAP.md`: tshark-aligned milestones and acceptance commands

## Project conventions (important)

### Safety & privacy (captures + AI)

- Assume packet data may contain credentials, cookies, tokens, internal hostnames/IPs, and personal data.
- Do not log or print API keys; only read `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` from env.
- If adding new “agent tool” capabilities that can capture/export/write files, require explicit user confirmation in UI/CLI before executing.
- Prefer summarizing/aggregating traffic before sending anything to a remote model; avoid uploading raw payloads by default.

### One source of truth for fields

When adding a new protocol feature, prefer this order:

1. Parse/derive it in `capture/*` and/or `stream/*`
2. Expose it as a field in `fields/fields.go`
3. Reuse fields in:
   - exporters (`export/*`)
   - display filter env mapping (`filter/*`)
   - agent tools (`agent/tools.go`)
   - UI (only for rendering, not for re-deriving semantics)

This prevents the UI/agent/exporter from each re-implementing the same logic.

### Display filter vs capture filter

- `-f` is BPF (pcap-level) and should stay a thin pass-through.
- Display filter is `filter` and is evaluated per parsed packet.
- Keep the syntax stable and document any incompatibilities with Wireshark/tshark.

## How the AI assistant works (high-level)

- The agent runs a tool loop: model proposes `tool_use` → code executes tool → tool result fed back → repeat until a final response.
- Tools are defined in `agent/tools.go` and should be:
  - deterministic
  - side-effect free by default
  - bounded (support `limit`, avoid unbounded output)

If you add new tools, keep inputs/outputs JSON-friendly and add basic validation.

## Progressive disclosure (how to work on tasks)

When implementing a feature:

1. Start with the minimal slice needed for the acceptance command in `ROADMAP.md`.
2. Prefer small, testable primitives (e.g. a new field extractor + a small exporter change) over a big UI-first change.
3. Only after the core pipeline works, add TUI polish and agent affordances.
