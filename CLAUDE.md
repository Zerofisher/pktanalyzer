# PktAnalyzer

Go module root: `pktanalyzer/go.mod`. Test captures: `examples/*.pcap*`

## What (WHAT)

CLI/TUI packet analyzer (Wireshark-like) on `gopacket/pcap`:
- Live capture (`-i`) or file (`-r`)
- BPF filter (`-f`), display filter (`filter/*`)
- TLS decryption (`-k`), TCP reassembly (`-S`), AI assistant (`-A`)

## Why (WHY)

Lightweight alternative to Wireshark for CLI workflows, with optional AI-powered analysis.

## How (HOW)

```bash
go build -o pktanalyzer                              # build
./pktanalyzer -r examples/http_google.pcapng         # run
go test ./...                                        # test
gofmt -w .                                           # format
```

## Docs (progressive disclosure)

Read only when relevant:
- `README.md` - user-facing features/flags
- `ROADMAP.md` - milestones, acceptance criteria
- `TESTING.md` - test conventions

## Repo map

| Path | Purpose |
|------|---------|
| `main.go` | CLI flags, wiring |
| `capture/*` | Packet capture/parsing |
| `stream/*` | TCP reassembly, HTTP parsing |
| `tls/*` | TLS parsing, keylog decryption |
| `ui/*` | BubbleTea TUI |
| `agent/*` | LLM clients, ReAct loop, tools |
| `filter/*` | Display filter (expr-lang) |
| `fields/*` | Field registry |

## Constraints

- Packet data is **sensitive** - no raw payloads to LLMs without summarization
- API keys from env only - never print/persist
- Side-effectful actions require **user confirmation**
- AI tools must be **bounded** (limit/size caps) and **side-effect free by default**
