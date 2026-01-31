// Package model defines core data models for the observability layer.
// These models are storage-friendly summaries (no raw bytes) with evidence references.
package model

import (
	"crypto/md5"
	"fmt"
	"sort"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────────
// Evidence Reference - 证据链核心：任何结论都要能回链到原始证据
// ────────────────────────────────────────────────────────────────────────────────

// EvidenceRef points back to raw evidence in the original pcap file.
// This allows AI/reports to cite specific packets without storing raw bytes.
type EvidenceRef struct {
	PcapFile      string    `json:"pcap_file,omitempty"`       // Source pcap filename
	PacketNumbers []int     `json:"packet_numbers,omitempty"`  // Related packet numbers (1-based, Wireshark style)
	FlowID        string    `json:"flow_id,omitempty"`         // Related flow identifier
	StreamID      int       `json:"stream_id,omitempty"`       // TCP stream index (if applicable)
	TimeRange     TimeRange `json:"time_range,omitempty"`      // Time window of the evidence
}

// TimeRange represents a time window.
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ────────────────────────────────────────────────────────────────────────────────
// PacketSummary - 包摘要（不含 RawData，只存索引必需字段）
// ────────────────────────────────────────────────────────────────────────────────

// PacketSummary is a storage-friendly packet representation.
// It contains only fields needed for filtering, display, and indexing.
// Raw bytes remain in the original pcap file, referenced by Number.
type PacketSummary struct {
	// Identity
	Number        int   `json:"number"`         // Packet number (1-based)
	TimestampNS   int64 `json:"timestamp_ns"`   // Unix nanoseconds
	Length        int   `json:"length"`         // Original packet length
	CaptureLength int   `json:"capture_length"` // Captured length

	// Layer 2
	SrcMAC  string `json:"src_mac,omitempty"`
	DstMAC  string `json:"dst_mac,omitempty"`
	EthType uint16 `json:"eth_type,omitempty"`

	// Layer 3
	SrcIP     string `json:"src_ip,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	IPVersion int    `json:"ip_version,omitempty"`
	IPProto   int    `json:"ip_proto,omitempty"`
	TTL       int    `json:"ttl,omitempty"`

	// Layer 4
	Protocol  string `json:"protocol"`           // TCP, UDP, ICMP, etc.
	SrcPort   int    `json:"src_port,omitempty"`
	DstPort   int    `json:"dst_port,omitempty"`
	TCPFlags  uint16 `json:"tcp_flags,omitempty"`
	TCPSeq    uint32 `json:"tcp_seq,omitempty"`
	TCPAck    uint32 `json:"tcp_ack,omitempty"`
	TCPWindow uint16 `json:"tcp_window,omitempty"`

	// Layer 7 hints
	AppProtocol string `json:"app_protocol,omitempty"` // HTTP, DNS, TLS, etc.
	Info        string `json:"info,omitempty"`         // One-line summary

	// TLS
	SNI       string `json:"sni,omitempty"`
	Decrypted bool   `json:"decrypted,omitempty"`

	// Flow correlation
	FlowID string `json:"flow_id,omitempty"`

	// Evidence pointer (for raw data lookup)
	Evidence PacketEvidence `json:"evidence,omitempty"`
}

// PacketEvidence points to the raw packet in the original file.
type PacketEvidence struct {
	FilePath   string `json:"file_path,omitempty"`
	FileOffset int64  `json:"file_offset,omitempty"`
}

// Timestamp returns the packet timestamp as time.Time.
func (p *PacketSummary) Timestamp() time.Time {
	return time.Unix(0, p.TimestampNS)
}

// ────────────────────────────────────────────────────────────────────────────────
// FlowKey & Flow - 流/连接级聚合
// ────────────────────────────────────────────────────────────────────────────────

// FlowKey uniquely identifies a bidirectional flow (normalized).
type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  int
	DstPort  int
	Protocol string
}

// Normalize ensures consistent ordering (smaller IP:port first) for bidirectional matching.
func (k FlowKey) Normalize() FlowKey {
	// Compare by IP first, then port
	srcKey := fmt.Sprintf("%s:%d", k.SrcIP, k.SrcPort)
	dstKey := fmt.Sprintf("%s:%d", k.DstIP, k.DstPort)
	if srcKey > dstKey {
		return FlowKey{
			SrcIP:    k.DstIP,
			DstIP:    k.SrcIP,
			SrcPort:  k.DstPort,
			DstPort:  k.SrcPort,
			Protocol: k.Protocol,
		}
	}
	return k
}

// ID returns a stable hash-based identifier for this flow.
func (k FlowKey) ID() string {
	nk := k.Normalize()
	data := fmt.Sprintf("%s|%d|%s|%d|%s", nk.SrcIP, nk.SrcPort, nk.DstIP, nk.DstPort, nk.Protocol)
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", hash[:8])
}

// Flow represents an aggregated network flow/connection.
type Flow struct {
	ID       string `json:"id"`       // Stable identifier (hash of FlowKey)
	Protocol string `json:"protocol"` // TCP, UDP, etc.

	// Endpoints (normalized: SrcIP < DstIP or SrcIP:SrcPort < DstIP:DstPort)
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	SrcPort int    `json:"src_port,omitempty"`
	DstPort int    `json:"dst_port,omitempty"`

	// State
	State string `json:"state"` // unknown, syn_sent, established, fin_wait, closed, etc.

	// Time range (nanoseconds for storage precision)
	StartNS int64 `json:"start_ns"`
	EndNS   int64 `json:"end_ns,omitempty"`

	// Counters
	Packets    int   `json:"packets"`
	Bytes      int64 `json:"bytes"`
	FwdPackets int   `json:"fwd_packets"` // Direction A→B
	FwdBytes   int64 `json:"fwd_bytes"`
	BwdPackets int   `json:"bwd_packets"` // Direction B→A
	BwdBytes   int64 `json:"bwd_bytes"`

	// TCP metrics (if applicable)
	Retrans    int   `json:"retrans,omitempty"`
	RTTSamples []int `json:"rtt_samples,omitempty"` // RTT samples in microseconds
	RTTAvgUS   int   `json:"rtt_avg_us,omitempty"`
	RTTMinUS   int   `json:"rtt_min_us,omitempty"`
	RTTMaxUS   int   `json:"rtt_max_us,omitempty"`

	// Application layer hints
	AppProtocol   string `json:"app_protocol,omitempty"` // HTTP, DNS, TLS, etc.
	TLSServerName string `json:"tls_server_name,omitempty"`

	// Metadata (JSON for protocol-specific data)
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Evidence
	PacketNumbers []int `json:"packet_numbers,omitempty"` // First N packet numbers for reference
}

// StartTime returns the flow start time.
func (f *Flow) StartTime() time.Time {
	return time.Unix(0, f.StartNS)
}

// EndTime returns the flow end time.
func (f *Flow) EndTime() time.Time {
	return time.Unix(0, f.EndNS)
}

// Duration returns the flow duration.
func (f *Flow) Duration() time.Duration {
	return time.Duration(f.EndNS - f.StartNS)
}

// ────────────────────────────────────────────────────────────────────────────────
// Transaction - 应用层事务（DNS query/response, HTTP request/response）
// ────────────────────────────────────────────────────────────────────────────────

// TransactionType identifies the type of application-layer transaction.
type TransactionType string

const (
	TransactionDNS       TransactionType = "dns"
	TransactionHTTP      TransactionType = "http"
	TransactionHTTP2     TransactionType = "http2"
	TransactionWebSocket TransactionType = "websocket"
	TransactionTLS       TransactionType = "tls"
)

// Transaction represents an application-layer request/response pair.
type Transaction struct {
	ID     string          `json:"id"`
	Type   TransactionType `json:"type"`
	FlowID string          `json:"flow_id"`

	// Time (nanoseconds for storage)
	StartNS   int64 `json:"start_ns"`
	EndNS     int64 `json:"end_ns,omitempty"`
	LatencyUS int64 `json:"latency_us,omitempty"` // Response latency in microseconds

	// Status
	Status string `json:"status,omitempty"` // OK, NXDOMAIN, 404, etc.

	// Packet references
	RequestPackets  []int `json:"request_packets,omitempty"`
	ResponsePackets []int `json:"response_packets,omitempty"`

	// Metadata (protocol-specific details as JSON)
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// StartTime returns the transaction start time.
func (t *Transaction) StartTime() time.Time {
	return time.Unix(0, t.StartNS)
}

// ────────────────────────────────────────────────────────────────────────────────
// ExpertEvent - 专家系统事件（异常/警告/提示）
// ────────────────────────────────────────────────────────────────────────────────

// Severity levels for expert events (matches Wireshark Expert Info).
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityNote    Severity = "note"
	SeverityChat    Severity = "chat"
)

// SeverityOrder returns numeric order for sorting (higher = more severe).
func (s Severity) Order() int {
	switch s {
	case SeverityError:
		return 4
	case SeverityWarning:
		return 3
	case SeverityNote:
		return 2
	case SeverityChat:
		return 1
	default:
		return 0
	}
}

// EventGroup categorizes expert events.
type EventGroup string

const (
	GroupTCP       EventGroup = "tcp"
	GroupDNS       EventGroup = "dns"
	GroupHTTP      EventGroup = "http"
	GroupTLS       EventGroup = "tls"
	GroupSecurity  EventGroup = "security"
	GroupPerformance EventGroup = "performance"
)

// ExpertEvent represents a detected anomaly, warning, or informational note.
type ExpertEvent struct {
	ID        string     `json:"id"`
	Severity  Severity   `json:"severity"`
	Group     EventGroup `json:"group"`
	Type      string     `json:"type"`      // e.g., "tcp_retransmission", "dns_nxdomain"
	Message   string     `json:"message"`   // Human-readable description
	TimestampNS int64    `json:"timestamp_ns"`

	// Context
	FlowID    string `json:"flow_id,omitempty"`
	Summary   string `json:"summary,omitempty"` // Brief context for AI

	// Evidence packet range
	PacketStart int `json:"packet_start"`
	PacketEnd   int `json:"packet_end"`
}

// Timestamp returns the event timestamp.
func (e *ExpertEvent) Timestamp() time.Time {
	return time.Unix(0, e.TimestampNS)
}

// ────────────────────────────────────────────────────────────────────────────────
// IndexMeta - 索引元数据（用于缓存校验）
// ────────────────────────────────────────────────────────────────────────────────

// IndexMeta stores metadata about the indexed pcap file.
type IndexMeta struct {
	SchemaVersion int       `json:"schema_version"`
	PcapPath      string    `json:"pcap_path"`
	PcapSize      int64     `json:"pcap_size"`
	PcapModified  time.Time `json:"pcap_modified"`
	IndexedAt     time.Time `json:"indexed_at"`
	TotalPackets  int       `json:"total_packets"`
	TotalBytes    int64     `json:"total_bytes"`
	DurationNS    int64     `json:"duration_ns"`
	IndexComplete bool      `json:"index_complete"`
}

// ────────────────────────────────────────────────────────────────────────────────
// Helper functions
// ────────────────────────────────────────────────────────────────────────────────

// SortExpertEventsBySeverity sorts events by severity (most severe first).
func SortExpertEventsBySeverity(events []ExpertEvent) {
	sort.Slice(events, func(i, j int) bool {
		if events[i].Severity.Order() != events[j].Severity.Order() {
			return events[i].Severity.Order() > events[j].Severity.Order()
		}
		return events[i].TimestampNS < events[j].TimestampNS
	})
}

// FilterEventsBySeverity returns events at or above the given severity level.
func FilterEventsBySeverity(events []ExpertEvent, minSeverity Severity) []ExpertEvent {
	minOrder := minSeverity.Order()
	var result []ExpertEvent
	for _, e := range events {
		if e.Severity.Order() >= minOrder {
			result = append(result, e)
		}
	}
	return result
}
