// Package query provides unified query interfaces for TUI and AI modules.
// All data access should go through this package instead of directly accessing store.
package query

import (
	"context"
	"time"

	"github.com/Zerofisher/pktanalyzer/pkg/model"
)

// QueryEngine provides the main query interface.
type QueryEngine interface {
	// Packet queries
	GetPacket(ctx context.Context, number int) (*model.PacketSummary, error)
	GetPackets(ctx context.Context, filter PacketFilter) ([]*model.PacketSummary, error)
	GetPacketCount(ctx context.Context) (int, error)

	// Flow queries
	GetFlow(ctx context.Context, id string) (*model.Flow, error)
	GetFlows(ctx context.Context, filter FlowFilter) ([]*model.Flow, error)
	GetFlowCount(ctx context.Context) (int, error)
	GetFlowPackets(ctx context.Context, flowID string, limit int) ([]*model.PacketSummary, error)

	// Expert event queries
	GetExpertEvents(ctx context.Context, filter EventFilter) ([]*model.ExpertEvent, error)
	GetExpertEventsByFlow(ctx context.Context, flowID string) ([]*model.ExpertEvent, error)
	GetExpertEventsByPacket(ctx context.Context, packetNum int) ([]*model.ExpertEvent, error)
	GetEventSummary(ctx context.Context) (*EventSummary, error)

	// Statistics
	GetProtocolStats(ctx context.Context) ([]*ProtocolStat, error)
	GetTopTalkers(ctx context.Context, limit int) ([]*TopTalker, error)
	GetOverview(ctx context.Context) (*Overview, error)

	// Meta
	GetIndexMeta(ctx context.Context) (*model.IndexMeta, error)
	IsIndexed(ctx context.Context) bool
	GetPcapPath(ctx context.Context) string
}

// PacketFilter defines filters for packet queries.
type PacketFilter struct {
	// Offset for pagination
	Offset int
	// Limit for pagination (0 means no limit)
	Limit int

	// Time range
	StartTime time.Time
	EndTime   time.Time

	// Address filters
	SrcIP   string
	DstIP   string
	IP      string // Either src or dst
	SrcPort int
	DstPort int
	Port    int // Either src or dst

	// Protocol filter
	Protocol string

	// Flow filter
	FlowID string

	// Text search in Info
	SearchText string

	// Sorting
	SortBy    string // "number", "timestamp", "protocol", "length"
	SortOrder string // "asc", "desc"
}

// FlowFilter defines filters for flow queries.
type FlowFilter struct {
	Offset int
	Limit  int

	// Address filters
	IP   string
	Port int

	// Protocol filter
	Protocol string

	// Size filters
	MinPackets int
	MaxPackets int
	MinBytes   int64
	MaxBytes   int64

	// TLS filter
	HasTLS      *bool
	TLSHostname string

	// Sorting
	SortBy    string // "packets", "bytes", "start_time", "duration"
	SortOrder string // "asc", "desc"
}

// EventFilter defines filters for expert event queries.
type EventFilter struct {
	Offset int
	Limit  int

	// Severity filters
	MinSeverity int      // 1=note, 2=warning, 3=error, 4=critical
	Severities  []string // ["warning", "error", "critical"]

	// Category filter
	Categories []string // ["security", "performance", "protocol_error", ...]

	// Flow filter
	FlowID string

	// Text search
	SearchText string

	// Time range
	StartTime time.Time
	EndTime   time.Time

	// Sorting
	SortBy    string // "severity", "timestamp", "category"
	SortOrder string
}

// EventSummary provides a summary of expert events.
type EventSummary struct {
	TotalEvents int
	BySeverity  map[string]int // critical, error, warning, note
	ByCategory  map[string]int
	TopEvents   []*model.ExpertEvent // Top 10 most severe
}

// ProtocolStat holds protocol statistics.
type ProtocolStat struct {
	Protocol string
	Packets  int
	Bytes    int64
	Percent  float64
}

// TopTalker represents a host with high traffic.
type TopTalker struct {
	IP      string
	Packets int
	Bytes   int64
	Flows   int
}

// Overview provides high-level summary information.
type Overview struct {
	// File info
	PcapPath     string
	PcapSize     int64
	IndexedAt    time.Time
	IndexVersion string

	// Capture info
	StartTime       time.Time
	EndTime         time.Time
	Duration        time.Duration
	TotalPackets    int
	TotalBytes      int64
	AvgPacketSize   float64
	PacketsPerSec   float64
	BytesPerSec     float64

	// Protocol distribution
	TopProtocols []*ProtocolStat

	// Flow info
	TotalFlows    int
	ActiveFlows   int
	CompletedFlows int

	// Expert events summary
	CriticalEvents int
	ErrorEvents    int
	WarningEvents  int
	NoteEvents     int
}
