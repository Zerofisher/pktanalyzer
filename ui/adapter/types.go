// Package uiadapter provides unified data access for TUI.
// It supports both indexed mode (reading from SQLite) and live mode (receiving from channel).
package uiadapter

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/pkg/model"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
)

// DataProvider provides unified data access for TUI.
// It abstracts the difference between indexed mode and live mode.
type DataProvider interface {
	// Mode
	IsLive() bool
	IsIndexed() bool

	// Packets - 分页查询
	GetPacketCount() int
	GetPackets(offset, limit int) ([]*DisplayPacket, error)
	GetPacket(number int) (*DisplayPacket, error)
	GetRawPacket(number int) ([]byte, error)

	// Flows
	GetFlowCount() int
	GetFlows(offset, limit int) ([]*model.Flow, error)
	GetFlow(id string) (*model.Flow, error)

	// Expert Events
	GetExpertEvents(minSeverity int) ([]*model.ExpertEvent, error)
	GetExpertEventCount() int

	// Statistics
	GetStats() *Stats
	GetOverview() (*query.Overview, error)

	// For live mode: receive packets
	ReceivePacket() <-chan *DisplayPacket

	// Lifecycle
	Close() error
}

// StreamEvent represents an AI streaming event.
// This mirrors agent.StreamEvent without importing it directly.
type StreamEvent struct {
	Type          string // delta, tool_start, tool_end, error, end
	Delta         string
	ToolName      string
	ToolExecuting bool
	Error         error
}

// ConfirmationRequest represents an authorization request from AI.
type ConfirmationRequest struct {
	ToolName    string
	Description string
	Reason      string
	Context     map[string]interface{}
	Responded   bool
	Granted     bool
}

// AIAssistant provides AI chat capabilities for the TUI.
// This interface allows ui package to work with AI without importing agent package.
type AIAssistant interface {
	// Chat sends a message and returns a stream of events
	ChatStream(message string) (<-chan StreamEvent, error)

	// Processing state
	IsProcessing() bool

	// Authorization handling
	HasPendingConfirmation() bool
	GetPendingConfirmation() *ConfirmationRequest
	GrantAuthorization(forSession bool)
	DenyAuthorization()
	ClearPendingAuthorization()
	RetryLastToolCall() (string, error)
}

// DisplayPacket is a TUI-friendly packet representation.
// It bridges model.PacketSummary and capture.PacketInfo.
type DisplayPacket struct {
	Number    int
	Timestamp time.Time
	Length    int
	SrcMAC    string
	DstMAC    string
	SrcIP     string
	DstIP     string
	SrcPort   string
	DstPort   string
	Protocol  string
	Info      string
	FlowID    string
	SNI       string
	Decrypted bool

	// TCP specific
	TCPFlags  uint16
	TCPSeq    uint32
	TCPAck    uint32
	TCPWindow uint16

	// For detail view - lazily loaded
	Layers []LayerInfo

	// Evidence for raw data lookup
	PcapPath   string
	FileOffset int64

	// Original capture.PacketInfo (only in live mode)
	RawPacketInfo *capture.PacketInfo
}

// LayerInfo represents a protocol layer for display.
type LayerInfo struct {
	Name    string
	Details []string
}

// Stats holds protocol statistics.
type Stats struct {
	mu         sync.RWMutex
	ByProtocol map[string]int
	TotalBytes int64
}

// NewStats creates a new Stats instance.
func NewStats() *Stats {
	return &Stats{
		ByProtocol: make(map[string]int),
	}
}

// Update updates stats with a new packet.
func (s *Stats) Update(p *DisplayPacket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ByProtocol[p.Protocol]++
	s.TotalBytes += int64(p.Length)
}

// Get returns a copy of protocol counts.
func (s *Stats) Get() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]int, len(s.ByProtocol))
	for k, v := range s.ByProtocol {
		result[k] = v
	}
	return result
}

// ConvertFromPacketInfo converts capture.PacketInfo to DisplayPacket.
func ConvertFromPacketInfo(p *capture.PacketInfo) *DisplayPacket {
	dp := &DisplayPacket{
		Number:        p.Number,
		Timestamp:     p.Timestamp,
		Length:        p.Length,
		SrcMAC:        p.SrcMAC,
		DstMAC:        p.DstMAC,
		SrcIP:         p.SrcIP,
		DstIP:         p.DstIP,
		SrcPort:       p.SrcPort,
		DstPort:       p.DstPort,
		Protocol:      p.Protocol,
		Info:          p.Info,
		SNI:           p.SNI,
		Decrypted:     p.Decrypted,
		TCPFlags:      p.TCPFlags,
		TCPSeq:        p.TCPSeq,
		TCPAck:        p.TCPAck,
		TCPWindow:     p.TCPWindow,
		FlowID:        p.StreamKey,
		RawPacketInfo: p,
	}

	// Convert layers
	for _, l := range p.Layers {
		dp.Layers = append(dp.Layers, LayerInfo{
			Name:    l.Name,
			Details: l.Details,
		})
	}

	return dp
}

// ConvertFromPacketSummary converts model.PacketSummary to DisplayPacket.
func ConvertFromPacketSummary(p *model.PacketSummary) *DisplayPacket {
	return &DisplayPacket{
		Number:     p.Number,
		Timestamp:  p.Timestamp(),
		Length:     p.Length,
		SrcMAC:     p.SrcMAC,
		DstMAC:     p.DstMAC,
		SrcIP:      p.SrcIP,
		DstIP:      p.DstIP,
		SrcPort:    formatPort(p.SrcPort),
		DstPort:    formatPort(p.DstPort),
		Protocol:   p.Protocol,
		Info:       p.Info,
		SNI:        p.SNI,
		Decrypted:  p.Decrypted,
		TCPFlags:   p.TCPFlags,
		TCPSeq:     p.TCPSeq,
		TCPAck:     p.TCPAck,
		TCPWindow:  p.TCPWindow,
		FlowID:     p.FlowID,
		PcapPath:   p.Evidence.FilePath,
		FileOffset: p.Evidence.FileOffset,
	}
}

func formatPort(port int) string {
	if port == 0 {
		return ""
	}
	return fmt.Sprintf("%d", port)
}

// FormatTimestamp formats timestamp for display.
func (p *DisplayPacket) FormatTimestamp() string {
	return p.Timestamp.Format("15:04:05.000000")
}

// FormatSrcEndpoint formats source endpoint for display.
func (p *DisplayPacket) FormatSrcEndpoint() string {
	if p.SrcIP != "" {
		if p.SrcPort != "" && p.SrcPort != "0" {
			return fmt.Sprintf("%s:%s", p.SrcIP, p.SrcPort)
		}
		return p.SrcIP
	}
	// Fallback to MAC address for non-IP packets (e.g., 802.11)
	return formatMAC(p.SrcMAC)
}

// FormatDstEndpoint formats destination endpoint for display.
func (p *DisplayPacket) FormatDstEndpoint() string {
	if p.DstIP != "" {
		if p.DstPort != "" && p.DstPort != "0" {
			return fmt.Sprintf("%s:%s", p.DstIP, p.DstPort)
		}
		return p.DstIP
	}
	// Fallback to MAC address for non-IP packets (e.g., 802.11)
	return formatMAC(p.DstMAC)
}

// formatMAC formats a MAC address for display (similar to Wireshark).
func formatMAC(mac string) string {
	if mac == "" {
		return ""
	}
	if mac == "ff:ff:ff:ff:ff:ff" {
		return "Broadcast"
	}
	// Return shortened format: vendor_xx:xx:xx
	parts := strings.Split(mac, ":")
	if len(parts) == 6 {
		return fmt.Sprintf("%s%s%s_%s:%s:%s", parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])
	}
	return mac
}

// HasRawData returns true if raw packet data is immediately available.
func (p *DisplayPacket) HasRawData() bool {
	return p.RawPacketInfo != nil && len(p.RawPacketInfo.RawData) > 0
}

// CanLoadRaw returns true if raw data can be loaded from PCAP file.
func (p *DisplayPacket) CanLoadRaw() bool {
	return p.PcapPath != ""
}
