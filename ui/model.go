package ui

import (
	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/expert"
	"github.com/Zerofisher/pktanalyzer/stream"
	uiadapter "github.com/Zerofisher/pktanalyzer/ui/adapter"

	"github.com/charmbracelet/bubbles/textinput"
)

// ViewMode represents the current view mode
type ViewMode int

const (
	ViewList ViewMode = iota
	ViewDetail
	ViewHex
	ViewStreamList
	ViewStreamDetail
	ViewChat   // AI chat view
	ViewExpert // Expert info view
)

// ChatMessage represents a message in the chat view
type ChatMessage struct {
	Role    string // "user", "assistant", "system"
	Content string
	IsError bool
}

// Model holds the application state
type Model struct {
	// PacketStore is the unified data source for packets
	store uiadapter.PacketStore

	// View state
	selectedIdx  int
	viewMode     ViewMode
	scrollOffset int
	detailScroll int
	hexScroll    int
	width        int
	height       int

	// For live capture mode - used to receive packets into store
	packetChan <-chan capture.PacketInfo
	capturer   *capture.Capturer

	// Filter state (now delegated to store)
	filter       string
	filterActive bool

	// Stats (computed from store or captured)
	stats  Stats
	isLive bool
	paused bool

	// Help overlay
	showHelp   bool
	helpScroll int

	// Stream view state
	streamSelectedIdx  int
	streamScroll       int
	selectedStream     *stream.TCPStream
	streamDetailScroll int

	// AI Chat state
	aiAssistant     uiadapter.AIAssistant
	chatMessages    []ChatMessage
	chatInputActive bool
	chatScroll      int
	aiEnabled       bool
	aiProcessing    bool
	splitView       bool // Show both packets and chat
	chatTextInput   textinput.Model
	filterTextInput textinput.Model

	// AI Streaming state
	aiStreamChan     <-chan uiadapter.StreamEvent // Channel for receiving stream events
	aiStreamContent  string                       // Accumulating streaming response content
	aiStreamingMsgID int                          // Index of the message being streamed (-1 if none)

	// Authorization confirmation dialog
	showConfirmDialog   bool                            // Whether to show confirmation dialog
	pendingConfirmation *uiadapter.ConfirmationRequest  // Current pending confirmation

	// Status message (for save operations, etc.)
	statusMessage string
	statusIsError bool

	// Expert analysis
	expertAnalyzer    *expert.Analyzer
	expertScroll      int
	expertMinSeverity expert.Severity // Minimum severity to show
}

// Stats holds packet statistics
type Stats struct {
	Total     int
	TCP       int
	UDP       int
	ICMP      int
	ARP       int
	DNS       int
	HTTP      int
	HTTPS     int
	TLS       int
	Decrypted int
	Other     int
	IPv4      int
	IPv6      int
	Streams   int
}

func (s *Stats) Update(p *uiadapter.DisplayPacket) {
	s.Total++
	switch p.Protocol {
	case "TCP":
		s.TCP++
	case "UDP":
		s.UDP++
	case "ICMP", "ICMPv6":
		s.ICMP++
	case "ARP":
		s.ARP++
	case "DNS":
		s.DNS++
	case "HTTP":
		s.HTTP++
	case "HTTPS":
		s.HTTPS++
		if p.Decrypted {
			s.Decrypted++
		}
	case "TLS":
		s.TLS++
	default:
		s.Other++
	}

	if p.SrcIP != "" {
		if len(p.SrcIP) > 15 || containsColon(p.SrcIP) {
			s.IPv6++
		} else {
			s.IPv4++
		}
	}
}

// UpdateFromPacketInfo updates stats from capture.PacketInfo (for live mode).
func (s *Stats) UpdateFromPacketInfo(p capture.PacketInfo) {
	s.Total++
	switch p.Protocol {
	case "TCP":
		s.TCP++
	case "UDP":
		s.UDP++
	case "ICMP", "ICMPv6":
		s.ICMP++
	case "ARP":
		s.ARP++
	case "DNS":
		s.DNS++
	case "HTTP":
		s.HTTP++
	case "HTTPS":
		s.HTTPS++
		if p.Decrypted {
			s.Decrypted++
		}
	case "TLS":
		s.TLS++
	default:
		s.Other++
	}

	if p.SrcIP != "" {
		if len(p.SrcIP) > 15 || containsColon(p.SrcIP) {
			s.IPv6++
		} else {
			s.IPv4++
		}
	}
}

func containsColon(s string) bool {
	for _, c := range s {
		if c == ':' {
			return true
		}
	}
	return false
}

// NewModel creates a new model for live capture mode.
// The store should be a MemoryStore that will receive packets.
func NewModel(store uiadapter.PacketStore, packetChan <-chan capture.PacketInfo, capturer *capture.Capturer, isLive bool) Model {
	// Initialize chat text input
	chatTi := textinput.New()
	chatTi.Placeholder = "输入消息..."
	chatTi.CharLimit = 500
	chatTi.Width = 60

	// Initialize filter text input
	filterTi := textinput.New()
	filterTi.Placeholder = "filter..."
	filterTi.CharLimit = 100
	filterTi.Width = 40

	return Model{
		store:             store,
		packetChan:        packetChan,
		capturer:          capturer,
		viewMode:          ViewList,
		isLive:            isLive,
		chatMessages:      make([]ChatMessage, 0),
		chatTextInput:     chatTi,
		filterTextInput:   filterTi,
		aiStreamingMsgID:  -1,
		expertAnalyzer:    expert.NewAnalyzer(),
		expertMinSeverity: expert.SeverityNote, // Default to showing Note and above
	}
}

// NewModelWithStore creates a new model from a PacketStore (for indexed mode).
func NewModelWithStore(store uiadapter.PacketStore) Model {
	// Initialize chat text input
	chatTi := textinput.New()
	chatTi.Placeholder = "输入消息..."
	chatTi.CharLimit = 500
	chatTi.Width = 60

	// Initialize filter text input
	filterTi := textinput.New()
	filterTi.Placeholder = "filter..."
	filterTi.CharLimit = 100
	filterTi.Width = 40

	return Model{
		store:             store,
		viewMode:          ViewList,
		isLive:            store.IsLive(),
		chatMessages:      make([]ChatMessage, 0),
		chatTextInput:     chatTi,
		filterTextInput:   filterTi,
		aiStreamingMsgID:  -1,
		expertAnalyzer:    expert.NewAnalyzer(),
		expertMinSeverity: expert.SeverityNote,
	}
}

// SetAIAssistant sets the AI assistant for the model
func (m *Model) SetAIAssistant(ai uiadapter.AIAssistant) {
	m.aiAssistant = ai
	m.aiEnabled = ai != nil
}

// AddChatMessage adds a message to the chat history
func (m *Model) AddChatMessage(role, content string, isError bool) {
	m.chatMessages = append(m.chatMessages, ChatMessage{
		Role:    role,
		Content: content,
		IsError: isError,
	})
}

// GetStreams returns all TCP streams from the stream manager
func (m *Model) GetStreams() []*stream.TCPStream {
	if m.capturer == nil {
		return nil
	}
	mgr := m.capturer.GetStreamManager()
	if mgr == nil {
		return nil
	}
	return mgr.GetAllStreams()
}

// StreamEnabled returns true if stream tracking is enabled
func (m *Model) StreamEnabled() bool {
	if m.capturer == nil {
		return false
	}
	mgr := m.capturer.GetStreamManager()
	return mgr != nil && mgr.IsEnabled()
}

// GetExpertAnalyzer returns the expert analyzer
func (m *Model) GetExpertAnalyzer() *expert.Analyzer {
	return m.expertAnalyzer
}

// AnalyzePacket runs expert analysis on a packet
func (m *Model) AnalyzePacket(pkt *capture.PacketInfo) {
	if m.expertAnalyzer != nil {
		m.expertAnalyzer.Analyze(pkt)
	}
}

// GetStore returns the underlying PacketStore
func (m *Model) GetStore() uiadapter.PacketStore {
	return m.store
}

// getDisplayPackets returns packets for display, respecting filter.
func (m *Model) getDisplayPackets() []*uiadapter.DisplayPacket {
	if m.store == nil {
		return nil
	}

	// For now, get a reasonable window of packets
	// In the future, this should be paginated based on scroll position
	if m.store.IsFiltered() {
		return m.store.GetFilteredRange(0, m.store.FilteredCount())
	}
	return m.store.GetRange(0, m.store.Count())
}

// getDisplayPacketsRange returns a range of packets for display.
func (m *Model) getDisplayPacketsRange(offset, limit int) []*uiadapter.DisplayPacket {
	if m.store == nil {
		return nil
	}

	if m.store.IsFiltered() {
		return m.store.GetFilteredRange(offset, limit)
	}
	return m.store.GetRange(offset, limit)
}

// getPacketCount returns the total number of displayable packets.
func (m *Model) getPacketCount() int {
	if m.store == nil {
		return 0
	}
	if m.store.IsFiltered() {
		return m.store.FilteredCount()
	}
	return m.store.Count()
}

// getSelectedPacket returns the currently selected packet.
func (m *Model) getSelectedPacket() *uiadapter.DisplayPacket {
	if m.store == nil || m.selectedIdx < 0 {
		return nil
	}
	count := m.getPacketCount()
	if m.selectedIdx >= count {
		return nil
	}
	// For efficiency, get just the selected packet
	packets := m.getDisplayPacketsRange(m.selectedIdx, 1)
	if len(packets) > 0 {
		return packets[0]
	}
	return nil
}
