package ui

import (
	"github.com/Zerofisher/pktanalyzer/agent"
	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/expert"
	"github.com/Zerofisher/pktanalyzer/stream"

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
	packets       []capture.PacketInfo
	filteredPkts  []capture.PacketInfo
	selectedIdx   int
	viewMode      ViewMode
	scrollOffset  int
	detailScroll  int
	hexScroll     int
	width         int
	height        int
	packetChan    <-chan capture.PacketInfo
	capturer      *capture.Capturer
	filter        string
	filterInput   string
	filterActive  bool
	stats         Stats
	isLive        bool
	paused        bool
	showHelp      bool
	helpScroll    int

	// Stream view state
	streamSelectedIdx  int
	streamScroll       int
	selectedStream     *stream.TCPStream
	streamDetailScroll int

	// AI Chat state
	aiAgent         *agent.Agent
	chatMessages    []ChatMessage
	chatInput       string
	chatInputActive bool
	chatScroll      int
	aiEnabled       bool
	aiProcessing    bool
	splitView       bool // Show both packets and chat
	chatTextInput   textinput.Model
	filterTextInput textinput.Model

	// AI Streaming state
	aiStreamChan     <-chan agent.StreamEvent // Channel for receiving stream events
	aiStreamContent  string                   // Accumulating streaming response content
	aiStreamingMsgID int                      // Index of the message being streamed (-1 if none)

	// Status message (for save operations, etc.)
	statusMessage string
	statusIsError bool

	// Expert analysis
	expertAnalyzer   *expert.Analyzer
	expertScroll     int
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

func (s *Stats) Update(p capture.PacketInfo) {
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

// NewModel creates a new model
func NewModel(packetChan <-chan capture.PacketInfo, capturer *capture.Capturer, isLive bool) Model {
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
		packets:           make([]capture.PacketInfo, 0),
		filteredPkts:      make([]capture.PacketInfo, 0),
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

// SetAIAgent sets the AI agent for the model
func (m *Model) SetAIAgent(a *agent.Agent) {
	m.aiAgent = a
	m.aiEnabled = a != nil
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
