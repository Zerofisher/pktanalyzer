// Package ui provides the TUI interface for pktanalyzer.
package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/Zerofisher/pktanalyzer/pkg/model"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
	uiadapter "github.com/Zerofisher/pktanalyzer/ui/adapter"

	tea "github.com/charmbracelet/bubbletea"
)

// RunIndexedWithProvider runs the TUI in indexed mode with the given provider.
// This is the preferred entry point as it accepts interfaces instead of concrete types.
func RunIndexedWithProvider(provider uiadapter.DataProvider, ai uiadapter.AIAssistant) error {
	m := NewIndexedModel(provider, ai)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// indexedStreamStartMsg indicates stream has started with channel reference (for indexed mode)
type indexedStreamStartMsg struct {
	eventChan <-chan uiadapter.StreamEvent
	err       error
}

// indexedStreamMsg contains a streaming event (for indexed mode)
type indexedStreamMsg struct {
	event uiadapter.StreamEvent
	done  bool
}

// sendIndexedAIMessage starts streaming AI response for indexed mode
func sendIndexedAIMessage(ai uiadapter.AIAssistant, message string) tea.Cmd {
	return func() tea.Msg {
		eventChan, err := ai.ChatStream(message)
		if err != nil {
			return indexedStreamStartMsg{err: err}
		}
		return indexedStreamStartMsg{eventChan: eventChan}
	}
}

// waitForIndexedStreamEvent waits for the next streaming event
func waitForIndexedStreamEvent(eventChan <-chan uiadapter.StreamEvent) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-eventChan
		if !ok {
			return indexedStreamMsg{done: true}
		}
		return indexedStreamMsg{event: event, done: false}
	}
}

// IndexedViewMode represents the current view in indexed mode
type IndexedViewMode int

const (
	IndexedViewPackets IndexedViewMode = iota
	IndexedViewPacketDetail
	IndexedViewPacketHex
	IndexedViewFlows
	IndexedViewFlowDetail
	IndexedViewEvents
	IndexedViewEventDetail
	IndexedViewChat
	IndexedViewHelp
)

// IndexedModel is the TUI model that uses indexed data.
type IndexedModel struct {
	provider uiadapter.DataProvider
	aiAgent  uiadapter.AIAssistant

	// Packet list state
	packets       []*uiadapter.DisplayPacket
	totalPackets  int
	packetIdx     int
	packetOffset  int
	pageSize      int

	// Flow list state
	flows        []*model.Flow
	totalFlows   int
	flowIdx      int
	flowOffset   int
	selectedFlow *model.Flow

	// Expert events state
	events      []*model.ExpertEvent
	totalEvents int
	eventIdx    int

	// View state
	viewMode     IndexedViewMode
	detailScroll int
	hexScroll    int
	width        int
	height       int

	// AI Chat state
	chatMessages     []ChatMessage
	chatInputActive  bool
	chatInputBuffer  string
	chatScroll       int
	aiProcessing     bool
	aiStreamChan     <-chan uiadapter.StreamEvent
	aiStreamContent  string
	aiStreamingMsgID int

	// Stats
	stats *query.Overview

	// Error handling
	lastError error
}

// NewIndexedModel creates a new indexed model.
func NewIndexedModel(provider uiadapter.DataProvider, ai uiadapter.AIAssistant) *IndexedModel {
	m := &IndexedModel{
		provider:         provider,
		aiAgent:          ai,
		pageSize:         100,
		viewMode:         IndexedViewPackets,
		chatMessages:     make([]ChatMessage, 0),
		aiStreamingMsgID: -1,
	}

	// Add welcome message if AI is enabled
	if ai != nil {
		m.chatMessages = append(m.chatMessages, ChatMessage{
			Role:    "assistant",
			Content: "你好！我是 AI 网络分析助手。\n\n我可以帮你分析这个 pcap 文件中的数据包、流量和异常事件。\n\n按 'a' 进入聊天视图，按 'i' 开始输入问题。",
		})
	}

	// Load initial data
	m.loadPacketPage(0)
	m.loadStats()

	return m
}

func (m *IndexedModel) loadPacketPage(offset int) {
	packets, err := m.provider.GetPackets(offset, m.pageSize)
	if err != nil {
		m.lastError = err
		return
	}
	m.packets = packets
	m.totalPackets = m.provider.GetPacketCount()
	m.packetOffset = offset
}

func (m *IndexedModel) loadFlowPage(offset int) {
	flows, err := m.provider.GetFlows(offset, m.pageSize)
	if err != nil {
		m.lastError = err
		return
	}
	m.flows = flows
	m.totalFlows = m.provider.GetFlowCount()
	m.flowOffset = offset
}

func (m *IndexedModel) loadEvents() {
	events, err := m.provider.GetExpertEvents(1) // 1 = Note and above
	if err != nil {
		m.lastError = err
		return
	}
	m.events = events
	m.totalEvents = len(events)
}

func (m *IndexedModel) loadStats() {
	stats, err := m.provider.GetOverview()
	if err != nil {
		m.lastError = err
		return
	}
	m.stats = stats
}

func (m *IndexedModel) Init() tea.Cmd {
	return nil
}

func (m *IndexedModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case indexedStreamStartMsg:
		if msg.err != nil {
			m.aiProcessing = false
			m.addChatMessage("system", "Error: "+msg.err.Error(), true)
			return m, nil
		}
		m.aiStreamChan = msg.eventChan
		m.aiStreamContent = ""
		m.addChatMessage("assistant", "▌", false)
		m.aiStreamingMsgID = len(m.chatMessages) - 1
		m.chatScroll = len(m.chatMessages) * 10
		return m, waitForIndexedStreamEvent(m.aiStreamChan)

	case indexedStreamMsg:
		if msg.done {
			m.aiProcessing = false
			if m.aiStreamingMsgID >= 0 && m.aiStreamingMsgID < len(m.chatMessages) {
				m.chatMessages[m.aiStreamingMsgID].Content = m.aiStreamContent
			}
			m.aiStreamingMsgID = -1
			m.aiStreamContent = ""
			return m, nil
		}
		// Handle streaming event based on Type field
		switch msg.event.Type {
		case "delta":
			m.aiStreamContent += msg.event.Delta
			if m.aiStreamingMsgID >= 0 && m.aiStreamingMsgID < len(m.chatMessages) {
				m.chatMessages[m.aiStreamingMsgID].Content = m.aiStreamContent + "▌"
			}
		case "tool_start":
			if msg.event.ToolExecuting {
				m.aiStreamContent += fmt.Sprintf("\n🔧 调用工具: %s\n", msg.event.ToolName)
			}
		case "tool_end":
			// Tool finished, could add result indicator
		case "error":
			if msg.event.Error != nil {
				m.aiStreamContent += fmt.Sprintf("\n❌ 错误: %s\n", msg.event.Error.Error())
			}
		case "end":
			// Stream ended normally
		}
		return m, waitForIndexedStreamEvent(m.aiStreamChan)

	case tea.KeyMsg:
		return m.handleKeyMsg(msg)
	}

	return m, nil
}

func (m *IndexedModel) handleKeyMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Handle chat input mode first
	if m.chatInputActive {
		return m.handleChatInputKeys(msg)
	}

	// Global keys
	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "?":
		m.viewMode = IndexedViewHelp
		return m, nil
	case "a":
		// Toggle chat view (only if AI is enabled)
		if m.aiAgent != nil {
			if m.viewMode == IndexedViewChat {
				m.viewMode = IndexedViewPackets
			} else {
				m.viewMode = IndexedViewChat
				m.chatScroll = len(m.chatMessages) * 10
			}
		}
		return m, nil
	}

	// View-specific keys
	switch m.viewMode {
	case IndexedViewPackets:
		return m.handlePacketListKeys(key)
	case IndexedViewPacketDetail:
		return m.handleDetailKeys(key)
	case IndexedViewPacketHex:
		return m.handleHexKeys(key)
	case IndexedViewFlows:
		return m.handleFlowListKeys(key)
	case IndexedViewFlowDetail:
		return m.handleFlowDetailKeys(key)
	case IndexedViewEvents:
		return m.handleEventListKeys(key)
	case IndexedViewEventDetail:
		return m.handleEventDetailKeys(key)
	case IndexedViewChat:
		return m.handleChatViewKeys(key)
	case IndexedViewHelp:
		if key == "esc" || key == "?" {
			m.viewMode = IndexedViewPackets
		}
		return m, nil
	}

	return m, nil
}

func (m *IndexedModel) handleChatViewKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "i":
		// Enter input mode
		if !m.aiProcessing {
			m.chatInputActive = true
		}
	case "esc":
		m.viewMode = IndexedViewPackets
	case "up", "k":
		if m.chatScroll > 0 {
			m.chatScroll--
		}
	case "down", "j":
		m.chatScroll++
	case "pgup":
		m.chatScroll -= 20
		if m.chatScroll < 0 {
			m.chatScroll = 0
		}
	case "pgdown":
		m.chatScroll += 20
	case "home", "g":
		m.chatScroll = 0
	case "end", "G":
		m.chatScroll = len(m.chatMessages) * 10
	}
	return m, nil
}

func (m *IndexedModel) handleChatInputKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	switch key {
	case "enter":
		if m.chatInputBuffer != "" && m.aiAgent != nil && !m.aiProcessing {
			userMsg := m.chatInputBuffer
			m.addChatMessage("user", userMsg, false)
			m.chatInputBuffer = ""
			m.aiProcessing = true
			m.chatInputActive = false
			return m, sendIndexedAIMessage(m.aiAgent, userMsg)
		}
		return m, nil
	case "esc":
		m.chatInputActive = false
		m.chatInputBuffer = ""
		return m, nil
	case "backspace":
		if len(m.chatInputBuffer) > 0 {
			m.chatInputBuffer = m.chatInputBuffer[:len(m.chatInputBuffer)-1]
		}
		return m, nil
	case "ctrl+u":
		m.chatInputBuffer = ""
		return m, nil
	default:
		// Handle regular character input
		if len(key) == 1 || key == "space" {
			if key == "space" {
				m.chatInputBuffer += " "
			} else {
				m.chatInputBuffer += key
			}
		}
		return m, nil
	}
}

func (m *IndexedModel) addChatMessage(role, content string, isError bool) {
	m.chatMessages = append(m.chatMessages, ChatMessage{
		Role:    role,
		Content: content,
		IsError: isError,
	})
}

func (m *IndexedModel) handlePacketListKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.packetIdx > 0 {
			m.packetIdx--
			if m.packetIdx < m.packetOffset && m.packetOffset > 0 {
				m.loadPacketPage(m.packetOffset - m.pageSize)
			}
		}
	case "down", "j":
		if m.packetIdx < m.totalPackets-1 {
			m.packetIdx++
			if m.packetIdx >= m.packetOffset+len(m.packets) {
				m.loadPacketPage(m.packetOffset + m.pageSize)
			}
		}
	case "pgup":
		m.packetIdx -= 20
		if m.packetIdx < 0 {
			m.packetIdx = 0
		}
		if m.packetIdx < m.packetOffset {
			m.loadPacketPage(m.packetIdx)
		}
	case "pgdown":
		m.packetIdx += 20
		if m.packetIdx >= m.totalPackets {
			m.packetIdx = m.totalPackets - 1
		}
		if m.packetIdx >= m.packetOffset+len(m.packets) {
			m.loadPacketPage(m.packetIdx)
		}
	case "home", "g":
		m.packetIdx = 0
		m.loadPacketPage(0)
	case "end", "G":
		m.packetIdx = m.totalPackets - 1
		startOffset := m.totalPackets - m.pageSize
		if startOffset < 0 {
			startOffset = 0
		}
		m.loadPacketPage(startOffset)
	case "enter":
		m.viewMode = IndexedViewPacketDetail
		m.detailScroll = 0
	case "x":
		m.viewMode = IndexedViewPacketHex
		m.hexScroll = 0
	case "f":
		// Switch to flows view
		m.viewMode = IndexedViewFlows
		if m.flows == nil {
			m.loadFlowPage(0)
		}
	case "e":
		// Switch to events view
		m.viewMode = IndexedViewEvents
		if m.events == nil {
			m.loadEvents()
		}
	}
	return m, nil
}

func (m *IndexedModel) handleDetailKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "enter":
		m.viewMode = IndexedViewPackets
	case "x":
		m.viewMode = IndexedViewPacketHex
	case "up", "k":
		if m.detailScroll > 0 {
			m.detailScroll--
		}
	case "down", "j":
		m.detailScroll++
	}
	return m, nil
}

func (m *IndexedModel) handleHexKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "x":
		m.viewMode = IndexedViewPackets
	case "enter":
		m.viewMode = IndexedViewPacketDetail
	case "up", "k":
		if m.hexScroll > 0 {
			m.hexScroll--
		}
	case "down", "j":
		m.hexScroll++
	}
	return m, nil
}

func (m *IndexedModel) handleFlowListKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.flowIdx > 0 {
			m.flowIdx--
			if m.flowIdx < m.flowOffset && m.flowOffset > 0 {
				m.loadFlowPage(m.flowOffset - m.pageSize)
			}
		}
	case "down", "j":
		if m.flowIdx < m.totalFlows-1 {
			m.flowIdx++
			if m.flowIdx >= m.flowOffset+len(m.flows) {
				m.loadFlowPage(m.flowOffset + m.pageSize)
			}
		}
	case "enter":
		if m.flowIdx >= 0 && m.flowIdx < len(m.flows) {
			m.selectedFlow = m.flows[m.flowIdx-m.flowOffset]
			m.viewMode = IndexedViewFlowDetail
		}
	case "esc", "p":
		m.viewMode = IndexedViewPackets
	case "e":
		m.viewMode = IndexedViewEvents
		if m.events == nil {
			m.loadEvents()
		}
	}
	return m, nil
}

func (m *IndexedModel) handleFlowDetailKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "enter":
		m.viewMode = IndexedViewFlows
	case "up", "k":
		if m.detailScroll > 0 {
			m.detailScroll--
		}
	case "down", "j":
		m.detailScroll++
	}
	return m, nil
}

func (m *IndexedModel) handleEventListKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.eventIdx > 0 {
			m.eventIdx--
		}
	case "down", "j":
		if m.eventIdx < m.totalEvents-1 {
			m.eventIdx++
		}
	case "enter":
		m.viewMode = IndexedViewEventDetail
	case "esc", "p":
		m.viewMode = IndexedViewPackets
	case "f":
		m.viewMode = IndexedViewFlows
		if m.flows == nil {
			m.loadFlowPage(0)
		}
	}
	return m, nil
}

func (m *IndexedModel) handleEventDetailKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "enter":
		m.viewMode = IndexedViewEvents
	}
	return m, nil
}

func (m *IndexedModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}

	switch m.viewMode {
	case IndexedViewPacketDetail:
		return m.renderPacketDetail()
	case IndexedViewPacketHex:
		return m.renderHex()
	case IndexedViewFlows:
		return m.renderFlowList()
	case IndexedViewFlowDetail:
		return m.renderFlowDetail()
	case IndexedViewEvents:
		return m.renderEventList()
	case IndexedViewEventDetail:
		return m.renderEventDetail()
	case IndexedViewChat:
		return m.renderChatView()
	case IndexedViewHelp:
		return m.renderHelp()
	default:
		return m.renderPacketList()
	}
}

func (m *IndexedModel) renderPacketList() string {
	var b strings.Builder

	// Header with stats
	b.WriteString(fmt.Sprintf(" 📦 Packets: %d | 🔗 Flows: %d | 📊 Bytes: %s",
		m.totalPackets,
		m.stats.TotalFlows,
		formatBytes(m.stats.TotalBytes),
	))
	if m.stats.WarningEvents > 0 {
		b.WriteString(fmt.Sprintf(" | ⚠️ Events: %d", m.stats.WarningEvents))
	}
	b.WriteString("\n")
	b.WriteString("─────────────────────────────────────────────────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf(" %-6s %-15s %-22s %-22s %-8s %s\n",
		"No.", "Time", "Source", "Destination", "Protocol", "Info"))
	b.WriteString("─────────────────────────────────────────────────────────────────────────────────────\n")

	// Calculate visible range
	listHeight := m.height - 6
	if listHeight < 1 {
		listHeight = 1
	}

	// Render packets
	for i, pkt := range m.packets {
		globalIdx := m.packetOffset + i
		isSelected := globalIdx == m.packetIdx

		line := fmt.Sprintf(" %-6d %-15s %-22s %-22s %-8s %s",
			pkt.Number,
			pkt.FormatTimestamp(),
			truncate(pkt.FormatSrcEndpoint(), 22),
			truncate(pkt.FormatDstEndpoint(), 22),
			pkt.Protocol,
			truncate(pkt.Info, 40),
		)

		if isSelected {
			b.WriteString(fmt.Sprintf("\x1b[7m%s\x1b[0m\n", line))
		} else {
			b.WriteString(line + "\n")
		}

		if i >= listHeight-1 {
			break
		}
	}

	// Footer
	b.WriteString("─────────────────────────────────────────────────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf(" [%d/%d] ↑↓:Navigate Enter:Detail x:Hex f:Flows e:Events ?:Help q:Quit",
		m.packetIdx+1, m.totalPackets))

	return b.String()
}

func (m *IndexedModel) renderPacketDetail() string {
	if m.packetIdx < 0 || m.packetIdx >= m.totalPackets {
		return "No packet selected"
	}

	localIdx := m.packetIdx - m.packetOffset
	if localIdx < 0 || localIdx >= len(m.packets) {
		return "Packet not in current view"
	}

	pkt := m.packets[localIdx]

	var b strings.Builder
	b.WriteString(fmt.Sprintf("📦 Packet #%d Details\n", pkt.Number))
	b.WriteString("═══════════════════════════════════════════════════════════════════════════════════\n\n")
	b.WriteString(fmt.Sprintf("  Timestamp: %s\n", pkt.Timestamp.Format("2006-01-02 15:04:05.000000")))
	b.WriteString(fmt.Sprintf("  Length:    %d bytes\n\n", pkt.Length))
	b.WriteString(fmt.Sprintf("  Source:      %s\n", pkt.FormatSrcEndpoint()))
	b.WriteString(fmt.Sprintf("  Destination: %s\n", pkt.FormatDstEndpoint()))
	b.WriteString(fmt.Sprintf("  Protocol:    %s\n", pkt.Protocol))
	b.WriteString(fmt.Sprintf("  Info:        %s\n", pkt.Info))

	if pkt.FlowID != "" {
		b.WriteString(fmt.Sprintf("\n  Flow ID: %s\n", pkt.FlowID))
	}

	if pkt.SNI != "" {
		b.WriteString(fmt.Sprintf("  TLS SNI: %s\n", pkt.SNI))
	}

	// TCP details
	if pkt.Protocol == "TCP" || pkt.TCPFlags != 0 {
		b.WriteString("\n  TCP Details:\n")
		b.WriteString(fmt.Sprintf("    Flags:  %s\n", formatTCPFlags(pkt.TCPFlags)))
		b.WriteString(fmt.Sprintf("    Seq:    %d\n", pkt.TCPSeq))
		b.WriteString(fmt.Sprintf("    Ack:    %d\n", pkt.TCPAck))
		b.WriteString(fmt.Sprintf("    Window: %d\n", pkt.TCPWindow))
	}

	b.WriteString("\n─────────────────────────────────────────────────────────────────────────────────────\n")
	b.WriteString(" ESC:Back x:Hex")

	return b.String()
}

func (m *IndexedModel) renderHex() string {
	if m.packetIdx < 0 || m.packetIdx >= m.totalPackets {
		return "No packet selected"
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("📦 Packet #%d Hex Dump\n", m.packetIdx+1))
	b.WriteString("═══════════════════════════════════════════════════════════════════════════════════\n\n")

	rawData, err := m.provider.GetRawPacket(m.packetIdx + 1)
	if err != nil {
		b.WriteString(fmt.Sprintf("  Raw data not available: %v\n", err))
		b.WriteString("\n  (Raw packet data requires reading from pcap file)\n")
	} else {
		b.WriteString(formatHexDump(rawData))
	}

	b.WriteString("\n─────────────────────────────────────────────────────────────────────────────────────\n")
	b.WriteString(" ESC:Back x:Back Enter:Detail")

	return b.String()
}

func (m *IndexedModel) renderFlowList() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf(" 🔗 Flows: %d | Total Bytes: %s\n",
		m.totalFlows,
		formatBytes(m.stats.TotalBytes),
	))
	b.WriteString("─────────────────────────────────────────────────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf(" %-8s %-22s %-22s %-8s %-8s %-10s %s\n",
		"ID", "Source", "Destination", "Protocol", "Packets", "Bytes", "Duration"))
	b.WriteString("─────────────────────────────────────────────────────────────────────────────────────\n")

	listHeight := m.height - 6
	if listHeight < 1 {
		listHeight = 1
	}

	for i, flow := range m.flows {
		globalIdx := m.flowOffset + i
		isSelected := globalIdx == m.flowIdx

		duration := flow.Duration()
		durationStr := formatDuration(duration)

		line := fmt.Sprintf(" %-8s %-22s %-22s %-8s %-8d %-10s %s",
			flow.ID[:8],
			truncate(fmt.Sprintf("%s:%d", flow.SrcIP, flow.SrcPort), 22),
			truncate(fmt.Sprintf("%s:%d", flow.DstIP, flow.DstPort), 22),
			flow.Protocol,
			flow.Packets,
			formatBytes(flow.Bytes),
			durationStr,
		)

		if isSelected {
			b.WriteString(fmt.Sprintf("\x1b[7m%s\x1b[0m\n", line))
		} else {
			b.WriteString(line + "\n")
		}

		if i >= listHeight-1 {
			break
		}
	}

	b.WriteString("─────────────────────────────────────────────────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf(" [%d/%d] ↑↓:Navigate Enter:Detail p:Packets e:Events q:Quit",
		m.flowIdx+1, m.totalFlows))

	return b.String()
}

func (m *IndexedModel) renderFlowDetail() string {
	if m.selectedFlow == nil {
		return "No flow selected"
	}

	flow := m.selectedFlow

	var b strings.Builder
	b.WriteString(fmt.Sprintf("🔗 Flow %s Details\n", flow.ID[:8]))
	b.WriteString("═══════════════════════════════════════════════════════════════════════════════════\n\n")

	b.WriteString(fmt.Sprintf("  Flow ID:     %s\n", flow.ID))
	b.WriteString(fmt.Sprintf("  Protocol:    %s\n\n", flow.Protocol))

	b.WriteString(fmt.Sprintf("  Source:      %s:%d\n", flow.SrcIP, flow.SrcPort))
	b.WriteString(fmt.Sprintf("  Destination: %s:%d\n\n", flow.DstIP, flow.DstPort))

	b.WriteString(fmt.Sprintf("  Packets:     %d\n", flow.Packets))
	b.WriteString(fmt.Sprintf("  Bytes:       %s\n", formatBytes(flow.Bytes)))
	b.WriteString(fmt.Sprintf("  Duration:    %s\n\n", formatDuration(flow.Duration())))

	b.WriteString(fmt.Sprintf("  Start Time:  %s\n", flow.StartTime().Format("2006-01-02 15:04:05.000")))
	b.WriteString(fmt.Sprintf("  End Time:    %s\n", flow.EndTime().Format("2006-01-02 15:04:05.000")))

	if flow.TLSServerName != "" {
		b.WriteString(fmt.Sprintf("\n  TLS/SNI:     %s\n", flow.TLSServerName))
	}

	b.WriteString("\n─────────────────────────────────────────────────────────────────────────────────────\n")
	b.WriteString(" ESC:Back")

	return b.String()
}

func (m *IndexedModel) renderEventList() string {
	var b strings.Builder

	errCount := 0
	warnCount := 0
	noteCount := 0
	for _, e := range m.events {
		switch e.Severity {
		case model.SeverityError:
			errCount++
		case model.SeverityWarning:
			warnCount++
		case model.SeverityNote:
			noteCount++
		}
	}

	b.WriteString(fmt.Sprintf(" ⚠️ Expert Events: %d (🔴 %d | 🟡 %d | 🔵 %d)\n",
		m.totalEvents, errCount, warnCount, noteCount))
	b.WriteString("─────────────────────────────────────────────────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf(" %-10s %-12s %-15s %-8s %s\n",
		"Severity", "Group", "Flow", "Packet", "Message"))
	b.WriteString("─────────────────────────────────────────────────────────────────────────────────────\n")

	listHeight := m.height - 6
	if listHeight < 1 {
		listHeight = 1
	}

	startIdx := m.eventIdx - listHeight/2
	if startIdx < 0 {
		startIdx = 0
	}
	endIdx := startIdx + listHeight
	if endIdx > len(m.events) {
		endIdx = len(m.events)
	}

	for i := startIdx; i < endIdx; i++ {
		event := m.events[i]
		isSelected := i == m.eventIdx

		severityIcon := getSeverityIcon(event.Severity)
		flowID := ""
		if event.FlowID != "" && len(event.FlowID) >= 8 {
			flowID = event.FlowID[:8]
		}

		line := fmt.Sprintf(" %-10s %-12s %-15s %-8d %s",
			severityIcon+" "+string(event.Severity),
			truncate(string(event.Group), 12),
			flowID,
			event.PacketStart,
			truncate(event.Message, 40),
		)

		if isSelected {
			b.WriteString(fmt.Sprintf("\x1b[7m%s\x1b[0m\n", line))
		} else {
			b.WriteString(line + "\n")
		}
	}

	b.WriteString("─────────────────────────────────────────────────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf(" [%d/%d] ↑↓:Navigate Enter:Detail p:Packets f:Flows q:Quit",
		m.eventIdx+1, m.totalEvents))

	return b.String()
}

func (m *IndexedModel) renderEventDetail() string {
	if m.eventIdx < 0 || m.eventIdx >= len(m.events) {
		return "No event selected"
	}

	event := m.events[m.eventIdx]

	var b strings.Builder
	b.WriteString(fmt.Sprintf("⚠️ Expert Event Details\n"))
	b.WriteString("═══════════════════════════════════════════════════════════════════════════════════\n\n")

	b.WriteString(fmt.Sprintf("  Severity:    %s %s\n", getSeverityIcon(event.Severity), string(event.Severity)))
	b.WriteString(fmt.Sprintf("  Group:       %s\n", string(event.Group)))
	b.WriteString(fmt.Sprintf("  Type:        %s\n", event.Type))
	b.WriteString(fmt.Sprintf("  Timestamp:   %s\n\n", event.Timestamp().Format("2006-01-02 15:04:05.000")))

	b.WriteString(fmt.Sprintf("  Message:     %s\n\n", event.Message))

	if event.Summary != "" {
		b.WriteString(fmt.Sprintf("  Summary:\n    %s\n\n", event.Summary))
	}

	if event.FlowID != "" {
		b.WriteString(fmt.Sprintf("  Flow ID:     %s\n", event.FlowID))
	}
	b.WriteString(fmt.Sprintf("  Packet Range: %d - %d\n", event.PacketStart, event.PacketEnd))

	b.WriteString("\n─────────────────────────────────────────────────────────────────────────────────────\n")
	b.WriteString(" ESC:Back")

	return b.String()
}

func (m *IndexedModel) renderHelp() string {
	help := `
📖 Keyboard Shortcuts
═══════════════════════════════════════════════════════════════════════════════════

  Navigation
  ──────────
  ↑/k, ↓/j     Move up/down
  PgUp, PgDn   Page up/down
  Home/g       Go to first item
  End/G        Go to last item

  Views
  ─────
  p            Packet list (main view)
  f            Flow list
  e            Expert events
  Enter        View details
  x            Hex dump (packets only)
  ESC          Go back

  General
  ───────
  ?            Toggle this help
  q, Ctrl+C    Quit

═══════════════════════════════════════════════════════════════════════════════════
  Press ESC or ? to close this help
`
	return help
}

// Helper functions

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatHexDump(data []byte) string {
	if len(data) == 0 {
		return "  (empty)\n"
	}

	var b strings.Builder
	for i := 0; i < len(data); i += 16 {
		b.WriteString(fmt.Sprintf("  %04x  ", i))

		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				b.WriteString(fmt.Sprintf("%02x ", data[i+j]))
			} else {
				b.WriteString("   ")
			}
			if j == 7 {
				b.WriteString(" ")
			}
		}

		b.WriteString(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			c := data[i+j]
			if c >= 32 && c < 127 {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|\n")
	}

	return b.String()
}

func formatTCPFlags(flags uint16) string {
	var parts []string
	if flags&0x01 != 0 {
		parts = append(parts, "FIN")
	}
	if flags&0x02 != 0 {
		parts = append(parts, "SYN")
	}
	if flags&0x04 != 0 {
		parts = append(parts, "RST")
	}
	if flags&0x08 != 0 {
		parts = append(parts, "PSH")
	}
	if flags&0x10 != 0 {
		parts = append(parts, "ACK")
	}
	if flags&0x20 != 0 {
		parts = append(parts, "URG")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	} else if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	} else if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}

func getSeverityIcon(s model.Severity) string {
	switch s {
	case model.SeverityError:
		return "🔴"
	case model.SeverityWarning:
		return "🟡"
	case model.SeverityNote:
		return "🔵"
	case model.SeverityChat:
		return "💬"
	default:
		return "🔵"
	}
}

func (m *IndexedModel) renderChatView() string {
	var b strings.Builder

	// Header
	aiStatus := "🤖 AI 未连接"
	if m.aiAgent != nil {
		if m.aiProcessing {
			aiStatus = "🤖 AI 正在思考..."
		} else {
			aiStatus = "🤖 AI 已就绪"
		}
	}
	b.WriteString(fmt.Sprintf(" 💬 AI 聊天 | %s | 📦 %d packets | 🔗 %d flows\n",
		aiStatus, m.totalPackets, m.stats.TotalFlows))
	b.WriteString("═══════════════════════════════════════════════════════════════════════════════════\n")

	// Chat messages area
	chatHeight := m.height - 6
	if chatHeight < 3 {
		chatHeight = 3
	}

	// Build message lines
	var lines []string
	for _, msg := range m.chatMessages {
		var prefix string
		switch msg.Role {
		case "user":
			prefix = "👤 你: "
		case "assistant":
			prefix = "🤖 AI: "
		case "system":
			prefix = "⚙️ 系统: "
		default:
			prefix = "   "
		}

		// Word wrap the message
		content := msg.Content
		if msg.IsError {
			content = "❌ " + content
		}

		// Simple line wrapping
		maxWidth := m.width - 10
		if maxWidth < 20 {
			maxWidth = 20
		}

		msgLines := indexedWrapText(content, maxWidth)
		for i, line := range msgLines {
			if i == 0 {
				lines = append(lines, prefix+line)
			} else {
				lines = append(lines, "      "+line)
			}
		}
		lines = append(lines, "") // Empty line between messages
	}

	// Apply scroll and render
	start := m.chatScroll
	if start >= len(lines) {
		start = len(lines) - chatHeight
		if start < 0 {
			start = 0
		}
	}
	end := start + chatHeight - 2
	if end > len(lines) {
		end = len(lines)
	}

	for i := start; i < end; i++ {
		b.WriteString(" " + lines[i] + "\n")
	}

	// Fill remaining space
	for i := end - start; i < chatHeight-2; i++ {
		b.WriteString("\n")
	}

	// Input area
	b.WriteString("───────────────────────────────────────────────────────────────────────────────────\n")
	if m.aiProcessing {
		b.WriteString(" ⏳ AI 正在处理...")
	} else if m.chatInputActive {
		b.WriteString(fmt.Sprintf(" >> %s▌", m.chatInputBuffer))
	} else {
		b.WriteString(" 按 'i' 输入 | ESC:返回 | ↑↓:滚动")
	}

	return b.String()
}

func indexedWrapText(text string, maxWidth int) []string {
	if maxWidth <= 0 {
		return []string{text}
	}

	var lines []string
	for _, paragraph := range strings.Split(text, "\n") {
		if len(paragraph) <= maxWidth {
			lines = append(lines, paragraph)
			continue
		}

		words := strings.Fields(paragraph)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}

		var currentLine string
		for _, word := range words {
			if currentLine == "" {
				currentLine = word
			} else if len(currentLine)+1+len(word) <= maxWidth {
				currentLine += " " + word
			} else {
				lines = append(lines, currentLine)
				currentLine = word
			}
		}
		if currentLine != "" {
			lines = append(lines, currentLine)
		}
	}

	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}
