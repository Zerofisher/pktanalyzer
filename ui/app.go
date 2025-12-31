package ui

import (
	"fmt"
	"github.com/Zerofisher/pktanalyzer/agent"
	"github.com/Zerofisher/pktanalyzer/agent/llm"
	"github.com/Zerofisher/pktanalyzer/capture"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// Messages
type packetMsg capture.PacketInfo
type tickMsg time.Time
type aiResponseMsg struct {
	content string
	err     error
}
type aiStreamMsg struct {
	event agent.StreamEvent
	done  bool
}
type saveResultMsg struct {
	filename string
	count    int
	err      error
}
type clearStatusMsg struct{}

func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func waitForPacket(packetChan <-chan capture.PacketInfo) tea.Cmd {
	return func() tea.Msg {
		p, ok := <-packetChan
		if !ok {
			return nil
		}
		return packetMsg(p)
	}
}

func sendAIMessage(aiAgent *agent.Agent, message string) tea.Cmd {
	return func() tea.Msg {
		response, err := aiAgent.Chat(message)
		return aiResponseMsg{content: response, err: err}
	}
}

// aiStreamStartMsg indicates stream has started with channel reference
type aiStreamStartMsg struct {
	eventChan <-chan agent.StreamEvent
	err       error
}

// sendAIMessageStream starts streaming AI response
func sendAIMessageStream(aiAgent *agent.Agent, message string) tea.Cmd {
	return func() tea.Msg {
		eventChan, err := aiAgent.ChatStream(message)
		if err != nil {
			return aiStreamStartMsg{err: err}
		}
		return aiStreamStartMsg{eventChan: eventChan}
	}
}

// waitForNextStreamEvent waits for the next streaming event
func waitForNextStreamEvent(eventChan <-chan agent.StreamEvent) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-eventChan
		if !ok {
			return aiStreamMsg{done: true}
		}
		return aiStreamMsg{event: event, done: false}
	}
}

// savePacketsCmd saves packets to a file asynchronously
func savePacketsCmd(packets []capture.PacketInfo) tea.Cmd {
	return func() tea.Msg {
		if len(packets) == 0 {
			return saveResultMsg{err: fmt.Errorf("no packets to save")}
		}

		filename := capture.GenerateFilename("capture")
		count, err := capture.SavePackets(filename, packets)
		return saveResultMsg{filename: filename, count: count, err: err}
	}
}

// clearStatusCmd clears the status message after a delay
func clearStatusCmd() tea.Cmd {
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
		return clearStatusMsg{}
	})
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		waitForPacket(m.packetChan),
		tickCmd(),
	)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Update text input width
		m.chatTextInput.Width = m.width - 20
		m.filterTextInput.Width = m.width - 20
		return m, nil

	case packetMsg:
		if !m.paused {
			p := capture.PacketInfo(msg)
			m.packets = append(m.packets, p)
			m.stats.Update(p)

			// Add packet to AI agent context
			if m.aiAgent != nil {
				m.aiAgent.AddPacket(p)
			}

			// Update filtered packets
			if m.filter != "" && matchFilter(p, m.filter) {
				m.filteredPkts = append(m.filteredPkts, p)
			}

			// Auto-scroll to new packet in list view
			if m.viewMode == ViewList && m.isLive {
				packets := m.getDisplayPackets()
				m.selectedIdx = len(packets) - 1
			}
		}
		return m, waitForPacket(m.packetChan)

	case aiResponseMsg:
		m.aiProcessing = false
		if msg.err != nil {
			m.AddChatMessage("system", "Error: "+msg.err.Error(), true)
		} else {
			m.AddChatMessage("assistant", msg.content, false)
		}
		// Auto-scroll to bottom
		m.chatScroll = len(m.chatMessages) * 10 // rough estimate
		return m, nil

	case aiStreamStartMsg:
		if msg.err != nil {
			m.aiProcessing = false
			m.AddChatMessage("system", "Error: "+msg.err.Error(), true)
			return m, nil
		}
		// Store the channel and create a placeholder message for streaming
		m.aiStreamChan = msg.eventChan
		m.aiStreamContent = ""
		m.AddChatMessage("assistant", "▌", false) // cursor placeholder
		m.aiStreamingMsgID = len(m.chatMessages) - 1
		m.chatScroll = len(m.chatMessages) * 10
		// Start listening for stream events
		return m, waitForNextStreamEvent(m.aiStreamChan)

	case aiStreamMsg:
		if msg.done {
			// Stream finished
			m.aiProcessing = false
			m.aiStreamChan = nil
			// Finalize the message content (remove cursor)
			if m.aiStreamingMsgID >= 0 && m.aiStreamingMsgID < len(m.chatMessages) {
				if m.aiStreamContent == "" {
					m.chatMessages[m.aiStreamingMsgID].Content = "(No response)"
				} else {
					m.chatMessages[m.aiStreamingMsgID].Content = m.aiStreamContent
				}
			}
			m.aiStreamingMsgID = -1
			m.aiStreamContent = ""
			return m, nil
		}

		// Handle different stream event types
		switch msg.event.Type {
		case llm.StreamEventDelta:
			// Append delta to current streaming content
			m.aiStreamContent += msg.event.Delta
			// Update the message being streamed
			if m.aiStreamingMsgID >= 0 && m.aiStreamingMsgID < len(m.chatMessages) {
				m.chatMessages[m.aiStreamingMsgID].Content = m.aiStreamContent + "▌"
			}
			m.chatScroll = len(m.chatMessages) * 10

		case llm.StreamEventToolStart:
			// Show tool execution indicator
			if msg.event.ToolCall != nil {
				toolInfo := fmt.Sprintf("\n🔧 [执行工具: %s]", msg.event.ToolCall.Name)
				m.aiStreamContent += toolInfo
				if m.aiStreamingMsgID >= 0 && m.aiStreamingMsgID < len(m.chatMessages) {
					m.chatMessages[m.aiStreamingMsgID].Content = m.aiStreamContent + "▌"
				}
			}

		case llm.StreamEventError:
			m.aiProcessing = false
			m.aiStreamChan = nil
			errMsg := "Stream error"
			if msg.event.Error != nil {
				errMsg = msg.event.Error.Error()
			}
			if m.aiStreamingMsgID >= 0 && m.aiStreamingMsgID < len(m.chatMessages) {
				m.chatMessages[m.aiStreamingMsgID].Content = m.aiStreamContent + "\n\n❌ " + errMsg
				m.chatMessages[m.aiStreamingMsgID].IsError = true
			}
			m.aiStreamingMsgID = -1
			m.aiStreamContent = ""
			return m, nil

		case llm.StreamEventEnd:
			// Will be handled by done=true
		}

		// Continue listening for more events
		if m.aiStreamChan != nil {
			return m, waitForNextStreamEvent(m.aiStreamChan)
		}
		return m, nil

	case saveResultMsg:
		if msg.err != nil {
			m.statusMessage = fmt.Sprintf("Save failed: %v", msg.err)
			m.statusIsError = true
		} else {
			m.statusMessage = fmt.Sprintf("Saved %d packets to %s", msg.count, msg.filename)
			m.statusIsError = false
		}
		return m, clearStatusCmd()

	case clearStatusMsg:
		m.statusMessage = ""
		m.statusIsError = false
		return m, nil

	case tickMsg:
		return m, tickCmd()

	case tea.KeyMsg:
		// Handle chat input mode with textinput
		if m.chatInputActive {
			switch msg.String() {
			case "enter":
				input := m.chatTextInput.Value()
				if input != "" && m.aiAgent != nil && !m.aiProcessing {
					m.AddChatMessage("user", input, false)
					userMsg := input
					m.chatTextInput.SetValue("")
					m.aiProcessing = true
					m.chatInputActive = false
					m.chatTextInput.Blur()
					// Use streaming API
					return m, sendAIMessageStream(m.aiAgent, userMsg)
				}
				return m, nil
			case "esc":
				m.chatInputActive = false
				m.chatTextInput.Blur()
				m.chatTextInput.SetValue("")
				return m, nil
			default:
				// Forward to textinput
				var cmd tea.Cmd
				m.chatTextInput, cmd = m.chatTextInput.Update(msg)
				return m, cmd
			}
		}

		// Handle filter input mode with textinput
		if m.filterActive {
			switch msg.String() {
			case "enter":
				m.filter = m.filterTextInput.Value()
				m.filterActive = false
				m.filterTextInput.Blur()
				m.applyFilter()
				m.selectedIdx = 0
				m.scrollOffset = 0
				return m, nil
			case "esc":
				m.filterActive = false
				m.filterTextInput.Blur()
				m.filterTextInput.SetValue("")
				return m, nil
			default:
				// Forward to textinput
				var cmd tea.Cmd
				m.filterTextInput, cmd = m.filterTextInput.Update(msg)
				return m, cmd
			}
		}

		// Handle help view
		if m.showHelp {
			return m.handleHelpInput(msg)
		}

		switch msg.String() {
		case "q", "ctrl+c":
			if m.capturer != nil {
				m.capturer.Stop()
			}
			return m, tea.Quit

		case "?":
			m.showHelp = true
			m.helpScroll = 0
			return m, nil

		case "a":
			// Toggle AI chat view
			if m.aiEnabled {
				if m.viewMode == ViewChat {
					m.viewMode = ViewList
				} else {
					m.viewMode = ViewChat
					m.chatScroll = len(m.chatMessages) * 10
				}
			}
			return m, nil

		case "tab":
			// Toggle split view (if AI enabled)
			if m.aiEnabled && m.viewMode != ViewChat {
				m.splitView = !m.splitView
			}
			return m, nil

		case "i":
			// Enter chat input mode (only in chat view)
			if m.viewMode == ViewChat && m.aiEnabled && !m.aiProcessing {
				m.chatInputActive = true
				m.chatTextInput.Focus()
				return m, textinput.Blink
			}
			return m, nil

		case "up", "k":
			switch m.viewMode {
			case ViewList:
				if m.selectedIdx > 0 {
					m.selectedIdx--
				}
			case ViewDetail:
				if m.detailScroll > 0 {
					m.detailScroll--
				}
			case ViewHex:
				if m.hexScroll > 0 {
					m.hexScroll--
				}
			case ViewStreamList:
				if m.streamSelectedIdx > 0 {
					m.streamSelectedIdx--
				}
			case ViewStreamDetail:
				if m.streamDetailScroll > 0 {
					m.streamDetailScroll--
				}
			case ViewChat:
				if m.chatScroll > 0 {
					m.chatScroll--
				}
			}
			return m, nil

		case "down", "j":
			switch m.viewMode {
			case ViewList:
				packets := m.getDisplayPackets()
				if m.selectedIdx < len(packets)-1 {
					m.selectedIdx++
				}
			case ViewDetail:
				m.detailScroll++
			case ViewHex:
				m.hexScroll++
			case ViewStreamList:
				streams := m.GetStreams()
				if m.streamSelectedIdx < len(streams)-1 {
					m.streamSelectedIdx++
				}
			case ViewStreamDetail:
				m.streamDetailScroll++
			case ViewChat:
				m.chatScroll++
			}
			return m, nil

		case "pgup":
			switch m.viewMode {
			case ViewList:
				m.selectedIdx -= 20
				if m.selectedIdx < 0 {
					m.selectedIdx = 0
				}
			case ViewDetail:
				m.detailScroll -= 20
				if m.detailScroll < 0 {
					m.detailScroll = 0
				}
			case ViewHex:
				m.hexScroll -= 20
				if m.hexScroll < 0 {
					m.hexScroll = 0
				}
			case ViewStreamList:
				m.streamSelectedIdx -= 20
				if m.streamSelectedIdx < 0 {
					m.streamSelectedIdx = 0
				}
			case ViewStreamDetail:
				m.streamDetailScroll -= 20
				if m.streamDetailScroll < 0 {
					m.streamDetailScroll = 0
				}
			case ViewChat:
				m.chatScroll -= 20
				if m.chatScroll < 0 {
					m.chatScroll = 0
				}
			}
			return m, nil

		case "pgdown":
			switch m.viewMode {
			case ViewList:
				packets := m.getDisplayPackets()
				m.selectedIdx += 20
				if m.selectedIdx >= len(packets) {
					m.selectedIdx = len(packets) - 1
				}
				if m.selectedIdx < 0 {
					m.selectedIdx = 0
				}
			case ViewDetail:
				m.detailScroll += 20
			case ViewHex:
				m.hexScroll += 20
			case ViewStreamList:
				streams := m.GetStreams()
				m.streamSelectedIdx += 20
				if m.streamSelectedIdx >= len(streams) {
					m.streamSelectedIdx = len(streams) - 1
				}
				if m.streamSelectedIdx < 0 {
					m.streamSelectedIdx = 0
				}
			case ViewStreamDetail:
				m.streamDetailScroll += 20
			case ViewChat:
				m.chatScroll += 20
			}
			return m, nil

		case "home", "g":
			switch m.viewMode {
			case ViewList:
				m.selectedIdx = 0
				m.scrollOffset = 0
			case ViewDetail:
				m.detailScroll = 0
			case ViewHex:
				m.hexScroll = 0
			case ViewStreamList:
				m.streamSelectedIdx = 0
				m.streamScroll = 0
			case ViewStreamDetail:
				m.streamDetailScroll = 0
			case ViewChat:
				m.chatScroll = 0
			}
			return m, nil

		case "end", "G":
			switch m.viewMode {
			case ViewList:
				packets := m.getDisplayPackets()
				m.selectedIdx = len(packets) - 1
				if m.selectedIdx < 0 {
					m.selectedIdx = 0
				}
			case ViewStreamList:
				streams := m.GetStreams()
				m.streamSelectedIdx = len(streams) - 1
				if m.streamSelectedIdx < 0 {
					m.streamSelectedIdx = 0
				}
			case ViewChat:
				m.chatScroll = len(m.chatMessages) * 10
			}
			return m, nil

		case "enter":
			switch m.viewMode {
			case ViewList:
				m.viewMode = ViewDetail
				m.detailScroll = 0
			case ViewStreamList:
				streams := m.GetStreams()
				if m.streamSelectedIdx < len(streams) {
					m.selectedStream = streams[m.streamSelectedIdx]
					m.viewMode = ViewStreamDetail
					m.streamDetailScroll = 0
				}
			default:
				m.viewMode = ViewList
			}
			return m, nil

		case "x":
			if m.viewMode == ViewHex {
				m.viewMode = ViewList
			} else {
				m.viewMode = ViewHex
				m.hexScroll = 0
			}
			return m, nil

		case "s":
			// Toggle stream view
			if m.viewMode == ViewStreamList || m.viewMode == ViewStreamDetail {
				m.viewMode = ViewList
			} else {
				m.viewMode = ViewStreamList
				m.streamSelectedIdx = 0
				m.streamScroll = 0
			}
			return m, nil

		case "w":
			// Save packets to file
			packetsToSave := m.packets
			if len(m.filteredPkts) > 0 && m.filter != "" {
				packetsToSave = m.filteredPkts
			}
			if len(packetsToSave) > 0 {
				m.statusMessage = "Saving..."
				m.statusIsError = false
				return m, savePacketsCmd(packetsToSave)
			} else {
				m.statusMessage = "No packets to save"
				m.statusIsError = true
				return m, clearStatusCmd()
			}

		case "esc":
			switch m.viewMode {
			case ViewStreamDetail:
				m.viewMode = ViewStreamList
			case ViewChat:
				m.viewMode = ViewList
			default:
				m.viewMode = ViewList
			}
			return m, nil

		case "/":
			m.filterActive = true
			m.filterTextInput.SetValue(m.filter)
			m.filterTextInput.Focus()
			return m, textinput.Blink

		case " ":
			if m.isLive {
				m.paused = !m.paused
			}
			return m, nil
		}
	}

	// Update textinput if active
	if m.chatInputActive {
		var cmd tea.Cmd
		m.chatTextInput, cmd = m.chatTextInput.Update(msg)
		cmds = append(cmds, cmd)
	}
	if m.filterActive {
		var cmd tea.Cmd
		m.filterTextInput, cmd = m.filterTextInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	if len(cmds) > 0 {
		return m, tea.Batch(cmds...)
	}
	return m, nil
}

func (m Model) handleHelpInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "?":
		m.showHelp = false
		return m, nil
	case "up", "k":
		if m.helpScroll > 0 {
			m.helpScroll--
		}
		return m, nil
	case "down", "j":
		m.helpScroll++
		return m, nil
	}
	return m, nil
}

func (m *Model) applyFilter() {
	m.filteredPkts = make([]capture.PacketInfo, 0)
	for _, p := range m.packets {
		if matchFilter(p, m.filter) {
			m.filteredPkts = append(m.filteredPkts, p)
		}
	}
}

func matchFilter(p capture.PacketInfo, filter string) bool {
	if filter == "" {
		return true
	}
	filter = strings.ToLower(filter)

	// Check protocol
	if strings.ToLower(p.Protocol) == filter {
		return true
	}

	// Check IP addresses
	if strings.Contains(strings.ToLower(p.SrcIP), filter) ||
		strings.Contains(strings.ToLower(p.DstIP), filter) {
		return true
	}

	// Check ports
	if p.SrcPort == filter || p.DstPort == filter {
		return true
	}

	// Check info
	if strings.Contains(strings.ToLower(p.Info), filter) {
		return true
	}

	return false
}

func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	var sb strings.Builder

	// Title bar
	title := " 📦 PktAnalyzer - Network Packet Analyzer "
	if m.aiEnabled {
		title += "🤖 "
	}
	sb.WriteString(titleStyle.Width(m.width).Render(title))
	sb.WriteString("\n")

	// Stats bar
	sb.WriteString(m.renderStats())
	sb.WriteString("\n")

	// Filter bar (if active or set)
	filterBar := m.renderFilterBar()
	if filterBar != "" {
		sb.WriteString(filterBar)
		sb.WriteString("\n")
	}

	// Main content
	if m.showHelp {
		sb.WriteString(m.renderHelp())
	} else if m.splitView && m.aiEnabled {
		// Split view: packets on left, chat on right
		sb.WriteString(m.renderSplitView())
	} else {
		switch m.viewMode {
		case ViewList:
			sb.WriteString(m.renderPacketList())
		case ViewDetail:
			sb.WriteString(m.renderPacketDetail())
		case ViewHex:
			sb.WriteString(m.renderHexDump())
		case ViewStreamList:
			sb.WriteString(m.renderStreamList())
		case ViewStreamDetail:
			sb.WriteString(m.renderStreamDetail())
		case ViewChat:
			sb.WriteString(m.renderChatView())
		}
	}

	// Status bar
	sb.WriteString(m.renderStatusBar())

	return sb.String()
}

// Run starts the TUI application
func Run(packetChan <-chan capture.PacketInfo, capturer *capture.Capturer, isLive bool) error {
	model := NewModel(packetChan, capturer, isLive)
	p := tea.NewProgram(model, tea.WithAltScreen())

	_, err := p.Run()
	return err
}

// RunWithAI starts the TUI application with AI agent
func RunWithAI(packetChan <-chan capture.PacketInfo, capturer *capture.Capturer, isLive bool, aiAgent *agent.Agent) error {
	model := NewModel(packetChan, capturer, isLive)
	model.SetAIAgent(aiAgent)

	// Add welcome message
	if aiAgent != nil {
		model.AddChatMessage("assistant", "你好！我是 AI 网络分析助手。我可以帮你：\n• 分析捕获的数据包\n• 解释网络协议\n• 统计流量信息\n• 检测异常模式\n\n按 'a' 切换到聊天视图，按 'i' 开始输入。", false)
	}

	p := tea.NewProgram(model, tea.WithAltScreen())

	_, err := p.Run()
	return err
}
