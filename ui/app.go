package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/expert"
	uiadapter "github.com/Zerofisher/pktanalyzer/ui/adapter"

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
	event uiadapter.StreamEvent
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

// aiStreamStartMsg indicates stream has started with channel reference
type aiStreamStartMsg struct {
	eventChan <-chan uiadapter.StreamEvent
	err       error
}

// sendAIMessageStream starts streaming AI response
func sendAIMessageStream(ai uiadapter.AIAssistant, message string) tea.Cmd {
	return func() tea.Msg {
		eventChan, err := ai.ChatStream(message)
		if err != nil {
			return aiStreamStartMsg{err: err}
		}
		return aiStreamStartMsg{eventChan: eventChan}
	}
}

// waitForNextStreamEvent waits for the next streaming event
func waitForNextStreamEvent(eventChan <-chan uiadapter.StreamEvent) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-eventChan
		if !ok {
			return aiStreamMsg{done: true}
		}
		return aiStreamMsg{event: event, done: false}
	}
}

// savePacketsCmd saves packets to a file asynchronously
func savePacketsCmd(store uiadapter.PacketStore) tea.Cmd {
	return func() tea.Msg {
		count := store.Count()
		if count == 0 {
			return saveResultMsg{err: fmt.Errorf("no packets to save")}
		}

		// Get all packets for saving
		packets := store.GetRange(0, count)
		if len(packets) == 0 {
			return saveResultMsg{err: fmt.Errorf("no packets to save")}
		}

		// Convert DisplayPackets to PacketInfos for saving
		var infos []capture.PacketInfo
		for _, dp := range packets {
			if dp.RawPacketInfo != nil {
				infos = append(infos, *dp.RawPacketInfo)
			}
		}

		if len(infos) == 0 {
			return saveResultMsg{err: fmt.Errorf("no raw packet data available for saving")}
		}

		filename := capture.GenerateFilename("capture")
		savedCount, err := capture.SavePackets(filename, infos)
		return saveResultMsg{filename: filename, count: savedCount, err: err}
	}
}

// clearStatusCmd clears the status message after a delay
func clearStatusCmd() tea.Cmd {
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
		return clearStatusMsg{}
	})
}

func (m Model) Init() tea.Cmd {
	var cmds []tea.Cmd

	// If we have a packet channel (live mode), start listening
	if m.packetChan != nil {
		cmds = append(cmds, waitForPacket(m.packetChan))
	}

	cmds = append(cmds, tickCmd())
	return tea.Batch(cmds...)
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

			// Convert to DisplayPacket and add to store
			dp := uiadapter.ConvertFromPacketInfo(&p)
			m.store.Add(dp)

			// Update stats
			m.stats.UpdateFromPacketInfo(p)

			// Run expert analysis
			if m.expertAnalyzer != nil {
				m.expertAnalyzer.Analyze(&p)
			}

			// Auto-scroll to new packet in list view
			if m.viewMode == ViewList && m.isLive {
				m.selectedIdx = m.getPacketCount() - 1
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

			// Check if the response contains a confirmation request
			if strings.Contains(m.aiStreamContent, "[CONFIRMATION_REQUIRED]") {
				if m.aiAssistant != nil && m.aiAssistant.HasPendingConfirmation() {
					m.pendingConfirmation = m.aiAssistant.GetPendingConfirmation()
					m.showConfirmDialog = true
				}
			}

			m.aiStreamingMsgID = -1
			m.aiStreamContent = ""
			return m, nil
		}

		// Handle different stream event types
		switch msg.event.Type {
		case "delta":
			// Append delta to current streaming content
			m.aiStreamContent += msg.event.Delta
			// Update the message being streamed
			if m.aiStreamingMsgID >= 0 && m.aiStreamingMsgID < len(m.chatMessages) {
				m.chatMessages[m.aiStreamingMsgID].Content = m.aiStreamContent + "▌"
			}
			m.chatScroll = len(m.chatMessages) * 10

		case "tool_start":
			// Show tool execution indicator
			if msg.event.ToolName != "" {
				toolInfo := fmt.Sprintf("\n🔧 [执行工具: %s]", msg.event.ToolName)
				m.aiStreamContent += toolInfo
				if m.aiStreamingMsgID >= 0 && m.aiStreamingMsgID < len(m.chatMessages) {
					m.chatMessages[m.aiStreamingMsgID].Content = m.aiStreamContent + "▌"
				}
			}

		case "error":
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

		case "end":
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
		// Handle confirmation dialog first (highest priority)
		if m.showConfirmDialog && m.pendingConfirmation != nil {
			switch msg.String() {
			case "y", "Y":
				// Grant authorization for this session
				if m.aiAssistant != nil {
					m.aiAssistant.GrantAuthorization(true)
					// Retry the tool call
					result, err := m.aiAssistant.RetryLastToolCall()
					if err != nil {
						m.AddChatMessage("system", "重试失败: "+err.Error(), true)
					} else {
						// Update the last message with the result
						m.AddChatMessage("assistant", "✅ 已授权\n\n"+result, false)
					}
				}
				m.showConfirmDialog = false
				m.pendingConfirmation = nil
				return m, nil
			case "n", "N", "esc":
				// Deny authorization
				if m.aiAssistant != nil {
					m.aiAssistant.DenyAuthorization()
				}
				m.AddChatMessage("system", "❌ 用户拒绝了显示原始数据的请求", false)
				m.showConfirmDialog = false
				m.pendingConfirmation = nil
				return m, nil
			}
			// Don't process other keys while dialog is open
			return m, nil
		}

		// Handle chat input mode with textinput
		if m.chatInputActive {
			switch msg.String() {
			case "enter":
				input := m.chatTextInput.Value()
				if input != "" && m.aiAssistant != nil && !m.aiProcessing {
					m.AddChatMessage("user", input, false)
					userMsg := input
					m.chatTextInput.SetValue("")
					m.aiProcessing = true
					m.chatInputActive = false
					m.chatTextInput.Blur()
					// Use streaming API
					return m, sendAIMessageStream(m.aiAssistant, userMsg)
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
			if m.store != nil {
				m.store.Close()
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
			case ViewExpert:
				if m.expertScroll > 0 {
					m.expertScroll--
				}
			}
			return m, nil

		case "down", "j":
			switch m.viewMode {
			case ViewList:
				count := m.getPacketCount()
				if m.selectedIdx < count-1 {
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
			case ViewExpert:
				m.expertScroll++
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
			case ViewExpert:
				m.expertScroll -= 20
				if m.expertScroll < 0 {
					m.expertScroll = 0
				}
			}
			return m, nil

		case "pgdown":
			switch m.viewMode {
			case ViewList:
				count := m.getPacketCount()
				m.selectedIdx += 20
				if m.selectedIdx >= count {
					m.selectedIdx = count - 1
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
			case ViewExpert:
				m.expertScroll += 20
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
			case ViewExpert:
				m.expertScroll = 0
			}
			return m, nil

		case "end", "G":
			switch m.viewMode {
			case ViewList:
				count := m.getPacketCount()
				m.selectedIdx = count - 1
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

		case "e":
			// Toggle expert view
			if m.viewMode == ViewExpert {
				m.viewMode = ViewList
			} else {
				m.viewMode = ViewExpert
				m.expertScroll = 0
			}
			return m, nil

		case "1":
			// Set expert filter to Error only
			if m.viewMode == ViewExpert {
				m.expertMinSeverity = expert.SeverityError
				m.expertScroll = 0
			}
			return m, nil

		case "2":
			// Set expert filter to Warning+
			if m.viewMode == ViewExpert {
				m.expertMinSeverity = expert.SeverityWarning
				m.expertScroll = 0
			}
			return m, nil

		case "3":
			// Set expert filter to Note+
			if m.viewMode == ViewExpert {
				m.expertMinSeverity = expert.SeverityNote
				m.expertScroll = 0
			}
			return m, nil

		case "4":
			// Set expert filter to Chat (all)
			if m.viewMode == ViewExpert {
				m.expertMinSeverity = expert.SeverityChat
				m.expertScroll = 0
			}
			return m, nil

		case "w":
			// Save packets to file
			if m.store != nil && m.store.Count() > 0 {
				m.statusMessage = "Saving..."
				m.statusIsError = false
				return m, savePacketsCmd(m.store)
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
			case ViewExpert:
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
	if m.store != nil {
		m.store.SetFilter(m.filter)
	}
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
	} else if m.showConfirmDialog && m.pendingConfirmation != nil {
		sb.WriteString("\n\n")
		sb.WriteString(m.renderConfirmationDialog())
		sb.WriteString("\n\n")
		// Add some helpful text if not in chat view
		if m.viewMode != ViewChat {
			sb.WriteString(dimStyle.Render("  (Authorization requested by AI Agent. Please confirm to proceed.)"))
		}
		// Fill some space to push status bar down
		lines := strings.Count(sb.String(), "\n")
		for i := lines; i < m.height-2; i++ {
			sb.WriteString("\n")
		}
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
		case ViewExpert:
			sb.WriteString(m.renderExpertView())
		}
	}

	// Status bar
	sb.WriteString(m.renderStatusBar())

	return sb.String()
}

// Run starts the TUI application with a PacketStore
func Run(store uiadapter.PacketStore, packetChan <-chan capture.PacketInfo, capturer *capture.Capturer, isLive bool) error {
	model := NewModel(store, packetChan, capturer, isLive)
	p := tea.NewProgram(model, tea.WithAltScreen())

	_, err := p.Run()
	return err
}

// RunWithAI starts the TUI application with AI assistant
func RunWithAI(store uiadapter.PacketStore, packetChan <-chan capture.PacketInfo, capturer *capture.Capturer, isLive bool, ai uiadapter.AIAssistant) error {
	model := NewModel(store, packetChan, capturer, isLive)
	model.SetAIAssistant(ai)

	// Add welcome message
	if ai != nil {
		model.AddChatMessage("assistant", "你好！我是 AI 网络分析助手。我可以帮你：\n• 分析捕获的数据包\n• 解释网络协议\n• 统计流量信息\n• 检测异常模式\n\n按 'a' 切换到聊天视图，按 'i' 开始输入。", false)
	}

	p := tea.NewProgram(model, tea.WithAltScreen())

	_, err := p.Run()
	return err
}

// RunWithStore starts the TUI application with just a PacketStore (for indexed mode)
func RunWithStore(store uiadapter.PacketStore, ai uiadapter.AIAssistant) error {
	model := NewModelWithStore(store)
	if ai != nil {
		model.SetAIAssistant(ai)
		model.AddChatMessage("assistant", "你好！我是 AI 网络分析助手。我可以帮你：\n• 分析捕获的数据包\n• 解释网络协议\n• 统计流量信息\n• 检测异常模式\n\n按 'a' 切换到聊天视图，按 'i' 开始输入。", false)
	}

	p := tea.NewProgram(model, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
