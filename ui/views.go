package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/expert"
	"github.com/Zerofisher/pktanalyzer/stream"
)

func (m Model) renderPacketList() string {
	var sb strings.Builder

	// Calculate visible area
	listHeight := m.height - 8 // Reserve space for header, stats, help
	if listHeight < 5 {
		listHeight = 5
	}

	// Header
	header := fmt.Sprintf("%-6s %-15s %-22s %-22s %-8s %s",
		"No.", "Time", "Source", "Destination", "Proto", "Info")
	sb.WriteString(headerStyle.Width(m.width).Render(header))
	sb.WriteString("\n")

	packets := m.getDisplayPackets()

	// Adjust scroll to keep selected visible
	if m.selectedIdx < m.scrollOffset {
		m.scrollOffset = m.selectedIdx
	}
	if m.selectedIdx >= m.scrollOffset+listHeight {
		m.scrollOffset = m.selectedIdx - listHeight + 1
	}

	// Render visible packets
	for i := m.scrollOffset; i < len(packets) && i < m.scrollOffset+listHeight; i++ {
		p := packets[i]

		timeStr := p.Timestamp.Format("15:04:05.000")
		src := truncateStr(formatAddr(p.SrcIP, p.SrcPort), 22)
		dst := truncateStr(formatAddr(p.DstIP, p.DstPort), 22)
		info := truncateStr(p.Info, m.width-75)

		line := fmt.Sprintf("%-6d %-15s %-22s %-22s %-8s %s",
			p.Number, timeStr, src, dst, p.Protocol, info)

		style := normalStyle
		if i == m.selectedIdx {
			style = selectedStyle.Width(m.width)
		} else {
			style = getProtocolStyle(p.Protocol).Width(m.width)
		}

		sb.WriteString(style.Render(line))
		sb.WriteString("\n")
	}

	// Fill remaining space
	for i := len(packets) - m.scrollOffset; i < listHeight; i++ {
		sb.WriteString("\n")
	}

	return sb.String()
}

func (m Model) renderPacketDetail() string {
	var sb strings.Builder

	packets := m.getDisplayPackets()
	if m.selectedIdx >= len(packets) {
		return "No packet selected"
	}

	p := packets[m.selectedIdx]

	// Header
	header := fmt.Sprintf("Packet #%d Details - %s", p.Number, p.Timestamp.Format("2006-01-02 15:04:05.000000"))
	sb.WriteString(titleStyle.Width(m.width).Render(header))
	sb.WriteString("\n\n")

	detailHeight := m.height - 6
	lines := make([]string, 0)

	// Render each layer
	for _, layer := range p.Layers {
		lines = append(lines, layerHeaderStyle.Render("▼ "+layer.Name))
		for _, detail := range layer.Details {
			lines = append(lines, layerDetailStyle.Render(detail))
		}
		lines = append(lines, "")
	}

	// Apply scroll
	start := m.detailScroll
	if start >= len(lines) {
		start = 0
	}
	end := start + detailHeight
	if end > len(lines) {
		end = len(lines)
	}

	for i := start; i < end; i++ {
		sb.WriteString(lines[i])
		sb.WriteString("\n")
	}

	return sb.String()
}

func (m Model) renderHexDump() string {
	var sb strings.Builder

	packets := m.getDisplayPackets()
	if m.selectedIdx >= len(packets) {
		return "No packet selected"
	}

	p := packets[m.selectedIdx]
	data := p.RawData

	// Header
	header := fmt.Sprintf("Packet #%d Hex Dump - %d bytes", p.Number, len(data))
	sb.WriteString(titleStyle.Width(m.width).Render(header))
	sb.WriteString("\n\n")

	hexHeight := m.height - 6
	bytesPerLine := 16
	totalLines := (len(data) + bytesPerLine - 1) / bytesPerLine

	start := m.hexScroll
	if start >= totalLines {
		start = 0
	}

	for lineIdx := start; lineIdx < totalLines && lineIdx < start+hexHeight; lineIdx++ {
		offset := lineIdx * bytesPerLine

		// Offset
		sb.WriteString(hexOffsetStyle.Render(fmt.Sprintf("%08x  ", offset)))

		// Hex bytes
		hexPart := strings.Builder{}
		asciiPart := strings.Builder{}

		for i := 0; i < bytesPerLine; i++ {
			idx := offset + i
			if idx < len(data) {
				hexPart.WriteString(fmt.Sprintf("%02x ", data[idx]))
				if data[idx] >= 32 && data[idx] <= 126 {
					asciiPart.WriteByte(data[idx])
				} else {
					asciiPart.WriteByte('.')
				}
			} else {
				hexPart.WriteString("   ")
				asciiPart.WriteByte(' ')
			}

			if i == 7 {
				hexPart.WriteByte(' ')
			}
		}

		sb.WriteString(hexByteStyle.Render(hexPart.String()))
		sb.WriteString(" ")
		sb.WriteString(hexAsciiStyle.Render("|" + asciiPart.String() + "|"))
		sb.WriteString("\n")
	}

	return sb.String()
}

func (m Model) renderStats() string {
	var stats string
	if m.stats.TLS > 0 || m.stats.HTTPS > 0 {
		stats = fmt.Sprintf("Total: %d | TCP: %d | UDP: %d | TLS: %d | HTTPS: %d (Decrypted: %d) | DNS: %d | HTTP: %d",
			m.stats.Total, m.stats.TCP, m.stats.UDP, m.stats.TLS, m.stats.HTTPS, m.stats.Decrypted, m.stats.DNS, m.stats.HTTP)
	} else {
		stats = fmt.Sprintf("Total: %d | TCP: %d | UDP: %d | ICMP: %d | ARP: %d | DNS: %d | HTTP: %d | Other: %d",
			m.stats.Total, m.stats.TCP, m.stats.UDP, m.stats.ICMP, m.stats.ARP, m.stats.DNS, m.stats.HTTP, m.stats.Other)
	}
	return statusStyle.Width(m.width).Render(stats)
}

func (m Model) renderHelp() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Width(m.width).Render("Help"))
	sb.WriteString("\n\n")

	helpText := []string{
		"Navigation:",
		"  ↑/k       Move up",
		"  ↓/j       Move down",
		"  PgUp      Page up",
		"  PgDn      Page down",
		"  Home/g    Go to first packet",
		"  End/G     Go to last packet",
		"",
		"Views:",
		"  Enter     Toggle detail view",
		"  x         Toggle hex view",
		"  s         Toggle stream view (TCP flow)",
		"  e         Toggle expert view (anomaly detection)",
		"  Esc       Return to list view",
		"",
		"Filter:",
		"  /         Start filter input",
		"  Enter     Apply filter",
		"  Esc       Cancel filter",
		"",
		"Other:",
		"  w         Save packets to pcapng file",
		"  Space     Pause/Resume capture (live mode)",
		"  ?         Toggle this help",
		"  q         Quit",
	}

	helpHeight := m.height - 6
	start := m.helpScroll
	end := start + helpHeight
	if end > len(helpText) {
		end = len(helpText)
	}

	for i := start; i < end; i++ {
		sb.WriteString(helpText[i])
		sb.WriteString("\n")
	}

	return sb.String()
}

func (m Model) renderFilterBar() string {
	if m.filterActive {
		return statusStyle.Width(m.width).Render("Filter: " + m.filterTextInput.View())
	}
	if m.filter != "" {
		return statusStyle.Width(m.width).Render(fmt.Sprintf("Filter: %s", m.filter))
	}
	return ""
}

func (m Model) renderStatusBar() string {
	// Show status message if present
	if m.statusMessage != "" {
		if m.statusIsError {
			return errorStyle.Width(m.width).Render(m.statusMessage)
		}
		return successStyle.Width(m.width).Render(m.statusMessage)
	}

	mode := "File"
	if m.isLive {
		mode = "Live"
		if m.paused {
			mode = "Paused"
		}
	}

	viewName := "List"
	switch m.viewMode {
	case ViewDetail:
		viewName = "Detail"
	case ViewHex:
		viewName = "Hex"
	case ViewStreamList:
		viewName = "Streams"
	case ViewStreamDetail:
		viewName = "Stream Detail"
	case ViewExpert:
		viewName = "Expert"
	}

	packets := m.getDisplayPackets()
	selected := m.selectedIdx + 1
	if selected > len(packets) {
		selected = len(packets)
	}

	var status string
	if m.viewMode == ViewStreamList || m.viewMode == ViewStreamDetail {
		streams := m.GetStreams()
		streamCount := len(streams)
		streamSelected := m.streamSelectedIdx + 1
		if streamSelected > streamCount {
			streamSelected = streamCount
		}
		status = fmt.Sprintf("[%s] View: %s | Stream: %d/%d | Press ? for help, q to quit",
			mode, viewName, streamSelected, streamCount)
	} else {
		status = fmt.Sprintf("[%s] View: %s | Packet: %d/%d | Press ? for help, w to save, q to quit",
			mode, viewName, selected, len(packets))
	}
	return helpStyle.Width(m.width).Render(status)
}

func (m Model) getDisplayPackets() []capture.PacketInfo {
	if m.filter == "" {
		return m.packets
	}
	return m.filteredPkts
}

func (m Model) renderStreamList() string {
	var sb strings.Builder

	streams := m.GetStreams()
	if len(streams) == 0 {
		sb.WriteString(titleStyle.Width(m.width).Render(" TCP Streams (Stream tracking not enabled or no streams yet) "))
		sb.WriteString("\n\n")
		sb.WriteString("Press 's' to return to packet list\n")
		return sb.String()
	}

	// Header
	sb.WriteString(titleStyle.Width(m.width).Render(" TCP Streams "))
	sb.WriteString("\n")

	header := fmt.Sprintf("%-4s %-24s %-24s %-6s %-10s %-10s %-10s",
		"#", "Client", "Server", "Pkts", "Bytes", "Protocol", "State")
	sb.WriteString(headerStyle.Width(m.width).Render(header))
	sb.WriteString("\n")

	// Calculate visible area
	listHeight := m.height - 8
	if listHeight < 5 {
		listHeight = 5
	}

	// Render streams
	for i := m.streamScroll; i < len(streams) && i < m.streamScroll+listHeight; i++ {
		s := streams[i]

		// Detect protocol if not done
		if s.Protocol == "" {
			s.DetectProtocol()
		}

		protocol := s.Protocol
		if protocol == "" {
			protocol = "-"
		}

		bytesStr := formatBytes(s.TotalBytes())
		line := fmt.Sprintf("%-4d %-24s %-24s %-6d %-10s %-10s %-10s",
			s.ID,
			truncateStr(s.ClientAddr, 24),
			truncateStr(s.ServerAddr, 24),
			s.PacketCount,
			bytesStr,
			truncateStr(protocol, 10),
			s.State.String())

		style := normalStyle
		if i == m.streamSelectedIdx {
			style = selectedStyle.Width(m.width)
		} else if s.IsHTTP2 {
			style = http2Style.Width(m.width) // Highlight HTTP/2 streams
		} else if s.IsWebSocket {
			style = websocketStyle.Width(m.width) // Highlight WebSocket streams
		}

		sb.WriteString(style.Render(line))
		sb.WriteString("\n")
	}

	return sb.String()
}

func (m Model) renderStreamDetail() string {
	var sb strings.Builder

	if m.selectedStream == nil {
		return "No stream selected"
	}

	s := m.selectedStream

	// Header
	header := fmt.Sprintf(" Stream #%d: %s → %s ", s.ID, s.ClientAddr, s.ServerAddr)
	sb.WriteString(titleStyle.Width(m.width).Render(header))
	sb.WriteString("\n")

	// Stream info
	info := fmt.Sprintf("State: %s | Packets: %d | Duration: %v",
		s.State.String(), s.PacketCount, s.Duration().Round(1e6))
	if s.Protocol != "" {
		info += fmt.Sprintf(" | Protocol: %s", s.Protocol)
	}
	sb.WriteString(statusStyle.Width(m.width).Render(info))
	sb.WriteString("\n\n")

	detailHeight := m.height - 8
	lines := make([]string, 0)

	// Detect protocol if not done
	if s.Protocol == "" {
		s.DetectProtocol()
	}

	// HTTP/2 display
	if s.IsHTTP2 || stream.IsHTTP2Preface(s.GetClientData()) {
		// Initialize and parse HTTP/2
		if s.HTTP2Parser == nil {
			s.InitHTTP2Parser()
			s.ParseHTTP2()
		}

		lines = append(lines, layerHeaderStyle.Render("▼ HTTP/2 Connection"))
		conn := s.HTTP2Parser.Connection
		lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("  Streams: %d | Frames: %d", conn.StreamCount(), len(conn.AllFrames))))
		lines = append(lines, "")

		// Show HTTP/2 frames summary
		lines = append(lines, layerHeaderStyle.Render("▼ HTTP/2 Frames"))
		for i, frame := range conn.AllFrames {
			if i >= 50 { // Limit display
				lines = append(lines, dimStyle.Render(fmt.Sprintf("  ... and %d more frames", len(conn.AllFrames)-i)))
				break
			}
			lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("  [%d] %s", i+1, frame.Summary())))
		}
		lines = append(lines, "")

		// Show HTTP/2 streams with requests/responses
		h2streams := conn.GetAllStreams()
		if len(h2streams) > 0 {
			lines = append(lines, layerHeaderStyle.Render("▼ HTTP/2 Streams"))
			for _, h2s := range h2streams {
				streamInfo := fmt.Sprintf("  Stream %d: %s", h2s.ID, h2s.State.String())
				lines = append(lines, layerDetailStyle.Render(streamInfo))

				if h2s.Request != nil {
					lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("    Request: %s %s%s",
						h2s.Request.Method, h2s.Request.Authority, h2s.Request.Path)))
					// Show some headers
					for k, v := range h2s.Request.Headers {
						if len(lines) < 100 { // Limit
							lines = append(lines, dimStyle.Render(fmt.Sprintf("      %s: %s", k, truncateStr(v, 60))))
						}
					}
				}

				if h2s.Response != nil {
					lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("    Response: Status %s", h2s.Response.Status)))
					// Show some headers
					for k, v := range h2s.Response.Headers {
						if len(lines) < 100 { // Limit
							lines = append(lines, dimStyle.Render(fmt.Sprintf("      %s: %s", k, truncateStr(v, 60))))
						}
					}
				}

				if len(h2s.RequestData) > 0 {
					lines = append(lines, dimStyle.Render(fmt.Sprintf("    Request body: %d bytes", len(h2s.RequestData))))
				}
				if len(h2s.ResponseData) > 0 {
					lines = append(lines, dimStyle.Render(fmt.Sprintf("    Response body: %d bytes", len(h2s.ResponseData))))
				}
				lines = append(lines, "")
			}
		}
	} else if s.IsWebSocket || stream.IsWebSocketUpgrade(s.GetClientData()) {
		// WebSocket display
		if s.WebSocketParser == nil {
			s.InitWebSocketParser()
			s.ParseWebSocket()
		}

		wsConn := s.WebSocketParser.Connection

		// Handshake info
		if wsConn.Handshake != nil {
			lines = append(lines, layerHeaderStyle.Render("▼ WebSocket Handshake"))
			h := wsConn.Handshake
			lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("  URI: %s", h.RequestURI)))
			if h.Host != "" {
				lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("  Host: %s", h.Host)))
			}
			if h.Origin != "" {
				lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("  Origin: %s", h.Origin)))
			}
			if h.SelectedSubprotocol != "" {
				lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("  Subprotocol: %s", h.SelectedSubprotocol)))
			}
			if h.PermessageDeflate {
				lines = append(lines, layerDetailStyle.Render("  Compression: permessage-deflate"))
			}
			validStr := "✓ Valid"
			if !h.IsValid {
				validStr = "✗ Invalid"
			}
			lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("  Handshake: %s", validStr)))
			lines = append(lines, "")
		}

		// Connection summary
		lines = append(lines, layerHeaderStyle.Render("▼ WebSocket Connection"))
		lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("  Frames: %d (Client: %d, Server: %d)",
			len(wsConn.Frames), wsConn.ClientFrames, wsConn.ServerFrames)))
		lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("  Messages: %d (Text: %d, Binary: %d)",
			len(wsConn.Messages), wsConn.TextMessages, wsConn.BinaryMessages)))
		lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("  Bytes: C→S %d, S→C %d",
			wsConn.ClientBytes, wsConn.ServerBytes)))
		if wsConn.PingCount > 0 || wsConn.PongCount > 0 {
			lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("  Ping/Pong: %d/%d", wsConn.PingCount, wsConn.PongCount)))
		}
		if wsConn.Closed {
			lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("  Closed: code=%d (%s) reason=%q",
				wsConn.CloseCode, stream.GetWebSocketCloseReason(wsConn.CloseCode), wsConn.CloseReason)))
		}
		lines = append(lines, "")

		// Show WebSocket frames
		lines = append(lines, layerHeaderStyle.Render("▼ WebSocket Frames"))
		for i, frame := range wsConn.Frames {
			if i >= 50 { // Limit display
				lines = append(lines, dimStyle.Render(fmt.Sprintf("  ... and %d more frames", len(wsConn.Frames)-i)))
				break
			}
			lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("  %s", frame.Summary())))

			// Show payload preview for text frames
			if frame.Opcode == stream.OpcodeText && len(frame.Payload) > 0 {
				text := frame.GetPayloadText()
				if len(text) > 80 {
					text = text[:77] + "..."
				}
				lines = append(lines, dimStyle.Render(fmt.Sprintf("    → %s", text)))
			}

			// Show close reason
			if frame.Opcode == stream.OpcodeClose {
				code, reason := frame.GetCloseCode()
				if code > 0 {
					lines = append(lines, dimStyle.Render(fmt.Sprintf("    → Close code: %d (%s) %s",
						code, stream.GetWebSocketCloseReason(code), reason)))
				}
			}
		}
		lines = append(lines, "")

		// Show messages (assembled from frames)
		if len(wsConn.Messages) > 0 {
			lines = append(lines, layerHeaderStyle.Render("▼ WebSocket Messages"))
			for i, msg := range wsConn.Messages {
				if i >= 20 { // Limit display
					lines = append(lines, dimStyle.Render(fmt.Sprintf("  ... and %d more messages", len(wsConn.Messages)-i)))
					break
				}
				fragStr := ""
				if len(msg.Frames) > 1 {
					fragStr = fmt.Sprintf(" (%d fragments)", len(msg.Frames))
				}
				lines = append(lines, layerDetailStyle.Render(fmt.Sprintf("  [%d] %s %d bytes%s",
					i+1, msg.Opcode, len(msg.Payload), fragStr)))

				// Show text message preview
				if msg.Opcode == stream.OpcodeText && len(msg.Payload) > 0 {
					text := string(msg.Payload)
					if len(text) > 100 {
						text = text[:97] + "..."
					}
					// Format multiline text
					textLines := strings.Split(text, "\n")
					for j, tl := range textLines {
						if j >= 3 {
							lines = append(lines, dimStyle.Render("    ..."))
							break
						}
						if len(tl) > 80 {
							tl = tl[:77] + "..."
						}
						lines = append(lines, dimStyle.Render(fmt.Sprintf("    %s", tl)))
					}
				}
			}
		}
	} else {
		// Regular stream data display (HTTP/1.1 or raw)
		// Client → Server data
		clientData := s.GetClientData()
		if len(clientData) > 0 {
			lines = append(lines, layerHeaderStyle.Render(fmt.Sprintf("▼ Client → Server (%d bytes)", len(clientData))))
			dataLines := formatStreamData(clientData, m.width-4)
			lines = append(lines, dataLines...)
			lines = append(lines, "")
		}

		// Server → Client data
		serverData := s.GetServerData()
		if len(serverData) > 0 {
			lines = append(lines, layerHeaderStyle.Render(fmt.Sprintf("▼ Server → Client (%d bytes)", len(serverData))))
			dataLines := formatStreamData(serverData, m.width-4)
			lines = append(lines, dataLines...)
		}
	}

	if len(lines) == 0 {
		lines = append(lines, dimStyle.Render("No application data captured"))
	}

	// Apply scroll
	start := m.streamDetailScroll
	if start >= len(lines) {
		start = 0
	}
	end := start + detailHeight
	if end > len(lines) {
		end = len(lines)
	}

	for i := start; i < end; i++ {
		sb.WriteString(lines[i])
		sb.WriteString("\n")
	}

	return sb.String()
}

func formatStreamData(data []byte, maxWidth int) []string {
	var lines []string
	text := string(data)

	// Try to parse as HTTP
	parser := stream.NewHTTPParser()
	if isHTTPData(data) {
		// Format as HTTP
		for _, line := range strings.Split(text, "\r\n") {
			if len(line) > maxWidth {
				line = line[:maxWidth-3] + "..."
			}
			lines = append(lines, layerDetailStyle.Render(line))
			if len(lines) > 50 {
				lines = append(lines, dimStyle.Render("... (truncated)"))
				break
			}
		}
	} else {
		// Format as hex/ascii
		for i := 0; i < len(data) && len(lines) < 30; i += 16 {
			end := i + 16
			if end > len(data) {
				end = len(data)
			}
			chunk := data[i:end]

			hex := ""
			ascii := ""
			for j, b := range chunk {
				hex += fmt.Sprintf("%02x ", b)
				if j == 7 {
					hex += " "
				}
				if b >= 32 && b <= 126 {
					ascii += string(b)
				} else {
					ascii += "."
				}
			}
			// Pad hex
			for j := len(chunk); j < 16; j++ {
				hex += "   "
				if j == 7 {
					hex += " "
				}
			}
			line := fmt.Sprintf("%08x  %s |%s|", i, hex, ascii)
			lines = append(lines, layerDetailStyle.Render(line))
		}
		if len(data) > 480 {
			lines = append(lines, dimStyle.Render("... (truncated)"))
		}
	}

	_ = parser // suppress unused warning
	return lines
}

func isHTTPData(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	methods := []string{"GET ", "POST", "PUT ", "DELE", "HEAD", "OPTI", "PATC", "HTTP"}
	prefix := string(data[:4])
	for _, m := range methods {
		if prefix == m {
			return true
		}
	}
	return false
}

func formatBytes(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	} else {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
}

func formatAddr(ip, port string) string {
	if ip == "" {
		return ""
	}
	if port == "" {
		return ip
	}
	return fmt.Sprintf("%s:%s", ip, port)
}

func truncateStr(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// renderChatView renders the AI chat interface
func (m Model) renderChatView() string {
	var sb strings.Builder

	// Calculate dimensions
	chatHeight := m.height - 8
	if chatHeight < 5 {
		chatHeight = 5
	}

	// Header
	header := "🤖 AI 网络分析助手"
	if m.aiProcessing {
		header += " (思考中...)"
	}
	sb.WriteString(titleStyle.Width(m.width).Render(header))
	sb.WriteString("\n")

	// Render messages
	var lines []string
	for _, msg := range m.chatMessages {
		var prefix string
		var msgStyle = normalStyle

		switch msg.Role {
		case "user":
			prefix = "👤 You: "
			msgStyle = userMsgStyle
		case "assistant":
			prefix = "🤖 AI: "
			msgStyle = assistantMsgStyle
		case "system":
			prefix = "⚠️  "
			if msg.IsError {
				msgStyle = errorStyle
			} else {
				msgStyle = systemMsgStyle
			}
		}

		// Word wrap the message content
		content := msg.Content
		wrappedLines := wrapText(content, m.width-10)

		// First line with prefix
		if len(wrappedLines) > 0 {
			lines = append(lines, msgStyle.Render(prefix+wrappedLines[0]))
			// Continuation lines
			for i := 1; i < len(wrappedLines); i++ {
				lines = append(lines, msgStyle.Render("    "+wrappedLines[i]))
			}
		}
		lines = append(lines, "") // Empty line between messages
	}

	// Apply scroll
	start := m.chatScroll
	if start >= len(lines) {
		start = len(lines) - chatHeight
		if start < 0 {
			start = 0
		}
	}
	end := start + chatHeight - 2 // Reserve space for input
	if end > len(lines) {
		end = len(lines)
	}

	// Render visible lines
	for i := start; i < end; i++ {
		sb.WriteString(lines[i])
		sb.WriteString("\n")
	}

	// Fill remaining space
	for i := end - start; i < chatHeight-2; i++ {
		sb.WriteString("\n")
	}

	// Input area
	sb.WriteString(strings.Repeat("─", m.width))
	sb.WriteString("\n")

	// Show confirmation dialog if active
	if m.showConfirmDialog && m.pendingConfirmation != nil {
		sb.WriteString(m.renderConfirmationDialog())
	} else if m.aiProcessing {
		sb.WriteString(inputStyle.Width(m.width).Render("⏳ AI 正在处理..."))
	} else if m.chatInputActive {
		// Use textinput component for input
		sb.WriteString(inputStyle.Width(m.width).Render(">> " + m.chatTextInput.View()))
	} else {
		sb.WriteString(inputStyle.Width(m.width).Render("> 按 'i' 开始输入"))
	}

	return sb.String()
}

// renderConfirmationDialog renders the authorization confirmation dialog
func (m Model) renderConfirmationDialog() string {
	if m.pendingConfirmation == nil {
		return ""
	}

	var sb strings.Builder

	// Dialog box with warning style
	dialogStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("226")). // Yellow
		Padding(1, 2).
		Width(m.width - 4)

	var content strings.Builder
	content.WriteString("⚠️  授权确认\n\n")
	content.WriteString(m.pendingConfirmation.Description)
	content.WriteString("\n\n")
	content.WriteString("按 [Y] 允许 (本次会话有效)  |  按 [N] 或 [Esc] 拒绝")

	sb.WriteString(dialogStyle.Render(content.String()))

	return sb.String()
}

// renderSplitView renders packets on left, chat on right
func (m Model) renderSplitView() string {
	var sb strings.Builder

	// Split width
	leftWidth := m.width * 60 / 100
	rightWidth := m.width - leftWidth - 1 // 1 for divider

	// Calculate heights
	contentHeight := m.height - 6

	// Render left side (packets)
	leftLines := m.renderPacketListLines(leftWidth, contentHeight)

	// Render right side (chat)
	rightLines := m.renderChatLines(rightWidth, contentHeight)

	// Combine with divider
	for i := 0; i < contentHeight; i++ {
		leftLine := ""
		rightLine := ""

		if i < len(leftLines) {
			leftLine = leftLines[i]
		}
		if i < len(rightLines) {
			rightLine = rightLines[i]
		}

		// Pad left line
		leftLine = padRight(leftLine, leftWidth)
		sb.WriteString(leftLine)
		sb.WriteString("│")
		sb.WriteString(rightLine)
		sb.WriteString("\n")
	}

	return sb.String()
}

func (m Model) renderPacketListLines(width, height int) []string {
	var lines []string

	// Header
	header := fmt.Sprintf("%-6s %-12s %-16s %-8s", "No.", "Time", "Src/Dst", "Proto")
	lines = append(lines, headerStyle.Width(width).Render(header))

	packets := m.getDisplayPackets()

	// Adjust scroll
	listHeight := height - 1
	startIdx := m.scrollOffset
	if m.selectedIdx < startIdx {
		startIdx = m.selectedIdx
	}
	if m.selectedIdx >= startIdx+listHeight {
		startIdx = m.selectedIdx - listHeight + 1
	}

	for i := startIdx; i < len(packets) && i < startIdx+listHeight; i++ {
		p := packets[i]
		timeStr := p.Timestamp.Format("15:04:05")
		addr := truncateStr(p.SrcIP, 16)

		line := fmt.Sprintf("%-6d %-12s %-16s %-8s", p.Number, timeStr, addr, p.Protocol)

		if i == m.selectedIdx {
			lines = append(lines, selectedStyle.Width(width).Render(line))
		} else {
			lines = append(lines, getProtocolStyle(p.Protocol).Width(width).Render(line))
		}
	}

	// Fill remaining
	for i := len(lines); i < height; i++ {
		lines = append(lines, "")
	}

	return lines
}

func (m Model) renderChatLines(width, height int) []string {
	var lines []string

	// Header
	header := "🤖 AI Chat"
	if m.aiProcessing {
		header += " ⏳"
	}
	lines = append(lines, titleStyle.Width(width).Render(header))

	// Messages
	for _, msg := range m.chatMessages {
		prefix := ""
		switch msg.Role {
		case "user":
			prefix = "👤 "
		case "assistant":
			prefix = "🤖 "
		}

		content := truncateStr(msg.Content, width-5)
		// Take first line only for split view
		if idx := strings.Index(content, "\n"); idx != -1 {
			content = content[:idx] + "..."
		}
		lines = append(lines, prefix+content)
	}

	// Input hint
	if len(lines) < height-1 {
		lines = append(lines, "")
		lines = append(lines, dimStyle.Render("Press 'a' for full chat"))
	}

	// Fill remaining
	for len(lines) < height {
		lines = append(lines, "")
	}

	return lines[:height]
}

// wrapText wraps text to the specified width
func wrapText(text string, width int) []string {
	if width <= 0 {
		width = 80
	}

	var lines []string
	paragraphs := strings.Split(text, "\n")

	for _, para := range paragraphs {
		if para == "" {
			lines = append(lines, "")
			continue
		}

		words := strings.Fields(para)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}

		currentLine := words[0]
		for _, word := range words[1:] {
			if len(currentLine)+1+len(word) <= width {
				currentLine += " " + word
			} else {
				lines = append(lines, currentLine)
				currentLine = word
			}
		}
		lines = append(lines, currentLine)
	}

	return lines
}

// padRight pads a string to the specified width
func padRight(s string, width int) string {
	// Count actual display width (accounting for CJK characters)
	displayWidth := 0
	for _, r := range s {
		if r > 0x7F {
			displayWidth += 2 // CJK characters take 2 columns
		} else {
			displayWidth += 1
		}
	}

	if displayWidth >= width {
		return s
	}

	return s + strings.Repeat(" ", width-displayWidth)
}

// renderExpertView renders the expert information view
func (m Model) renderExpertView() string {
	var sb strings.Builder

	analyzer := m.expertAnalyzer
	if analyzer == nil {
		return "Expert analysis not available"
	}

	// Header
	stats := analyzer.GetStatistics()
	header := fmt.Sprintf(" 🔍 Expert Information (%d issues found) ", stats.TotalCount)
	sb.WriteString(titleStyle.Width(m.width).Render(header))
	sb.WriteString("\n")

	// Summary bar
	summaryParts := []string{}
	if stats.CountBySeverity[expert.SeverityError] > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("Errors: %d", stats.CountBySeverity[expert.SeverityError]))
	}
	if stats.CountBySeverity[expert.SeverityWarning] > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("Warnings: %d", stats.CountBySeverity[expert.SeverityWarning]))
	}
	if stats.CountBySeverity[expert.SeverityNote] > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("Notes: %d", stats.CountBySeverity[expert.SeverityNote]))
	}
	if stats.CountBySeverity[expert.SeverityChat] > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("Chat: %d", stats.CountBySeverity[expert.SeverityChat]))
	}

	summary := strings.Join(summaryParts, " | ")
	if summary == "" {
		summary = "No issues detected"
	}
	summary += fmt.Sprintf("  [Filter: %s+]", m.expertMinSeverity.String())
	sb.WriteString(statusStyle.Width(m.width).Render(summary))
	sb.WriteString("\n")

	// Table header
	tableHeader := fmt.Sprintf("%-6s %-8s %-10s %-8s %-25s %s",
		"Packet", "Severity", "Group", "Proto", "Summary", "Details")
	sb.WriteString(headerStyle.Width(m.width).Render(tableHeader))
	sb.WriteString("\n")

	// Calculate visible area
	listHeight := m.height - 10
	if listHeight < 5 {
		listHeight = 5
	}

	// Get filtered infos
	infos := analyzer.GetInfosBySeverity(m.expertMinSeverity)

	if len(infos) == 0 {
		sb.WriteString("\n")
		sb.WriteString(dimStyle.Render("  No issues at this severity level. Press 1-4 to change filter level."))
		sb.WriteString("\n")
		sb.WriteString(dimStyle.Render("  1=Error, 2=Warning, 3=Note, 4=Chat (all)"))
		sb.WriteString("\n")
		return sb.String()
	}

	// Render visible expert infos
	for i := m.expertScroll; i < len(infos) && i < m.expertScroll+listHeight; i++ {
		info := infos[i]

		// Truncate details
		details := info.Details
		maxDetailsLen := m.width - 65
		if maxDetailsLen < 10 {
			maxDetailsLen = 10
		}
		if len(details) > maxDetailsLen {
			details = details[:maxDetailsLen-3] + "..."
		}

		line := fmt.Sprintf("%-6d %-8s %-10s %-8s %-25s %s",
			info.PacketNum,
			info.Severity.String(),
			info.Group,
			truncateStr(info.Protocol, 8),
			truncateStr(info.Summary, 25),
			details)

		// Style based on severity
		style := normalStyle
		switch info.Severity {
		case expert.SeverityError:
			style = errorStyle
		case expert.SeverityWarning:
			style = warningStyle
		case expert.SeverityNote:
			style = noteStyle
		case expert.SeverityChat:
			style = dimStyle
		}

		sb.WriteString(style.Width(m.width).Render(line))
		sb.WriteString("\n")
	}

	// Fill remaining space
	for i := len(infos) - m.expertScroll; i < listHeight; i++ {
		sb.WriteString("\n")
	}

	// Help hint
	sb.WriteString(dimStyle.Render("  1-4: Filter level | ↑↓: Scroll | Enter: Go to packet | Esc: Back"))
	sb.WriteString("\n")

	return sb.String()
}
