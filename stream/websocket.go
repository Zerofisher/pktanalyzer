package stream

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// WebSocket constants from RFC 6455
const (
	// Opcodes
	OpcodeContinuation = 0x0
	OpcodeText         = 0x1
	OpcodeBinary       = 0x2
	// 0x3-0x7 reserved for non-control frames
	OpcodeClose = 0x8
	OpcodePing  = 0x9
	OpcodePong  = 0xA
	// 0xB-0xF reserved for control frames

	// Frame header sizes
	MinFrameHeaderSize = 2
	MaxFrameHeaderSize = 14 // 2 + 8 (extended payload) + 4 (mask key)

	// Magic GUID for WebSocket handshake
	WebSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

// WebSocketOpcode represents a WebSocket frame opcode
type WebSocketOpcode uint8

func (o WebSocketOpcode) String() string {
	switch o {
	case OpcodeContinuation:
		return "CONTINUATION"
	case OpcodeText:
		return "TEXT"
	case OpcodeBinary:
		return "BINARY"
	case OpcodeClose:
		return "CLOSE"
	case OpcodePing:
		return "PING"
	case OpcodePong:
		return "PONG"
	default:
		return fmt.Sprintf("RESERVED(0x%x)", uint8(o))
	}
}

// IsControl returns true if this is a control frame opcode
func (o WebSocketOpcode) IsControl() bool {
	return o >= OpcodeClose
}

// WebSocketFrame represents a WebSocket frame (RFC 6455 Section 5.2)
type WebSocketFrame struct {
	// Header fields
	FIN    bool            // Final fragment flag
	RSV1   bool            // Reserved bit 1 (for extensions)
	RSV2   bool            // Reserved bit 2
	RSV3   bool            // Reserved bit 3
	Opcode WebSocketOpcode // Operation code

	// Payload
	Masked        bool    // Is payload masked?
	MaskKey       [4]byte // Masking key (client->server)
	PayloadLength uint64  // Payload length
	Payload       []byte  // Actual payload (unmasked)

	// Metadata
	Timestamp    time.Time
	FromClient   bool
	FrameNumber  int // Frame index in the stream
	HeaderLength int // Length of header in bytes
	TotalLength  int // Total frame length including header
}

// Summary returns a one-line summary of the frame
func (f *WebSocketFrame) Summary() string {
	direction := "S→C"
	if f.FromClient {
		direction = "C→S"
	}

	finStr := ""
	if !f.FIN {
		finStr = " (fragment)"
	}

	maskedStr := ""
	if f.Masked {
		maskedStr = " [masked]"
	}

	return fmt.Sprintf("[%d] %s %s len=%d%s%s",
		f.FrameNumber, direction, f.Opcode, f.PayloadLength, maskedStr, finStr)
}

// GetPayloadText returns payload as text (for TEXT frames)
func (f *WebSocketFrame) GetPayloadText() string {
	if f.Opcode == OpcodeText {
		return string(f.Payload)
	}
	return ""
}

// GetCloseCode returns close status code and reason (for CLOSE frames)
func (f *WebSocketFrame) GetCloseCode() (uint16, string) {
	if f.Opcode != OpcodeClose || len(f.Payload) < 2 {
		return 0, ""
	}
	code := binary.BigEndian.Uint16(f.Payload[:2])
	reason := ""
	if len(f.Payload) > 2 {
		reason = string(f.Payload[2:])
	}
	return code, reason
}

// WebSocketHandshake represents the WebSocket upgrade handshake
type WebSocketHandshake struct {
	// Request fields
	RequestURI          string
	Host                string
	Origin              string
	SecWebSocketKey     string
	SecWebSocketVersion string
	Subprotocols        []string // Sec-WebSocket-Protocol
	Extensions          []string // Sec-WebSocket-Extensions

	// Response fields
	StatusCode             int
	SecWebSocketAccept     string
	SelectedSubprotocol    string
	SelectedExtensions     []string
	PermessageDeflate      bool // Extension: permessage-deflate

	// Validation
	IsValid bool
}

// ValidateAcceptKey validates Sec-WebSocket-Accept against Sec-WebSocket-Key
func (h *WebSocketHandshake) ValidateAcceptKey() bool {
	if h.SecWebSocketKey == "" || h.SecWebSocketAccept == "" {
		return false
	}
	// Calculate expected accept value: base64(sha1(key + GUID))
	hash := sha1.Sum([]byte(h.SecWebSocketKey + WebSocketGUID))
	expected := base64.StdEncoding.EncodeToString(hash[:])
	return h.SecWebSocketAccept == expected
}

// WebSocketMessage represents a complete WebSocket message (may span multiple frames)
type WebSocketMessage struct {
	Opcode    WebSocketOpcode
	Payload   []byte
	Frames    []*WebSocketFrame
	Timestamp time.Time
	Complete  bool
}

// WebSocketConnection represents a WebSocket connection
type WebSocketConnection struct {
	Handshake *WebSocketHandshake
	Frames    []*WebSocketFrame
	Messages  []*WebSocketMessage

	// State
	ClientConnected bool
	ServerConnected bool
	Closed          bool
	CloseCode       uint16
	CloseReason     string

	// Statistics
	ClientFrames   int
	ServerFrames   int
	ClientBytes    int64
	ServerBytes    int64
	TextMessages   int
	BinaryMessages int
	PingCount      int
	PongCount      int

	// Fragment handling
	pendingMessage *WebSocketMessage
}

// NewWebSocketConnection creates a new WebSocket connection
func NewWebSocketConnection() *WebSocketConnection {
	return &WebSocketConnection{
		Frames:   make([]*WebSocketFrame, 0),
		Messages: make([]*WebSocketMessage, 0),
	}
}

// AddFrame adds a frame to the connection
func (c *WebSocketConnection) AddFrame(frame *WebSocketFrame) {
	frame.FrameNumber = len(c.Frames)
	c.Frames = append(c.Frames, frame)

	// Update statistics
	if frame.FromClient {
		c.ClientFrames++
		c.ClientBytes += int64(frame.TotalLength)
	} else {
		c.ServerFrames++
		c.ServerBytes += int64(frame.TotalLength)
	}

	// Handle frame types
	switch frame.Opcode {
	case OpcodePing:
		c.PingCount++
	case OpcodePong:
		c.PongCount++
	case OpcodeClose:
		c.Closed = true
		c.CloseCode, c.CloseReason = frame.GetCloseCode()
	}

	// Handle message assembly
	c.handleFrameForMessage(frame)
}

// handleFrameForMessage handles fragmented message assembly
func (c *WebSocketConnection) handleFrameForMessage(frame *WebSocketFrame) {
	// Control frames can be interspersed with fragmented messages
	if frame.Opcode.IsControl() {
		return
	}

	if frame.Opcode != OpcodeContinuation {
		// New message starts
		c.pendingMessage = &WebSocketMessage{
			Opcode:    frame.Opcode,
			Payload:   make([]byte, 0, frame.PayloadLength),
			Frames:    make([]*WebSocketFrame, 0),
			Timestamp: frame.Timestamp,
		}
	}

	if c.pendingMessage != nil {
		c.pendingMessage.Payload = append(c.pendingMessage.Payload, frame.Payload...)
		c.pendingMessage.Frames = append(c.pendingMessage.Frames, frame)

		if frame.FIN {
			c.pendingMessage.Complete = true
			c.Messages = append(c.Messages, c.pendingMessage)

			// Update message stats
			if c.pendingMessage.Opcode == OpcodeText {
				c.TextMessages++
			} else if c.pendingMessage.Opcode == OpcodeBinary {
				c.BinaryMessages++
			}

			c.pendingMessage = nil
		}
	}
}

// Summary returns a summary of the WebSocket connection
func (c *WebSocketConnection) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Frames: %d (Client: %d, Server: %d)\n",
		len(c.Frames), c.ClientFrames, c.ServerFrames))
	sb.WriteString(fmt.Sprintf("Messages: %d (Text: %d, Binary: %d)\n",
		len(c.Messages), c.TextMessages, c.BinaryMessages))
	sb.WriteString(fmt.Sprintf("Bytes: Client→Server: %d, Server→Client: %d\n",
		c.ClientBytes, c.ServerBytes))
	if c.PingCount > 0 || c.PongCount > 0 {
		sb.WriteString(fmt.Sprintf("Ping/Pong: %d/%d\n", c.PingCount, c.PongCount))
	}
	if c.Closed {
		sb.WriteString(fmt.Sprintf("Closed: code=%d reason=%q\n", c.CloseCode, c.CloseReason))
	}
	return sb.String()
}

// WebSocketParser parses WebSocket frames from TCP stream data
type WebSocketParser struct {
	Connection *WebSocketConnection

	// Internal state
	clientOffset int
	serverOffset int
}

// NewWebSocketParser creates a new WebSocket parser
func NewWebSocketParser() *WebSocketParser {
	return &WebSocketParser{
		Connection: NewWebSocketConnection(),
	}
}

// ParseHandshake detects and parses WebSocket upgrade handshake from HTTP
func (p *WebSocketParser) ParseHandshake(stream *TCPStream) bool {
	clientData := stream.GetClientData()
	serverData := stream.GetServerData()

	if len(clientData) == 0 || len(serverData) == 0 {
		return false
	}

	handshake := &WebSocketHandshake{}

	// Parse client request (Upgrade: websocket)
	if !p.parseHandshakeRequest(clientData, handshake) {
		return false
	}

	// Parse server response (101 Switching Protocols)
	if !p.parseHandshakeResponse(serverData, handshake) {
		return false
	}

	// Validate the handshake
	handshake.IsValid = handshake.ValidateAcceptKey()

	p.Connection.Handshake = handshake
	p.Connection.ClientConnected = true
	p.Connection.ServerConnected = handshake.StatusCode == 101

	return handshake.IsValid
}

// parseHandshakeRequest parses the client's upgrade request
func (p *WebSocketParser) parseHandshakeRequest(data []byte, h *WebSocketHandshake) bool {
	// Find end of HTTP headers
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return false
	}

	lines := bytes.Split(data[:headerEnd], []byte("\r\n"))
	if len(lines) == 0 {
		return false
	}

	// Parse request line: GET /path HTTP/1.1
	firstLine := string(lines[0])
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) < 2 || parts[0] != "GET" {
		return false
	}
	h.RequestURI = parts[1]

	// Parse headers
	upgradeFound := false
	connectionUpgrade := false

	for i := 1; i < len(lines); i++ {
		line := string(lines[i])
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}

		name := strings.TrimSpace(strings.ToLower(line[:colonIdx]))
		value := strings.TrimSpace(line[colonIdx+1:])

		switch name {
		case "host":
			h.Host = value
		case "origin":
			h.Origin = value
		case "upgrade":
			if strings.ToLower(value) == "websocket" {
				upgradeFound = true
			}
		case "connection":
			if strings.Contains(strings.ToLower(value), "upgrade") {
				connectionUpgrade = true
			}
		case "sec-websocket-key":
			h.SecWebSocketKey = value
		case "sec-websocket-version":
			h.SecWebSocketVersion = value
		case "sec-websocket-protocol":
			h.Subprotocols = parseCommaSeparated(value)
		case "sec-websocket-extensions":
			h.Extensions = parseCommaSeparated(value)
		}
	}

	// Remember header length for data offset
	p.clientOffset = headerEnd + 4

	return upgradeFound && connectionUpgrade && h.SecWebSocketKey != ""
}

// parseHandshakeResponse parses the server's upgrade response
func (p *WebSocketParser) parseHandshakeResponse(data []byte, h *WebSocketHandshake) bool {
	// Find end of HTTP headers
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return false
	}

	lines := bytes.Split(data[:headerEnd], []byte("\r\n"))
	if len(lines) == 0 {
		return false
	}

	// Parse status line: HTTP/1.1 101 Switching Protocols
	firstLine := string(lines[0])
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) < 2 {
		return false
	}

	fmt.Sscanf(parts[1], "%d", &h.StatusCode)
	if h.StatusCode != 101 {
		return false
	}

	// Parse headers
	for i := 1; i < len(lines); i++ {
		line := string(lines[i])
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}

		name := strings.TrimSpace(strings.ToLower(line[:colonIdx]))
		value := strings.TrimSpace(line[colonIdx+1:])

		switch name {
		case "sec-websocket-accept":
			h.SecWebSocketAccept = value
		case "sec-websocket-protocol":
			h.SelectedSubprotocol = value
		case "sec-websocket-extensions":
			h.SelectedExtensions = parseCommaSeparated(value)
			for _, ext := range h.SelectedExtensions {
				if strings.HasPrefix(ext, "permessage-deflate") {
					h.PermessageDeflate = true
				}
			}
		}
	}

	// Remember header length for data offset
	p.serverOffset = headerEnd + 4

	return h.SecWebSocketAccept != ""
}

// parseCommaSeparated parses comma-separated header values
func parseCommaSeparated(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// ParseFrames parses WebSocket frames from the TCP stream data
func (p *WebSocketParser) ParseFrames(stream *TCPStream) error {
	clientData := stream.GetClientData()
	serverData := stream.GetServerData()

	// Parse frames from client (after handshake)
	if p.clientOffset < len(clientData) {
		p.parseFramesFromData(clientData[p.clientOffset:], true)
	}

	// Parse frames from server (after handshake)
	if p.serverOffset < len(serverData) {
		p.parseFramesFromData(serverData[p.serverOffset:], false)
	}

	return nil
}

// parseFramesFromData parses WebSocket frames from raw data
func (p *WebSocketParser) parseFramesFromData(data []byte, fromClient bool) {
	offset := 0

	for offset < len(data) {
		frame, consumed := ParseWebSocketFrame(data[offset:], fromClient)
		if frame == nil || consumed == 0 {
			break
		}

		p.Connection.AddFrame(frame)
		offset += consumed
	}
}

// ParseStream is the main entry point - parses handshake and frames
func (p *WebSocketParser) ParseStream(stream *TCPStream) error {
	// First, try to parse handshake
	if !p.ParseHandshake(stream) {
		return fmt.Errorf("no valid WebSocket handshake found")
	}

	// Then parse frames
	return p.ParseFrames(stream)
}

// ParseWebSocketFrame parses a single WebSocket frame from data
// Returns the frame and number of bytes consumed, or nil if incomplete
func ParseWebSocketFrame(data []byte, fromClient bool) (*WebSocketFrame, int) {
	if len(data) < MinFrameHeaderSize {
		return nil, 0
	}

	frame := &WebSocketFrame{
		FromClient: fromClient,
		Timestamp:  time.Now(),
	}

	offset := 0

	// Byte 0: FIN, RSV1-3, Opcode
	b0 := data[offset]
	frame.FIN = (b0 & 0x80) != 0
	frame.RSV1 = (b0 & 0x40) != 0
	frame.RSV2 = (b0 & 0x20) != 0
	frame.RSV3 = (b0 & 0x10) != 0
	frame.Opcode = WebSocketOpcode(b0 & 0x0F)
	offset++

	// Byte 1: Mask flag, Payload length
	b1 := data[offset]
	frame.Masked = (b1 & 0x80) != 0
	payloadLen := uint64(b1 & 0x7F)
	offset++

	// Extended payload length
	if payloadLen == 126 {
		if len(data) < offset+2 {
			return nil, 0
		}
		payloadLen = uint64(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
	} else if payloadLen == 127 {
		if len(data) < offset+8 {
			return nil, 0
		}
		payloadLen = binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
	}
	frame.PayloadLength = payloadLen

	// Masking key (if masked)
	if frame.Masked {
		if len(data) < offset+4 {
			return nil, 0
		}
		copy(frame.MaskKey[:], data[offset:offset+4])
		offset += 4
	}

	frame.HeaderLength = offset

	// Check if we have complete payload
	if len(data) < offset+int(payloadLen) {
		return nil, 0
	}

	// Extract and unmask payload
	frame.Payload = make([]byte, payloadLen)
	copy(frame.Payload, data[offset:offset+int(payloadLen)])

	if frame.Masked {
		unmaskPayload(frame.Payload, frame.MaskKey)
	}

	frame.TotalLength = offset + int(payloadLen)

	return frame, frame.TotalLength
}

// unmaskPayload applies XOR masking to payload
func unmaskPayload(payload []byte, maskKey [4]byte) {
	for i := range payload {
		payload[i] ^= maskKey[i%4]
	}
}

// IsWebSocketUpgrade checks if the data looks like a WebSocket upgrade request
func IsWebSocketUpgrade(data []byte) bool {
	if len(data) < 50 { // Minimum viable upgrade request size
		return false
	}

	// Check for GET request with Upgrade header
	if !bytes.HasPrefix(data, []byte("GET ")) {
		return false
	}

	// Look for key headers (case-insensitive search)
	lowerData := bytes.ToLower(data)

	hasUpgrade := bytes.Contains(lowerData, []byte("upgrade: websocket"))
	hasConnection := bytes.Contains(lowerData, []byte("connection:")) &&
		bytes.Contains(lowerData, []byte("upgrade"))
	hasKey := bytes.Contains(lowerData, []byte("sec-websocket-key:"))

	return hasUpgrade && hasConnection && hasKey
}

// IsWebSocketResponse checks if the data looks like a WebSocket upgrade response
func IsWebSocketResponse(data []byte) bool {
	if len(data) < 30 {
		return false
	}

	// Check for 101 Switching Protocols
	checkLen := 50
	if len(data) < checkLen {
		checkLen = len(data)
	}
	if !bytes.Contains(data[:checkLen], []byte("101")) {
		return false
	}

	// Look for accept header
	lowerData := bytes.ToLower(data)
	return bytes.Contains(lowerData, []byte("sec-websocket-accept:"))
}

// GetWebSocketCloseReason returns a human-readable close reason
func GetWebSocketCloseReason(code uint16) string {
	switch code {
	case 1000:
		return "Normal Closure"
	case 1001:
		return "Going Away"
	case 1002:
		return "Protocol Error"
	case 1003:
		return "Unsupported Data"
	case 1005:
		return "No Status Received"
	case 1006:
		return "Abnormal Closure"
	case 1007:
		return "Invalid Payload Data"
	case 1008:
		return "Policy Violation"
	case 1009:
		return "Message Too Big"
	case 1010:
		return "Mandatory Extension"
	case 1011:
		return "Internal Server Error"
	case 1015:
		return "TLS Handshake Failure"
	default:
		if code >= 3000 && code < 4000 {
			return "Registered (IANA)"
		}
		if code >= 4000 && code < 5000 {
			return "Private Use"
		}
		return "Unknown"
	}
}
