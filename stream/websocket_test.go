package stream

import (
	"encoding/binary"
	"testing"
)

func TestParseWebSocketFrame_Text(t *testing.T) {
	// Build a simple text frame: "hello"
	// FIN=1, opcode=1 (text), mask=0, length=5
	payload := []byte("hello")
	data := make([]byte, 2+len(payload))
	data[0] = 0x81 // FIN=1, opcode=1 (text)
	data[1] = 0x05 // mask=0, length=5
	copy(data[2:], payload)

	frame, consumed := ParseWebSocketFrame(data, false)
	if frame == nil {
		t.Fatal("Expected frame to be parsed")
	}
	if consumed != len(data) {
		t.Errorf("Expected consumed=%d, got %d", len(data), consumed)
	}
	if !frame.FIN {
		t.Error("Expected FIN=true")
	}
	if frame.Opcode != OpcodeText {
		t.Errorf("Expected opcode=TEXT, got %s", frame.Opcode)
	}
	if string(frame.Payload) != "hello" {
		t.Errorf("Expected payload='hello', got '%s'", frame.Payload)
	}
}

func TestParseWebSocketFrame_Binary(t *testing.T) {
	// Build a binary frame with some data
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	data := make([]byte, 2+len(payload))
	data[0] = 0x82 // FIN=1, opcode=2 (binary)
	data[1] = 0x04 // mask=0, length=4
	copy(data[2:], payload)

	frame, consumed := ParseWebSocketFrame(data, false)
	if frame == nil {
		t.Fatal("Expected frame to be parsed")
	}
	if consumed != len(data) {
		t.Errorf("Expected consumed=%d, got %d", len(data), consumed)
	}
	if frame.Opcode != OpcodeBinary {
		t.Errorf("Expected opcode=BINARY, got %s", frame.Opcode)
	}
}

func TestParseWebSocketFrame_Masked(t *testing.T) {
	// Build a masked text frame from client
	payload := []byte("hello")
	maskKey := [4]byte{0x12, 0x34, 0x56, 0x78}

	// Mask the payload
	maskedPayload := make([]byte, len(payload))
	for i := range payload {
		maskedPayload[i] = payload[i] ^ maskKey[i%4]
	}

	data := make([]byte, 2+4+len(payload))
	data[0] = 0x81 // FIN=1, opcode=1 (text)
	data[1] = 0x85 // mask=1, length=5
	copy(data[2:6], maskKey[:])
	copy(data[6:], maskedPayload)

	frame, consumed := ParseWebSocketFrame(data, true)
	if frame == nil {
		t.Fatal("Expected frame to be parsed")
	}
	if consumed != len(data) {
		t.Errorf("Expected consumed=%d, got %d", len(data), consumed)
	}
	if !frame.Masked {
		t.Error("Expected Masked=true")
	}
	// After unmasking, payload should be "hello"
	if string(frame.Payload) != "hello" {
		t.Errorf("Expected unmasked payload='hello', got '%s'", frame.Payload)
	}
}

func TestParseWebSocketFrame_ExtendedLength16(t *testing.T) {
	// Build a frame with 126-byte payload (extended 16-bit length)
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	data := make([]byte, 4+len(payload))
	data[0] = 0x82 // FIN=1, opcode=2 (binary)
	data[1] = 126  // extended length marker
	binary.BigEndian.PutUint16(data[2:4], uint16(len(payload)))
	copy(data[4:], payload)

	frame, consumed := ParseWebSocketFrame(data, false)
	if frame == nil {
		t.Fatal("Expected frame to be parsed")
	}
	if consumed != len(data) {
		t.Errorf("Expected consumed=%d, got %d", len(data), consumed)
	}
	if frame.PayloadLength != uint64(len(payload)) {
		t.Errorf("Expected PayloadLength=%d, got %d", len(payload), frame.PayloadLength)
	}
}

func TestParseWebSocketFrame_ExtendedLength64(t *testing.T) {
	// Build a frame with 64-bit extended length
	payload := make([]byte, 70000)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	data := make([]byte, 10+len(payload))
	data[0] = 0x82 // FIN=1, opcode=2 (binary)
	data[1] = 127  // 64-bit extended length marker
	binary.BigEndian.PutUint64(data[2:10], uint64(len(payload)))
	copy(data[10:], payload)

	frame, consumed := ParseWebSocketFrame(data, false)
	if frame == nil {
		t.Fatal("Expected frame to be parsed")
	}
	if consumed != len(data) {
		t.Errorf("Expected consumed=%d, got %d", len(data), consumed)
	}
	if frame.PayloadLength != uint64(len(payload)) {
		t.Errorf("Expected PayloadLength=%d, got %d", len(payload), frame.PayloadLength)
	}
}

func TestParseWebSocketFrame_Close(t *testing.T) {
	// Build a close frame with code 1000 (normal closure)
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, 1000)

	data := make([]byte, 2+len(payload))
	data[0] = 0x88 // FIN=1, opcode=8 (close)
	data[1] = 0x02 // length=2
	copy(data[2:], payload)

	frame, consumed := ParseWebSocketFrame(data, false)
	if frame == nil {
		t.Fatal("Expected frame to be parsed")
	}
	if consumed != len(data) {
		t.Errorf("Expected consumed=%d, got %d", len(data), consumed)
	}
	if frame.Opcode != OpcodeClose {
		t.Errorf("Expected opcode=CLOSE, got %s", frame.Opcode)
	}

	code, reason := frame.GetCloseCode()
	if code != 1000 {
		t.Errorf("Expected close code=1000, got %d", code)
	}
	if reason != "" {
		t.Errorf("Expected empty reason, got '%s'", reason)
	}
}

func TestParseWebSocketFrame_CloseWithReason(t *testing.T) {
	// Build a close frame with code 1001 and reason
	reasonStr := "Going Away"
	payload := make([]byte, 2+len(reasonStr))
	binary.BigEndian.PutUint16(payload, 1001)
	copy(payload[2:], reasonStr)

	data := make([]byte, 2+len(payload))
	data[0] = 0x88 // FIN=1, opcode=8 (close)
	data[1] = byte(len(payload))
	copy(data[2:], payload)

	frame, _ := ParseWebSocketFrame(data, false)
	if frame == nil {
		t.Fatal("Expected frame to be parsed")
	}

	code, reason := frame.GetCloseCode()
	if code != 1001 {
		t.Errorf("Expected close code=1001, got %d", code)
	}
	if reason != reasonStr {
		t.Errorf("Expected reason='%s', got '%s'", reasonStr, reason)
	}
}

func TestParseWebSocketFrame_Ping(t *testing.T) {
	data := []byte{0x89, 0x00} // PING with no payload

	frame, consumed := ParseWebSocketFrame(data, false)
	if frame == nil {
		t.Fatal("Expected frame to be parsed")
	}
	if consumed != len(data) {
		t.Errorf("Expected consumed=%d, got %d", len(data), consumed)
	}
	if frame.Opcode != OpcodePing {
		t.Errorf("Expected opcode=PING, got %s", frame.Opcode)
	}
}

func TestParseWebSocketFrame_Pong(t *testing.T) {
	data := []byte{0x8A, 0x00} // PONG with no payload

	frame, _ := ParseWebSocketFrame(data, false)
	if frame == nil {
		t.Fatal("Expected frame to be parsed")
	}
	if frame.Opcode != OpcodePong {
		t.Errorf("Expected opcode=PONG, got %s", frame.Opcode)
	}
}

func TestParseWebSocketFrame_Continuation(t *testing.T) {
	// First fragment (FIN=0, opcode=TEXT)
	data1 := []byte{0x01, 0x03, 'H', 'e', 'l'} // FIN=0, TEXT
	frame1, _ := ParseWebSocketFrame(data1, false)
	if frame1 == nil {
		t.Fatal("Expected first fragment to be parsed")
	}
	if frame1.FIN {
		t.Error("Expected FIN=false for first fragment")
	}
	if frame1.Opcode != OpcodeText {
		t.Errorf("Expected TEXT opcode, got %s", frame1.Opcode)
	}

	// Continuation (FIN=1, opcode=CONTINUATION)
	data2 := []byte{0x80, 0x02, 'l', 'o'} // FIN=1, CONTINUATION
	frame2, _ := ParseWebSocketFrame(data2, false)
	if frame2 == nil {
		t.Fatal("Expected continuation to be parsed")
	}
	if !frame2.FIN {
		t.Error("Expected FIN=true for last fragment")
	}
	if frame2.Opcode != OpcodeContinuation {
		t.Errorf("Expected CONTINUATION opcode, got %s", frame2.Opcode)
	}
}

func TestParseWebSocketFrame_Incomplete(t *testing.T) {
	// Incomplete frame (missing payload)
	data := []byte{0x81, 0x05, 'H', 'e'} // Says length=5 but only has 2 bytes

	frame, consumed := ParseWebSocketFrame(data, false)
	if frame != nil {
		t.Error("Expected nil frame for incomplete data")
	}
	if consumed != 0 {
		t.Errorf("Expected consumed=0, got %d", consumed)
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name: "valid upgrade request",
			data: []byte("GET /chat HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
				"Sec-WebSocket-Version: 13\r\n\r\n"),
			expected: true,
		},
		{
			name:     "not upgrade request",
			data:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: false,
		},
		{
			name:     "missing key",
			data:     []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"),
			expected: false,
		},
		{
			name:     "too short",
			data:     []byte("GET /"),
			expected: false,
		},
		{
			name:     "POST request",
			data:     []byte("POST /chat HTTP/1.1\r\nUpgrade: websocket\r\n"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsWebSocketUpgrade(tt.data)
			if result != tt.expected {
				t.Errorf("IsWebSocketUpgrade() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsWebSocketResponse(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name: "valid 101 response",
			data: []byte("HTTP/1.1 101 Switching Protocols\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"),
			expected: true,
		},
		{
			name:     "200 response",
			data:     []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"),
			expected: false,
		},
		{
			name:     "too short",
			data:     []byte("HTTP/1.1 101"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsWebSocketResponse(tt.data)
			if result != tt.expected {
				t.Errorf("IsWebSocketResponse() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestWebSocketHandshake_ValidateAcceptKey(t *testing.T) {
	// Test vector from RFC 6455
	h := &WebSocketHandshake{
		SecWebSocketKey:    "dGhlIHNhbXBsZSBub25jZQ==",
		SecWebSocketAccept: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
	}

	if !h.ValidateAcceptKey() {
		t.Error("Expected valid accept key")
	}

	// Test with wrong accept
	h.SecWebSocketAccept = "wrongvalue"
	if h.ValidateAcceptKey() {
		t.Error("Expected invalid accept key")
	}
}

func TestWebSocketConnection_AddFrame(t *testing.T) {
	conn := NewWebSocketConnection()

	// Add a text frame from client
	frame1 := &WebSocketFrame{
		FIN:           true,
		Opcode:        OpcodeText,
		Masked:        true,
		PayloadLength: 5,
		Payload:       []byte("hello"),
		FromClient:    true,
		TotalLength:   7,
	}
	conn.AddFrame(frame1)

	if conn.ClientFrames != 1 {
		t.Errorf("Expected ClientFrames=1, got %d", conn.ClientFrames)
	}
	if conn.ClientBytes != 7 {
		t.Errorf("Expected ClientBytes=7, got %d", conn.ClientBytes)
	}
	if len(conn.Messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(conn.Messages))
	}
	if conn.TextMessages != 1 {
		t.Errorf("Expected TextMessages=1, got %d", conn.TextMessages)
	}

	// Add a response from server
	frame2 := &WebSocketFrame{
		FIN:           true,
		Opcode:        OpcodeText,
		Masked:        false,
		PayloadLength: 5,
		Payload:       []byte("world"),
		FromClient:    false,
		TotalLength:   7,
	}
	conn.AddFrame(frame2)

	if conn.ServerFrames != 1 {
		t.Errorf("Expected ServerFrames=1, got %d", conn.ServerFrames)
	}
	if len(conn.Messages) != 2 {
		t.Errorf("Expected 2 messages, got %d", len(conn.Messages))
	}
}

func TestWebSocketConnection_Fragmentation(t *testing.T) {
	conn := NewWebSocketConnection()

	// Fragment 1: start of text message
	frame1 := &WebSocketFrame{
		FIN:           false,
		Opcode:        OpcodeText,
		Masked:        false,
		PayloadLength: 3,
		Payload:       []byte("Hel"),
		FromClient:    false,
		TotalLength:   5,
	}
	conn.AddFrame(frame1)

	// Should not have complete message yet
	if len(conn.Messages) != 0 {
		t.Errorf("Expected 0 messages, got %d", len(conn.Messages))
	}

	// Fragment 2: continuation and final
	frame2 := &WebSocketFrame{
		FIN:           true,
		Opcode:        OpcodeContinuation,
		Masked:        false,
		PayloadLength: 2,
		Payload:       []byte("lo"),
		FromClient:    false,
		TotalLength:   4,
	}
	conn.AddFrame(frame2)

	// Now should have complete message
	if len(conn.Messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(conn.Messages))
	}
	if string(conn.Messages[0].Payload) != "Hello" {
		t.Errorf("Expected message='Hello', got '%s'", conn.Messages[0].Payload)
	}
	if len(conn.Messages[0].Frames) != 2 {
		t.Errorf("Expected 2 frames in message, got %d", len(conn.Messages[0].Frames))
	}
}

func TestWebSocketConnection_ControlFrames(t *testing.T) {
	conn := NewWebSocketConnection()

	// Ping frame
	pingFrame := &WebSocketFrame{
		FIN:         true,
		Opcode:      OpcodePing,
		Payload:     []byte{},
		FromClient:  false,
		TotalLength: 2,
	}
	conn.AddFrame(pingFrame)

	if conn.PingCount != 1 {
		t.Errorf("Expected PingCount=1, got %d", conn.PingCount)
	}

	// Pong frame
	pongFrame := &WebSocketFrame{
		FIN:         true,
		Opcode:      OpcodePong,
		Payload:     []byte{},
		FromClient:  true,
		TotalLength: 2,
	}
	conn.AddFrame(pongFrame)

	if conn.PongCount != 1 {
		t.Errorf("Expected PongCount=1, got %d", conn.PongCount)
	}

	// Close frame
	closePayload := make([]byte, 2)
	binary.BigEndian.PutUint16(closePayload, 1000)
	closeFrame := &WebSocketFrame{
		FIN:         true,
		Opcode:      OpcodeClose,
		Payload:     closePayload,
		FromClient:  true,
		TotalLength: 4,
	}
	conn.AddFrame(closeFrame)

	if !conn.Closed {
		t.Error("Expected connection to be marked as closed")
	}
	if conn.CloseCode != 1000 {
		t.Errorf("Expected CloseCode=1000, got %d", conn.CloseCode)
	}
}

func TestGetWebSocketCloseReason(t *testing.T) {
	tests := []struct {
		code     uint16
		expected string
	}{
		{1000, "Normal Closure"},
		{1001, "Going Away"},
		{1002, "Protocol Error"},
		{1003, "Unsupported Data"},
		{1006, "Abnormal Closure"},
		{1011, "Internal Server Error"},
		{3000, "Registered (IANA)"},
		{4000, "Private Use"},
		{9999, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := GetWebSocketCloseReason(tt.code)
			if result != tt.expected {
				t.Errorf("GetWebSocketCloseReason(%d) = %s, expected %s", tt.code, result, tt.expected)
			}
		})
	}
}

func TestWebSocketOpcode_String(t *testing.T) {
	tests := []struct {
		opcode   WebSocketOpcode
		expected string
	}{
		{OpcodeContinuation, "CONTINUATION"},
		{OpcodeText, "TEXT"},
		{OpcodeBinary, "BINARY"},
		{OpcodeClose, "CLOSE"},
		{OpcodePing, "PING"},
		{OpcodePong, "PONG"},
		{WebSocketOpcode(0x3), "RESERVED(0x3)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.opcode.String() != tt.expected {
				t.Errorf("Opcode.String() = %s, expected %s", tt.opcode.String(), tt.expected)
			}
		})
	}
}

func TestWebSocketOpcode_IsControl(t *testing.T) {
	tests := []struct {
		opcode    WebSocketOpcode
		isControl bool
	}{
		{OpcodeContinuation, false},
		{OpcodeText, false},
		{OpcodeBinary, false},
		{OpcodeClose, true},
		{OpcodePing, true},
		{OpcodePong, true},
	}

	for _, tt := range tests {
		t.Run(tt.opcode.String(), func(t *testing.T) {
			if tt.opcode.IsControl() != tt.isControl {
				t.Errorf("%s.IsControl() = %v, expected %v", tt.opcode, tt.opcode.IsControl(), tt.isControl)
			}
		})
	}
}
