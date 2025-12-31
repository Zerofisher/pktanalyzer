package stream

import (
	"testing"
)

func TestHTTP2FrameParsing(t *testing.T) {
	// HTTP/2 SETTINGS frame (no ACK)
	// Length: 18 (0x000012), Type: SETTINGS (0x04), Flags: 0x00, Stream ID: 0
	settingsFrame := []byte{
		0x00, 0x00, 0x12, // Length: 18
		0x04,             // Type: SETTINGS
		0x00,             // Flags
		0x00, 0x00, 0x00, 0x00, // Stream ID: 0
		// Settings (3 settings, 6 bytes each)
		0x00, 0x03, 0x00, 0x00, 0x00, 0x64, // MAX_CONCURRENT_STREAMS: 100
		0x00, 0x04, 0x00, 0x01, 0x00, 0x00, // INITIAL_WINDOW_SIZE: 65536
		0x00, 0x05, 0x00, 0x00, 0x40, 0x00, // MAX_FRAME_SIZE: 16384
	}

	frame, consumed, err := ParseHTTP2Frame(settingsFrame)
	if err != nil {
		t.Fatalf("Failed to parse SETTINGS frame: %v", err)
	}

	if consumed != len(settingsFrame) {
		t.Errorf("Expected consumed %d, got %d", len(settingsFrame), consumed)
	}

	if frame.Type != HTTP2FrameSettings {
		t.Errorf("Expected type SETTINGS (%d), got %d", HTTP2FrameSettings, frame.Type)
	}

	if frame.StreamID != 0 {
		t.Errorf("Expected stream ID 0, got %d", frame.StreamID)
	}

	if frame.Length != 18 {
		t.Errorf("Expected length 18, got %d", frame.Length)
	}

	// Parse settings payload
	settings, err := frame.ParseSettingsPayload()
	if err != nil {
		t.Fatalf("Failed to parse settings payload: %v", err)
	}

	if len(settings.Settings) != 3 {
		t.Errorf("Expected 3 settings, got %d", len(settings.Settings))
	}

	t.Logf("SETTINGS frame: %s", frame.Summary())
}

func TestHTTP2HeadersFrame(t *testing.T) {
	// HTTP/2 HEADERS frame
	// Length: 5, Type: HEADERS (0x01), Flags: END_HEADERS (0x04), Stream ID: 1
	headersFrame := []byte{
		0x00, 0x00, 0x05, // Length: 5
		0x01,             // Type: HEADERS
		0x04,             // Flags: END_HEADERS
		0x00, 0x00, 0x00, 0x01, // Stream ID: 1
		// Header block (minimal)
		0x82, 0x84, 0x86, 0x41, 0x8a, // Compressed headers
	}

	frame, consumed, err := ParseHTTP2Frame(headersFrame)
	if err != nil {
		t.Fatalf("Failed to parse HEADERS frame: %v", err)
	}

	if consumed != len(headersFrame) {
		t.Errorf("Expected consumed %d, got %d", len(headersFrame), consumed)
	}

	if frame.Type != HTTP2FrameHeaders {
		t.Errorf("Expected type HEADERS (%d), got %d", HTTP2FrameHeaders, frame.Type)
	}

	if frame.StreamID != 1 {
		t.Errorf("Expected stream ID 1, got %d", frame.StreamID)
	}

	if !frame.IsEndHeaders() {
		t.Error("Expected END_HEADERS flag to be set")
	}

	t.Logf("HEADERS frame: %s", frame.Summary())
}

func TestHTTP2DataFrame(t *testing.T) {
	// HTTP/2 DATA frame
	// Length: 11, Type: DATA (0x00), Flags: END_STREAM (0x01), Stream ID: 1
	dataFrame := []byte{
		0x00, 0x00, 0x0b, // Length: 11
		0x00,             // Type: DATA
		0x01,             // Flags: END_STREAM
		0x00, 0x00, 0x00, 0x01, // Stream ID: 1
		// Payload: "Hello World"
		0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
	}

	frame, consumed, err := ParseHTTP2Frame(dataFrame)
	if err != nil {
		t.Fatalf("Failed to parse DATA frame: %v", err)
	}

	if consumed != len(dataFrame) {
		t.Errorf("Expected consumed %d, got %d", len(dataFrame), consumed)
	}

	if frame.Type != HTTP2FrameData {
		t.Errorf("Expected type DATA (%d), got %d", HTTP2FrameData, frame.Type)
	}

	if frame.StreamID != 1 {
		t.Errorf("Expected stream ID 1, got %d", frame.StreamID)
	}

	if !frame.IsEndStream() {
		t.Error("Expected END_STREAM flag to be set")
	}

	// Parse data payload
	data, err := frame.ParseDataPayload()
	if err != nil {
		t.Fatalf("Failed to parse data payload: %v", err)
	}

	if string(data.Data) != "Hello World" {
		t.Errorf("Expected 'Hello World', got '%s'", string(data.Data))
	}

	t.Logf("DATA frame: %s", frame.Summary())
}

func TestHTTP2Preface(t *testing.T) {
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

	if !IsHTTP2Preface(preface) {
		t.Error("Should recognize HTTP/2 preface")
	}

	notPreface := []byte("GET / HTTP/1.1\r\n")
	if IsHTTP2Preface(notPreface) {
		t.Error("Should not recognize HTTP/1.1 as HTTP/2 preface")
	}
}

func TestHTTP2GoAwayFrame(t *testing.T) {
	// GOAWAY frame: Last Stream ID: 7, Error: NO_ERROR
	goawayFrame := []byte{
		0x00, 0x00, 0x08, // Length: 8
		0x07,             // Type: GOAWAY
		0x00,             // Flags
		0x00, 0x00, 0x00, 0x00, // Stream ID: 0
		0x00, 0x00, 0x00, 0x07, // Last Stream ID: 7
		0x00, 0x00, 0x00, 0x00, // Error: NO_ERROR
	}

	frame, _, err := ParseHTTP2Frame(goawayFrame)
	if err != nil {
		t.Fatalf("Failed to parse GOAWAY frame: %v", err)
	}

	if frame.Type != HTTP2FrameGoAway {
		t.Errorf("Expected GOAWAY frame type")
	}

	payload, err := frame.ParseGoAwayPayload()
	if err != nil {
		t.Fatalf("Failed to parse GOAWAY payload: %v", err)
	}

	if payload.LastStreamID != 7 {
		t.Errorf("Expected last stream ID 7, got %d", payload.LastStreamID)
	}

	if payload.ErrorCode != HTTP2ErrNoError {
		t.Errorf("Expected NO_ERROR, got %d", payload.ErrorCode)
	}

	t.Logf("GOAWAY frame: %s", frame.Summary())
}

func TestHTTP2WindowUpdateFrame(t *testing.T) {
	// WINDOW_UPDATE frame: Stream 1, increment 65535
	windowFrame := []byte{
		0x00, 0x00, 0x04, // Length: 4
		0x08,             // Type: WINDOW_UPDATE
		0x00,             // Flags
		0x00, 0x00, 0x00, 0x01, // Stream ID: 1
		0x00, 0x00, 0xff, 0xff, // Window Size Increment: 65535
	}

	frame, _, err := ParseHTTP2Frame(windowFrame)
	if err != nil {
		t.Fatalf("Failed to parse WINDOW_UPDATE frame: %v", err)
	}

	payload, err := frame.ParseWindowUpdatePayload()
	if err != nil {
		t.Fatalf("Failed to parse WINDOW_UPDATE payload: %v", err)
	}

	if payload.WindowSizeIncrement != 65535 {
		t.Errorf("Expected increment 65535, got %d", payload.WindowSizeIncrement)
	}

	t.Logf("WINDOW_UPDATE frame: %s", frame.Summary())
}

func TestHTTP2PingFrame(t *testing.T) {
	// PING frame with ACK
	pingFrame := []byte{
		0x00, 0x00, 0x08, // Length: 8
		0x06,             // Type: PING
		0x01,             // Flags: ACK
		0x00, 0x00, 0x00, 0x00, // Stream ID: 0
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Opaque data
	}

	frame, _, err := ParseHTTP2Frame(pingFrame)
	if err != nil {
		t.Fatalf("Failed to parse PING frame: %v", err)
	}

	if frame.Type != HTTP2FramePing {
		t.Errorf("Expected PING frame type")
	}

	if frame.Flags&HTTP2FlagPingAck == 0 {
		t.Error("Expected ACK flag to be set")
	}

	t.Logf("PING frame: %s", frame.Summary())
}

func TestMultipleFrames(t *testing.T) {
	// Two frames concatenated
	data := []byte{
		// Frame 1: SETTINGS ACK
		0x00, 0x00, 0x00, // Length: 0
		0x04,             // Type: SETTINGS
		0x01,             // Flags: ACK
		0x00, 0x00, 0x00, 0x00, // Stream ID: 0
		// Frame 2: PING
		0x00, 0x00, 0x08, // Length: 8
		0x06,             // Type: PING
		0x00,             // Flags
		0x00, 0x00, 0x00, 0x00, // Stream ID: 0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	frames, err := ParseHTTP2Frames(data)
	if err != nil {
		t.Fatalf("Failed to parse frames: %v", err)
	}

	if len(frames) != 2 {
		t.Errorf("Expected 2 frames, got %d", len(frames))
	}

	if frames[0].Type != HTTP2FrameSettings {
		t.Errorf("First frame should be SETTINGS")
	}

	if frames[1].Type != HTTP2FramePing {
		t.Errorf("Second frame should be PING")
	}
}
