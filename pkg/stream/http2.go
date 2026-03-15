// Package stream provides HTTP/2 frame parsing and stream management
package stream

import (
	"encoding/binary"
	"fmt"
)

// HTTP/2 Frame Types (RFC 7540 Section 6)
const (
	HTTP2FrameData         uint8 = 0x0
	HTTP2FrameHeaders      uint8 = 0x1
	HTTP2FramePriority     uint8 = 0x2
	HTTP2FrameRSTStream    uint8 = 0x3
	HTTP2FrameSettings     uint8 = 0x4
	HTTP2FramePushPromise  uint8 = 0x5
	HTTP2FramePing         uint8 = 0x6
	HTTP2FrameGoAway       uint8 = 0x7
	HTTP2FrameWindowUpdate uint8 = 0x8
	HTTP2FrameContinuation uint8 = 0x9
)

// HTTP/2 Frame Flags
const (
	// DATA frame flags
	HTTP2FlagDataEndStream uint8 = 0x1
	HTTP2FlagDataPadded    uint8 = 0x8

	// HEADERS frame flags
	HTTP2FlagHeadersEndStream  uint8 = 0x1
	HTTP2FlagHeadersEndHeaders uint8 = 0x4
	HTTP2FlagHeadersPadded     uint8 = 0x8
	HTTP2FlagHeadersPriority   uint8 = 0x20

	// SETTINGS frame flags
	HTTP2FlagSettingsAck uint8 = 0x1

	// PUSH_PROMISE frame flags
	HTTP2FlagPushPromiseEndHeaders uint8 = 0x4
	HTTP2FlagPushPromisePadded     uint8 = 0x8

	// PING frame flags
	HTTP2FlagPingAck uint8 = 0x1

	// CONTINUATION frame flags
	HTTP2FlagContinuationEndHeaders uint8 = 0x4
)

// HTTP/2 Error Codes (RFC 7540 Section 7)
const (
	HTTP2ErrNoError            uint32 = 0x0
	HTTP2ErrProtocolError      uint32 = 0x1
	HTTP2ErrInternalError      uint32 = 0x2
	HTTP2ErrFlowControlError   uint32 = 0x3
	HTTP2ErrSettingsTimeout    uint32 = 0x4
	HTTP2ErrStreamClosed       uint32 = 0x5
	HTTP2ErrFrameSizeError     uint32 = 0x6
	HTTP2ErrRefusedStream      uint32 = 0x7
	HTTP2ErrCancel             uint32 = 0x8
	HTTP2ErrCompressionError   uint32 = 0x9
	HTTP2ErrConnectError       uint32 = 0xa
	HTTP2ErrEnhanceYourCalm    uint32 = 0xb
	HTTP2ErrInadequateSecurity uint32 = 0xc
	HTTP2ErrHTTP11Required     uint32 = 0xd
)

// HTTP/2 Settings Parameters (RFC 7540 Section 6.5.2)
const (
	HTTP2SettingsHeaderTableSize      uint16 = 0x1
	HTTP2SettingsEnablePush           uint16 = 0x2
	HTTP2SettingsMaxConcurrentStreams uint16 = 0x3
	HTTP2SettingsInitialWindowSize    uint16 = 0x4
	HTTP2SettingsMaxFrameSize         uint16 = 0x5
	HTTP2SettingsMaxHeaderListSize    uint16 = 0x6
)

// HTTP2Frame represents an HTTP/2 frame
type HTTP2Frame struct {
	Length   uint32 // 24 bits
	Type     uint8
	Flags    uint8
	StreamID uint32 // 31 bits (R bit is reserved)
	Payload  []byte
}

// HTTP2FrameHeader is the 9-byte frame header
const HTTP2FrameHeaderSize = 9

// HTTP/2 Connection Preface
var HTTP2ConnectionPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// HTTP2DataPayload represents DATA frame payload
type HTTP2DataPayload struct {
	PadLength uint8
	Data      []byte
}

// HTTP2HeadersPayload represents HEADERS frame payload
type HTTP2HeadersPayload struct {
	PadLength           uint8
	Exclusive           bool
	StreamDependency    uint32
	Weight              uint8
	HeaderBlockFragment []byte
}

// HTTP2PriorityPayload represents PRIORITY frame payload
type HTTP2PriorityPayload struct {
	Exclusive        bool
	StreamDependency uint32
	Weight           uint8
}

// HTTP2RSTStreamPayload represents RST_STREAM frame payload
type HTTP2RSTStreamPayload struct {
	ErrorCode uint32
}

// HTTP2SettingsPayload represents SETTINGS frame payload
type HTTP2SettingsPayload struct {
	Settings []HTTP2Setting
}

// HTTP2Setting represents a single settings parameter
type HTTP2Setting struct {
	ID    uint16
	Value uint32
}

// HTTP2PushPromisePayload represents PUSH_PROMISE frame payload
type HTTP2PushPromisePayload struct {
	PadLength           uint8
	PromisedStreamID    uint32
	HeaderBlockFragment []byte
}

// HTTP2PingPayload represents PING frame payload
type HTTP2PingPayload struct {
	OpaqueData [8]byte
}

// HTTP2GoAwayPayload represents GOAWAY frame payload
type HTTP2GoAwayPayload struct {
	LastStreamID uint32
	ErrorCode    uint32
	DebugData    []byte
}

// HTTP2WindowUpdatePayload represents WINDOW_UPDATE frame payload
type HTTP2WindowUpdatePayload struct {
	WindowSizeIncrement uint32
}

// ParseHTTP2Frame parses an HTTP/2 frame from raw bytes
// Returns the frame, bytes consumed, and error
func ParseHTTP2Frame(data []byte) (*HTTP2Frame, int, error) {
	if len(data) < HTTP2FrameHeaderSize {
		return nil, 0, fmt.Errorf("data too short for HTTP/2 frame header: need %d, have %d", HTTP2FrameHeaderSize, len(data))
	}

	// Parse 24-bit length (big-endian)
	length := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])

	frame := &HTTP2Frame{
		Length:   length,
		Type:     data[3],
		Flags:    data[4],
		StreamID: binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF, // Mask out reserved bit
	}

	totalLen := HTTP2FrameHeaderSize + int(length)
	if len(data) < totalLen {
		return nil, 0, fmt.Errorf("data too short for HTTP/2 frame: need %d, have %d", totalLen, len(data))
	}

	if length > 0 {
		frame.Payload = make([]byte, length)
		copy(frame.Payload, data[HTTP2FrameHeaderSize:totalLen])
	}

	return frame, totalLen, nil
}

// ParseHTTP2Frames parses multiple HTTP/2 frames from data
func ParseHTTP2Frames(data []byte) ([]*HTTP2Frame, error) {
	var frames []*HTTP2Frame
	offset := 0

	for offset < len(data) {
		frame, consumed, err := ParseHTTP2Frame(data[offset:])
		if err != nil {
			// Return frames parsed so far
			if len(frames) > 0 {
				return frames, nil
			}
			return nil, err
		}
		frames = append(frames, frame)
		offset += consumed
	}

	return frames, nil
}

// ParseDataPayload parses DATA frame payload
func (f *HTTP2Frame) ParseDataPayload() (*HTTP2DataPayload, error) {
	if f.Type != HTTP2FrameData {
		return nil, fmt.Errorf("not a DATA frame")
	}

	payload := &HTTP2DataPayload{}
	data := f.Payload
	offset := 0

	// Check for padding
	if f.Flags&HTTP2FlagDataPadded != 0 {
		if len(data) < 1 {
			return nil, fmt.Errorf("DATA frame too short for padding length")
		}
		payload.PadLength = data[0]
		offset = 1
	}

	// Calculate data length
	dataLen := len(data) - offset - int(payload.PadLength)
	if dataLen < 0 {
		return nil, fmt.Errorf("invalid padding length")
	}

	payload.Data = data[offset : offset+dataLen]
	return payload, nil
}

// ParseHeadersPayload parses HEADERS frame payload
func (f *HTTP2Frame) ParseHeadersPayload() (*HTTP2HeadersPayload, error) {
	if f.Type != HTTP2FrameHeaders {
		return nil, fmt.Errorf("not a HEADERS frame")
	}

	payload := &HTTP2HeadersPayload{}
	data := f.Payload
	offset := 0

	// Check for padding
	if f.Flags&HTTP2FlagHeadersPadded != 0 {
		if len(data) < 1 {
			return nil, fmt.Errorf("HEADERS frame too short for padding length")
		}
		payload.PadLength = data[0]
		offset = 1
	}

	// Check for priority
	if f.Flags&HTTP2FlagHeadersPriority != 0 {
		if len(data) < offset+5 {
			return nil, fmt.Errorf("HEADERS frame too short for priority")
		}
		depField := binary.BigEndian.Uint32(data[offset : offset+4])
		payload.Exclusive = depField&0x80000000 != 0
		payload.StreamDependency = depField & 0x7FFFFFFF
		payload.Weight = data[offset+4]
		offset += 5
	}

	// Calculate header block length
	headerLen := len(data) - offset - int(payload.PadLength)
	if headerLen < 0 {
		return nil, fmt.Errorf("invalid padding length")
	}

	payload.HeaderBlockFragment = data[offset : offset+headerLen]
	return payload, nil
}

// ParsePriorityPayload parses PRIORITY frame payload
func (f *HTTP2Frame) ParsePriorityPayload() (*HTTP2PriorityPayload, error) {
	if f.Type != HTTP2FramePriority {
		return nil, fmt.Errorf("not a PRIORITY frame")
	}

	if len(f.Payload) != 5 {
		return nil, fmt.Errorf("PRIORITY frame must be 5 bytes")
	}

	depField := binary.BigEndian.Uint32(f.Payload[0:4])
	return &HTTP2PriorityPayload{
		Exclusive:        depField&0x80000000 != 0,
		StreamDependency: depField & 0x7FFFFFFF,
		Weight:           f.Payload[4],
	}, nil
}

// ParseRSTStreamPayload parses RST_STREAM frame payload
func (f *HTTP2Frame) ParseRSTStreamPayload() (*HTTP2RSTStreamPayload, error) {
	if f.Type != HTTP2FrameRSTStream {
		return nil, fmt.Errorf("not a RST_STREAM frame")
	}

	if len(f.Payload) != 4 {
		return nil, fmt.Errorf("RST_STREAM frame must be 4 bytes")
	}

	return &HTTP2RSTStreamPayload{
		ErrorCode: binary.BigEndian.Uint32(f.Payload),
	}, nil
}

// ParseSettingsPayload parses SETTINGS frame payload
func (f *HTTP2Frame) ParseSettingsPayload() (*HTTP2SettingsPayload, error) {
	if f.Type != HTTP2FrameSettings {
		return nil, fmt.Errorf("not a SETTINGS frame")
	}

	// ACK has no payload
	if f.Flags&HTTP2FlagSettingsAck != 0 {
		if len(f.Payload) != 0 {
			return nil, fmt.Errorf("SETTINGS ACK must have no payload")
		}
		return &HTTP2SettingsPayload{}, nil
	}

	if len(f.Payload)%6 != 0 {
		return nil, fmt.Errorf("SETTINGS payload must be multiple of 6 bytes")
	}

	payload := &HTTP2SettingsPayload{}
	for i := 0; i < len(f.Payload); i += 6 {
		payload.Settings = append(payload.Settings, HTTP2Setting{
			ID:    binary.BigEndian.Uint16(f.Payload[i : i+2]),
			Value: binary.BigEndian.Uint32(f.Payload[i+2 : i+6]),
		})
	}

	return payload, nil
}

// ParsePushPromisePayload parses PUSH_PROMISE frame payload
func (f *HTTP2Frame) ParsePushPromisePayload() (*HTTP2PushPromisePayload, error) {
	if f.Type != HTTP2FramePushPromise {
		return nil, fmt.Errorf("not a PUSH_PROMISE frame")
	}

	payload := &HTTP2PushPromisePayload{}
	data := f.Payload
	offset := 0

	// Check for padding
	if f.Flags&HTTP2FlagPushPromisePadded != 0 {
		if len(data) < 1 {
			return nil, fmt.Errorf("PUSH_PROMISE frame too short for padding length")
		}
		payload.PadLength = data[0]
		offset = 1
	}

	// Promised stream ID
	if len(data) < offset+4 {
		return nil, fmt.Errorf("PUSH_PROMISE frame too short for promised stream ID")
	}
	payload.PromisedStreamID = binary.BigEndian.Uint32(data[offset:offset+4]) & 0x7FFFFFFF
	offset += 4

	// Calculate header block length
	headerLen := len(data) - offset - int(payload.PadLength)
	if headerLen < 0 {
		return nil, fmt.Errorf("invalid padding length")
	}

	payload.HeaderBlockFragment = data[offset : offset+headerLen]
	return payload, nil
}

// ParsePingPayload parses PING frame payload
func (f *HTTP2Frame) ParsePingPayload() (*HTTP2PingPayload, error) {
	if f.Type != HTTP2FramePing {
		return nil, fmt.Errorf("not a PING frame")
	}

	if len(f.Payload) != 8 {
		return nil, fmt.Errorf("PING frame must be 8 bytes")
	}

	payload := &HTTP2PingPayload{}
	copy(payload.OpaqueData[:], f.Payload)
	return payload, nil
}

// ParseGoAwayPayload parses GOAWAY frame payload
func (f *HTTP2Frame) ParseGoAwayPayload() (*HTTP2GoAwayPayload, error) {
	if f.Type != HTTP2FrameGoAway {
		return nil, fmt.Errorf("not a GOAWAY frame")
	}

	if len(f.Payload) < 8 {
		return nil, fmt.Errorf("GOAWAY frame too short")
	}

	payload := &HTTP2GoAwayPayload{
		LastStreamID: binary.BigEndian.Uint32(f.Payload[0:4]) & 0x7FFFFFFF,
		ErrorCode:    binary.BigEndian.Uint32(f.Payload[4:8]),
	}

	if len(f.Payload) > 8 {
		payload.DebugData = f.Payload[8:]
	}

	return payload, nil
}

// ParseWindowUpdatePayload parses WINDOW_UPDATE frame payload
func (f *HTTP2Frame) ParseWindowUpdatePayload() (*HTTP2WindowUpdatePayload, error) {
	if f.Type != HTTP2FrameWindowUpdate {
		return nil, fmt.Errorf("not a WINDOW_UPDATE frame")
	}

	if len(f.Payload) != 4 {
		return nil, fmt.Errorf("WINDOW_UPDATE frame must be 4 bytes")
	}

	return &HTTP2WindowUpdatePayload{
		WindowSizeIncrement: binary.BigEndian.Uint32(f.Payload) & 0x7FFFFFFF,
	}, nil
}

// GetContinuationFragment returns header block fragment from CONTINUATION frame
func (f *HTTP2Frame) GetContinuationFragment() ([]byte, error) {
	if f.Type != HTTP2FrameContinuation {
		return nil, fmt.Errorf("not a CONTINUATION frame")
	}
	return f.Payload, nil
}

// TypeName returns the frame type name
func (f *HTTP2Frame) TypeName() string {
	return HTTP2FrameTypeName(f.Type)
}

// HTTP2FrameTypeName returns the name of an HTTP/2 frame type
func HTTP2FrameTypeName(frameType uint8) string {
	names := map[uint8]string{
		HTTP2FrameData:         "DATA",
		HTTP2FrameHeaders:      "HEADERS",
		HTTP2FramePriority:     "PRIORITY",
		HTTP2FrameRSTStream:    "RST_STREAM",
		HTTP2FrameSettings:     "SETTINGS",
		HTTP2FramePushPromise:  "PUSH_PROMISE",
		HTTP2FramePing:         "PING",
		HTTP2FrameGoAway:       "GOAWAY",
		HTTP2FrameWindowUpdate: "WINDOW_UPDATE",
		HTTP2FrameContinuation: "CONTINUATION",
	}
	if name, ok := names[frameType]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", frameType)
}

// HTTP2ErrorName returns the name of an HTTP/2 error code
func HTTP2ErrorName(errorCode uint32) string {
	names := map[uint32]string{
		HTTP2ErrNoError:            "NO_ERROR",
		HTTP2ErrProtocolError:      "PROTOCOL_ERROR",
		HTTP2ErrInternalError:      "INTERNAL_ERROR",
		HTTP2ErrFlowControlError:   "FLOW_CONTROL_ERROR",
		HTTP2ErrSettingsTimeout:    "SETTINGS_TIMEOUT",
		HTTP2ErrStreamClosed:       "STREAM_CLOSED",
		HTTP2ErrFrameSizeError:     "FRAME_SIZE_ERROR",
		HTTP2ErrRefusedStream:      "REFUSED_STREAM",
		HTTP2ErrCancel:             "CANCEL",
		HTTP2ErrCompressionError:   "COMPRESSION_ERROR",
		HTTP2ErrConnectError:       "CONNECT_ERROR",
		HTTP2ErrEnhanceYourCalm:    "ENHANCE_YOUR_CALM",
		HTTP2ErrInadequateSecurity: "INADEQUATE_SECURITY",
		HTTP2ErrHTTP11Required:     "HTTP_1_1_REQUIRED",
	}
	if name, ok := names[errorCode]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", errorCode)
}

// HTTP2SettingName returns the name of an HTTP/2 setting
func HTTP2SettingName(settingID uint16) string {
	names := map[uint16]string{
		HTTP2SettingsHeaderTableSize:      "HEADER_TABLE_SIZE",
		HTTP2SettingsEnablePush:           "ENABLE_PUSH",
		HTTP2SettingsMaxConcurrentStreams: "MAX_CONCURRENT_STREAMS",
		HTTP2SettingsInitialWindowSize:    "INITIAL_WINDOW_SIZE",
		HTTP2SettingsMaxFrameSize:         "MAX_FRAME_SIZE",
		HTTP2SettingsMaxHeaderListSize:    "MAX_HEADER_LIST_SIZE",
	}
	if name, ok := names[settingID]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", settingID)
}

// FlagsString returns a string representation of frame flags
func (f *HTTP2Frame) FlagsString() string {
	var flags []string

	switch f.Type {
	case HTTP2FrameData:
		if f.Flags&HTTP2FlagDataEndStream != 0 {
			flags = append(flags, "END_STREAM")
		}
		if f.Flags&HTTP2FlagDataPadded != 0 {
			flags = append(flags, "PADDED")
		}
	case HTTP2FrameHeaders:
		if f.Flags&HTTP2FlagHeadersEndStream != 0 {
			flags = append(flags, "END_STREAM")
		}
		if f.Flags&HTTP2FlagHeadersEndHeaders != 0 {
			flags = append(flags, "END_HEADERS")
		}
		if f.Flags&HTTP2FlagHeadersPadded != 0 {
			flags = append(flags, "PADDED")
		}
		if f.Flags&HTTP2FlagHeadersPriority != 0 {
			flags = append(flags, "PRIORITY")
		}
	case HTTP2FrameSettings:
		if f.Flags&HTTP2FlagSettingsAck != 0 {
			flags = append(flags, "ACK")
		}
	case HTTP2FramePushPromise:
		if f.Flags&HTTP2FlagPushPromiseEndHeaders != 0 {
			flags = append(flags, "END_HEADERS")
		}
		if f.Flags&HTTP2FlagPushPromisePadded != 0 {
			flags = append(flags, "PADDED")
		}
	case HTTP2FramePing:
		if f.Flags&HTTP2FlagPingAck != 0 {
			flags = append(flags, "ACK")
		}
	case HTTP2FrameContinuation:
		if f.Flags&HTTP2FlagContinuationEndHeaders != 0 {
			flags = append(flags, "END_HEADERS")
		}
	}

	if len(flags) == 0 {
		return "-"
	}

	result := ""
	for i, flag := range flags {
		if i > 0 {
			result += "|"
		}
		result += flag
	}
	return result
}

// IsEndStream returns true if this frame ends the stream
func (f *HTTP2Frame) IsEndStream() bool {
	switch f.Type {
	case HTTP2FrameData:
		return f.Flags&HTTP2FlagDataEndStream != 0
	case HTTP2FrameHeaders:
		return f.Flags&HTTP2FlagHeadersEndStream != 0
	default:
		return false
	}
}

// IsEndHeaders returns true if this frame ends the header block
func (f *HTTP2Frame) IsEndHeaders() bool {
	switch f.Type {
	case HTTP2FrameHeaders:
		return f.Flags&HTTP2FlagHeadersEndHeaders != 0
	case HTTP2FramePushPromise:
		return f.Flags&HTTP2FlagPushPromiseEndHeaders != 0
	case HTTP2FrameContinuation:
		return f.Flags&HTTP2FlagContinuationEndHeaders != 0
	default:
		return false
	}
}

// Summary returns a summary string for the frame
func (f *HTTP2Frame) Summary() string {
	switch f.Type {
	case HTTP2FrameData:
		return fmt.Sprintf("DATA stream=%d len=%d flags=%s", f.StreamID, f.Length, f.FlagsString())
	case HTTP2FrameHeaders:
		return fmt.Sprintf("HEADERS stream=%d len=%d flags=%s", f.StreamID, f.Length, f.FlagsString())
	case HTTP2FramePriority:
		return fmt.Sprintf("PRIORITY stream=%d", f.StreamID)
	case HTTP2FrameRSTStream:
		if payload, err := f.ParseRSTStreamPayload(); err == nil {
			return fmt.Sprintf("RST_STREAM stream=%d error=%s", f.StreamID, HTTP2ErrorName(payload.ErrorCode))
		}
		return fmt.Sprintf("RST_STREAM stream=%d", f.StreamID)
	case HTTP2FrameSettings:
		if f.Flags&HTTP2FlagSettingsAck != 0 {
			return "SETTINGS ACK"
		}
		return fmt.Sprintf("SETTINGS len=%d", f.Length)
	case HTTP2FramePushPromise:
		if payload, err := f.ParsePushPromisePayload(); err == nil {
			return fmt.Sprintf("PUSH_PROMISE stream=%d promised=%d", f.StreamID, payload.PromisedStreamID)
		}
		return fmt.Sprintf("PUSH_PROMISE stream=%d", f.StreamID)
	case HTTP2FramePing:
		if f.Flags&HTTP2FlagPingAck != 0 {
			return "PING ACK"
		}
		return "PING"
	case HTTP2FrameGoAway:
		if payload, err := f.ParseGoAwayPayload(); err == nil {
			return fmt.Sprintf("GOAWAY last=%d error=%s", payload.LastStreamID, HTTP2ErrorName(payload.ErrorCode))
		}
		return "GOAWAY"
	case HTTP2FrameWindowUpdate:
		if payload, err := f.ParseWindowUpdatePayload(); err == nil {
			return fmt.Sprintf("WINDOW_UPDATE stream=%d increment=%d", f.StreamID, payload.WindowSizeIncrement)
		}
		return fmt.Sprintf("WINDOW_UPDATE stream=%d", f.StreamID)
	case HTTP2FrameContinuation:
		return fmt.Sprintf("CONTINUATION stream=%d len=%d flags=%s", f.StreamID, f.Length, f.FlagsString())
	default:
		return fmt.Sprintf("UNKNOWN(%d) stream=%d len=%d", f.Type, f.StreamID, f.Length)
	}
}

// IsHTTP2Preface checks if data starts with HTTP/2 connection preface
func IsHTTP2Preface(data []byte) bool {
	if len(data) < len(HTTP2ConnectionPreface) {
		return false
	}
	for i, b := range HTTP2ConnectionPreface {
		if data[i] != b {
			return false
		}
	}
	return true
}
