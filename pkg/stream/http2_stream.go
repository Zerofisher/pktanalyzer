// Package stream provides HTTP/2 stream management
package stream

import (
	"fmt"
	"sync"
	"time"
)

// HTTP2StreamState represents the state of an HTTP/2 stream
type HTTP2StreamState int

const (
	HTTP2StreamIdle HTTP2StreamState = iota
	HTTP2StreamReservedLocal
	HTTP2StreamReservedRemote
	HTTP2StreamOpen
	HTTP2StreamHalfClosedLocal
	HTTP2StreamHalfClosedRemote
	HTTP2StreamClosed
)

func (s HTTP2StreamState) String() string {
	names := []string{
		"idle",
		"reserved (local)",
		"reserved (remote)",
		"open",
		"half-closed (local)",
		"half-closed (remote)",
		"closed",
	}
	if int(s) < len(names) {
		return names[s]
	}
	return "unknown"
}

// HTTP2Stream represents a single HTTP/2 stream
type HTTP2Stream struct {
	ID            uint32
	State         HTTP2StreamState
	Priority      HTTP2StreamPriority
	Request       *HTTP2Request
	Response      *HTTP2Response
	Frames        []*HTTP2Frame
	HeaderDecoder *HPACKDecoder

	// Header block accumulation (for CONTINUATION frames)
	headerBlockBuffer []byte
	headersComplete   bool

	// Data accumulation
	RequestData  []byte
	ResponseData []byte

	// Timing
	StartTime time.Time
	EndTime   time.Time
}

// HTTP2StreamPriority represents stream priority
type HTTP2StreamPriority struct {
	Exclusive        bool
	StreamDependency uint32
	Weight           uint8
}

// HTTP2Request represents an HTTP/2 request
type HTTP2Request struct {
	Method    string
	Scheme    string
	Authority string
	Path      string
	Headers   map[string]string
	Body      []byte
}

// HTTP2Response represents an HTTP/2 response
type HTTP2Response struct {
	Status  string
	Headers map[string]string
	Body    []byte
}

// Summary returns a summary of the request
func (r *HTTP2Request) Summary() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%s %s%s", r.Method, r.Authority, r.Path)
}

// Summary returns a summary of the response
func (r *HTTP2Response) Summary() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("Status: %s", r.Status)
}

// HTTP2Connection represents an HTTP/2 connection with all its streams
type HTTP2Connection struct {
	mu           sync.RWMutex
	streams      map[uint32]*HTTP2Stream
	Settings     HTTP2ConnectionSettings
	PeerSettings HTTP2ConnectionSettings

	// HPACK decoders (one for each direction)
	ClientDecoder *HPACKDecoder // For decoding client->server headers
	ServerDecoder *HPACKDecoder // For decoding server->client headers

	// Connection-level state
	LastStreamID   uint32
	GoAwayReceived bool
	GoAwayStreamID uint32
	GoAwayError    uint32

	// All frames in order
	AllFrames []*HTTP2Frame

	// Protocol detection
	IsHTTP2     bool
	PrefaceSeen bool
}

// HTTP2ConnectionSettings represents HTTP/2 connection settings
type HTTP2ConnectionSettings struct {
	HeaderTableSize      uint32
	EnablePush           bool
	MaxConcurrentStreams uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	MaxHeaderListSize    uint32
}

// DefaultHTTP2Settings returns default HTTP/2 settings per RFC 7540
func DefaultHTTP2Settings() HTTP2ConnectionSettings {
	return HTTP2ConnectionSettings{
		HeaderTableSize:      4096,
		EnablePush:           true,
		MaxConcurrentStreams: 100, // Default is unlimited, but we set a reasonable limit
		InitialWindowSize:    65535,
		MaxFrameSize:         16384,
		MaxHeaderListSize:    8192,
	}
}

// NewHTTP2Connection creates a new HTTP/2 connection tracker
func NewHTTP2Connection() *HTTP2Connection {
	return &HTTP2Connection{
		streams:       make(map[uint32]*HTTP2Stream),
		Settings:      DefaultHTTP2Settings(),
		PeerSettings:  DefaultHTTP2Settings(),
		ClientDecoder: DefaultHPACKDecoder(),
		ServerDecoder: DefaultHPACKDecoder(),
		AllFrames:     make([]*HTTP2Frame, 0),
	}
}

// GetStream returns a stream by ID, creating it if necessary
func (c *HTTP2Connection) GetStream(streamID uint32) *HTTP2Stream {
	c.mu.Lock()
	defer c.mu.Unlock()

	if stream, exists := c.streams[streamID]; exists {
		return stream
	}

	// Create new stream
	stream := &HTTP2Stream{
		ID:            streamID,
		State:         HTTP2StreamIdle,
		Frames:        make([]*HTTP2Frame, 0),
		StartTime:     time.Now(),
		HeaderDecoder: DefaultHPACKDecoder(),
	}
	c.streams[streamID] = stream

	if streamID > c.LastStreamID {
		c.LastStreamID = streamID
	}

	return stream
}

// GetAllStreams returns all streams sorted by ID
func (c *HTTP2Connection) GetAllStreams() []*HTTP2Stream {
	c.mu.RLock()
	defer c.mu.RUnlock()

	streams := make([]*HTTP2Stream, 0, len(c.streams))
	for _, s := range c.streams {
		streams = append(streams, s)
	}
	return streams
}

// ProcessFrame processes an HTTP/2 frame and updates connection/stream state
func (c *HTTP2Connection) ProcessFrame(frame *HTTP2Frame, isFromClient bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.AllFrames = append(c.AllFrames, frame)

	// Connection-level frames (stream ID 0)
	if frame.StreamID == 0 {
		return c.processConnectionFrame(frame)
	}

	// Get or create stream
	stream, exists := c.streams[frame.StreamID]
	if !exists {
		stream = &HTTP2Stream{
			ID:            frame.StreamID,
			State:         HTTP2StreamIdle,
			Frames:        make([]*HTTP2Frame, 0),
			StartTime:     time.Now(),
			HeaderDecoder: DefaultHPACKDecoder(),
		}
		c.streams[frame.StreamID] = stream

		if frame.StreamID > c.LastStreamID {
			c.LastStreamID = frame.StreamID
		}
	}

	// Add frame to stream
	stream.Frames = append(stream.Frames, frame)

	// Process based on frame type
	switch frame.Type {
	case HTTP2FrameHeaders:
		return c.processHeadersFrame(stream, frame, isFromClient)
	case HTTP2FrameData:
		return c.processDataFrame(stream, frame, isFromClient)
	case HTTP2FramePriority:
		return c.processPriorityFrame(stream, frame)
	case HTTP2FrameRSTStream:
		return c.processRSTStreamFrame(stream, frame)
	case HTTP2FramePushPromise:
		return c.processPushPromiseFrame(stream, frame)
	case HTTP2FrameContinuation:
		return c.processContinuationFrame(stream, frame, isFromClient)
	case HTTP2FrameWindowUpdate:
		// Window update on stream level - just record
		return nil
	}

	return nil
}

// processConnectionFrame handles connection-level frames
func (c *HTTP2Connection) processConnectionFrame(frame *HTTP2Frame) error {
	switch frame.Type {
	case HTTP2FrameSettings:
		if frame.Flags&HTTP2FlagSettingsAck == 0 {
			payload, err := frame.ParseSettingsPayload()
			if err != nil {
				return err
			}
			for _, setting := range payload.Settings {
				c.applyPeerSetting(setting)
			}
		}
	case HTTP2FrameGoAway:
		payload, err := frame.ParseGoAwayPayload()
		if err != nil {
			return err
		}
		c.GoAwayReceived = true
		c.GoAwayStreamID = payload.LastStreamID
		c.GoAwayError = payload.ErrorCode
	case HTTP2FramePing:
		// Just record
	case HTTP2FrameWindowUpdate:
		// Connection-level flow control
	}
	return nil
}

// applyPeerSetting applies a setting from the peer
func (c *HTTP2Connection) applyPeerSetting(setting HTTP2Setting) {
	switch setting.ID {
	case HTTP2SettingsHeaderTableSize:
		c.PeerSettings.HeaderTableSize = setting.Value
	case HTTP2SettingsEnablePush:
		c.PeerSettings.EnablePush = setting.Value != 0
	case HTTP2SettingsMaxConcurrentStreams:
		c.PeerSettings.MaxConcurrentStreams = setting.Value
	case HTTP2SettingsInitialWindowSize:
		c.PeerSettings.InitialWindowSize = setting.Value
	case HTTP2SettingsMaxFrameSize:
		c.PeerSettings.MaxFrameSize = setting.Value
	case HTTP2SettingsMaxHeaderListSize:
		c.PeerSettings.MaxHeaderListSize = setting.Value
	}
}

// processHeadersFrame handles HEADERS frames
func (c *HTTP2Connection) processHeadersFrame(stream *HTTP2Stream, frame *HTTP2Frame, isFromClient bool) error {
	payload, err := frame.ParseHeadersPayload()
	if err != nil {
		return err
	}

	// Handle priority if present
	if frame.Flags&HTTP2FlagHeadersPriority != 0 {
		stream.Priority = HTTP2StreamPriority{
			Exclusive:        payload.Exclusive,
			StreamDependency: payload.StreamDependency,
			Weight:           payload.Weight,
		}
	}

	// Update stream state
	if stream.State == HTTP2StreamIdle {
		stream.State = HTTP2StreamOpen
	}

	// Start accumulating header block
	stream.headerBlockBuffer = payload.HeaderBlockFragment

	if frame.Flags&HTTP2FlagHeadersEndHeaders != 0 {
		// Headers complete, decode them
		return c.decodeHeaders(stream, isFromClient)
	}

	return nil
}

// processDataFrame handles DATA frames
func (c *HTTP2Connection) processDataFrame(stream *HTTP2Stream, frame *HTTP2Frame, isFromClient bool) error {
	payload, err := frame.ParseDataPayload()
	if err != nil {
		return err
	}

	// Accumulate data
	if isFromClient {
		stream.RequestData = append(stream.RequestData, payload.Data...)
		if stream.Request != nil {
			stream.Request.Body = stream.RequestData
		}
	} else {
		stream.ResponseData = append(stream.ResponseData, payload.Data...)
		if stream.Response != nil {
			stream.Response.Body = stream.ResponseData
		}
	}

	// Update state on END_STREAM
	if frame.Flags&HTTP2FlagDataEndStream != 0 {
		if isFromClient {
			if stream.State == HTTP2StreamOpen {
				stream.State = HTTP2StreamHalfClosedLocal
			} else if stream.State == HTTP2StreamHalfClosedRemote {
				stream.State = HTTP2StreamClosed
				stream.EndTime = time.Now()
			}
		} else {
			if stream.State == HTTP2StreamOpen {
				stream.State = HTTP2StreamHalfClosedRemote
			} else if stream.State == HTTP2StreamHalfClosedLocal {
				stream.State = HTTP2StreamClosed
				stream.EndTime = time.Now()
			}
		}
	}

	return nil
}

// processPriorityFrame handles PRIORITY frames
func (c *HTTP2Connection) processPriorityFrame(stream *HTTP2Stream, frame *HTTP2Frame) error {
	payload, err := frame.ParsePriorityPayload()
	if err != nil {
		return err
	}

	stream.Priority = HTTP2StreamPriority{
		Exclusive:        payload.Exclusive,
		StreamDependency: payload.StreamDependency,
		Weight:           payload.Weight,
	}

	return nil
}

// processRSTStreamFrame handles RST_STREAM frames
func (c *HTTP2Connection) processRSTStreamFrame(stream *HTTP2Stream, frame *HTTP2Frame) error {
	stream.State = HTTP2StreamClosed
	stream.EndTime = time.Now()
	return nil
}

// processPushPromiseFrame handles PUSH_PROMISE frames
func (c *HTTP2Connection) processPushPromiseFrame(stream *HTTP2Stream, frame *HTTP2Frame) error {
	payload, err := frame.ParsePushPromisePayload()
	if err != nil {
		return err
	}

	// Create the promised stream
	promisedStream := &HTTP2Stream{
		ID:            payload.PromisedStreamID,
		State:         HTTP2StreamReservedRemote,
		Frames:        make([]*HTTP2Frame, 0),
		StartTime:     time.Now(),
		HeaderDecoder: DefaultHPACKDecoder(),
	}
	c.streams[payload.PromisedStreamID] = promisedStream

	// Start accumulating header block for promised stream
	promisedStream.headerBlockBuffer = payload.HeaderBlockFragment

	if frame.Flags&HTTP2FlagPushPromiseEndHeaders != 0 {
		// Headers complete, decode them
		return c.decodeHeaders(promisedStream, true) // PUSH_PROMISE is a request
	}

	return nil
}

// processContinuationFrame handles CONTINUATION frames
func (c *HTTP2Connection) processContinuationFrame(stream *HTTP2Stream, frame *HTTP2Frame, isFromClient bool) error {
	fragment, err := frame.GetContinuationFragment()
	if err != nil {
		return err
	}

	// Append to header block buffer
	stream.headerBlockBuffer = append(stream.headerBlockBuffer, fragment...)

	if frame.Flags&HTTP2FlagContinuationEndHeaders != 0 {
		// Headers complete, decode them
		return c.decodeHeaders(stream, isFromClient)
	}

	return nil
}

// decodeHeaders decodes the accumulated header block
func (c *HTTP2Connection) decodeHeaders(stream *HTTP2Stream, isFromClient bool) error {
	if len(stream.headerBlockBuffer) == 0 {
		return nil
	}

	// Select appropriate decoder based on direction
	decoder := c.ClientDecoder
	if !isFromClient {
		decoder = c.ServerDecoder
	}

	headers, err := decoder.Decode(stream.headerBlockBuffer)
	if err != nil {
		return err
	}

	// Extract pseudo-headers and regular headers
	pseudoHeaders := ExtractPseudoHeaders(headers)
	regularHeaders := make(map[string]string)
	for _, h := range headers {
		if len(h.Name) > 0 && h.Name[0] != ':' {
			regularHeaders[h.Name] = h.Value
		}
	}

	// Create request or response
	if isFromClient {
		stream.Request = &HTTP2Request{
			Method:    pseudoHeaders.Method,
			Scheme:    pseudoHeaders.Scheme,
			Authority: pseudoHeaders.Authority,
			Path:      pseudoHeaders.Path,
			Headers:   regularHeaders,
			Body:      stream.RequestData,
		}
	} else {
		stream.Response = &HTTP2Response{
			Status:  pseudoHeaders.Status,
			Headers: regularHeaders,
			Body:    stream.ResponseData,
		}
	}

	// Clear buffer
	stream.headerBlockBuffer = nil
	stream.headersComplete = true

	return nil
}

// StreamCount returns the number of streams
func (c *HTTP2Connection) StreamCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.streams)
}

// Summary returns a summary of the HTTP/2 connection
func (c *HTTP2Connection) Summary() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return fmt.Sprintf("HTTP/2: %d streams, %d frames", len(c.streams), len(c.AllFrames))
}

// HTTP2Parser parses HTTP/2 from reassembled TCP data
type HTTP2Parser struct {
	Connection   *HTTP2Connection
	ClientBuffer []byte // Buffer for client->server data
	ServerBuffer []byte // Buffer for server->client data
}

// NewHTTP2Parser creates a new HTTP/2 parser
func NewHTTP2Parser() *HTTP2Parser {
	return &HTTP2Parser{
		Connection: NewHTTP2Connection(),
	}
}

// ParseClientData parses client->server HTTP/2 data
func (p *HTTP2Parser) ParseClientData(data []byte) error {
	p.ClientBuffer = append(p.ClientBuffer, data...)

	// Check for connection preface
	if !p.Connection.PrefaceSeen {
		if len(p.ClientBuffer) >= len(HTTP2ConnectionPreface) {
			if IsHTTP2Preface(p.ClientBuffer) {
				p.Connection.IsHTTP2 = true
				p.Connection.PrefaceSeen = true
				p.ClientBuffer = p.ClientBuffer[len(HTTP2ConnectionPreface):]
			}
		}
	}

	// Parse frames
	return p.parseFrames(true)
}

// ParseServerData parses server->client HTTP/2 data
func (p *HTTP2Parser) ParseServerData(data []byte) error {
	p.ServerBuffer = append(p.ServerBuffer, data...)
	return p.parseFrames(false)
}

// parseFrames parses frames from the appropriate buffer
func (p *HTTP2Parser) parseFrames(isFromClient bool) error {
	var buffer *[]byte
	if isFromClient {
		buffer = &p.ClientBuffer
	} else {
		buffer = &p.ServerBuffer
	}

	for len(*buffer) >= HTTP2FrameHeaderSize {
		frame, consumed, err := ParseHTTP2Frame(*buffer)
		if err != nil {
			// Not enough data or parse error
			break
		}

		if err := p.Connection.ProcessFrame(frame, isFromClient); err != nil {
			return err
		}

		*buffer = (*buffer)[consumed:]
	}

	return nil
}

// ParseStream parses HTTP/2 from a TCP stream
func (p *HTTP2Parser) ParseStream(stream *TCPStream) error {
	// Parse client data
	if clientData := stream.GetClientData(); len(clientData) > 0 {
		if err := p.ParseClientData(clientData); err != nil {
			return err
		}
	}

	// Parse server data
	if serverData := stream.GetServerData(); len(serverData) > 0 {
		if err := p.ParseServerData(serverData); err != nil {
			return err
		}
	}

	return nil
}
