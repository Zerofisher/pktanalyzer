package stream

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// TCPState represents the state of a TCP connection
type TCPState int

const (
	StateClosed TCPState = iota
	StateSynSent
	StateSynReceived
	StateEstablished
	StateFinWait1
	StateFinWait2
	StateCloseWait
	StateLastAck
	StateTimeWait
)

func (s TCPState) String() string {
	names := []string{
		"CLOSED", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED",
		"FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT",
	}
	if int(s) < len(names) {
		return names[s]
	}
	return "UNKNOWN"
}

// TCPFlags represents TCP flag bits
type TCPFlags uint16

const (
	FlagFIN TCPFlags = 1 << iota
	FlagSYN
	FlagRST
	FlagPSH
	FlagACK
	FlagURG
	FlagECE
	FlagCWR
)

func (f TCPFlags) Has(flag TCPFlags) bool {
	return f&flag != 0
}

func (f TCPFlags) String() string {
	var flags string
	if f.Has(FlagSYN) {
		flags += "S"
	}
	if f.Has(FlagACK) {
		flags += "A"
	}
	if f.Has(FlagFIN) {
		flags += "F"
	}
	if f.Has(FlagRST) {
		flags += "R"
	}
	if f.Has(FlagPSH) {
		flags += "P"
	}
	if f.Has(FlagURG) {
		flags += "U"
	}
	return flags
}

// TCPStream represents a TCP connection
type TCPStream struct {
	ID         int
	Key        string
	ClientAddr string // IP:Port (initiator)
	ServerAddr string // IP:Port (responder)
	State      TCPState

	// Initial sequence numbers
	ClientISN uint32
	ServerISN uint32

	// Reassembly buffers
	ClientData *ReassemblyBuffer // Client → Server data
	ServerData *ReassemblyBuffer // Server → Client data

	// Timestamps
	StartTime time.Time
	EndTime   time.Time
	LastSeen  time.Time

	// Associated packets
	PacketNums []int

	// Statistics
	ClientBytes int
	ServerBytes int
	PacketCount int

	// FIN tracking for proper state transitions
	ClientFinSeen bool
	ServerFinSeen bool

	// Direction certainty (false for mid-stream captures)
	DirectionKnown bool

	// Protocol detection
	Protocol        string // "HTTP/1.1", "HTTP/2", "TLS", "WebSocket", etc.
	IsHTTP2         bool
	HTTP2Parser     *HTTP2Parser     // HTTP/2 parser if this is an HTTP/2 stream
	ALPNProtocol    string           // Negotiated ALPN protocol (from TLS)
	IsWebSocket     bool             // WebSocket connection detected
	WebSocketParser *WebSocketParser // WebSocket parser if this is a WebSocket stream
}

// TotalBytes returns total bytes in both directions
func (s *TCPStream) TotalBytes() int {
	return s.ClientBytes + s.ServerBytes
}

// Duration returns the duration of the stream
func (s *TCPStream) Duration() time.Duration {
	if s.EndTime.IsZero() {
		return s.LastSeen.Sub(s.StartTime)
	}
	return s.EndTime.Sub(s.StartTime)
}

// GetClientData returns reassembled client data
func (s *TCPStream) GetClientData() []byte {
	if s.ClientData == nil {
		return nil
	}
	return s.ClientData.GetAssembled()
}

// GetServerData returns reassembled server data
func (s *TCPStream) GetServerData() []byte {
	if s.ServerData == nil {
		return nil
	}
	return s.ServerData.GetAssembled()
}

// StreamStats contains detailed statistics for a stream
type StreamStats struct {
	UniqueClientBytes int // Actual unique bytes from client
	UniqueServerBytes int // Actual unique bytes from server
	DroppedBytes      int // Bytes dropped due to limits
	DroppedSegs       int // Segments dropped due to limits
	PendingSegs       int // Currently pending out-of-order segments
}

// GetStats returns detailed statistics for the stream
func (s *TCPStream) GetStats() StreamStats {
	stats := StreamStats{
		UniqueClientBytes: s.ClientBytes,
		UniqueServerBytes: s.ServerBytes,
	}

	if s.ClientData != nil {
		bytes, segs := s.ClientData.GetDroppedStats()
		stats.DroppedBytes += bytes
		stats.DroppedSegs += segs
		stats.PendingSegs += s.ClientData.GetPendingSegments()
	}
	if s.ServerData != nil {
		bytes, segs := s.ServerData.GetDroppedStats()
		stats.DroppedBytes += bytes
		stats.DroppedSegs += segs
		stats.PendingSegs += s.ServerData.GetPendingSegments()
	}

	return stats
}

// DetectProtocol attempts to detect the application protocol
func (s *TCPStream) DetectProtocol() string {
	clientData := s.GetClientData()
	serverData := s.GetServerData()

	// Check for HTTP/2 connection preface
	if len(clientData) >= len(HTTP2ConnectionPreface) {
		if IsHTTP2Preface(clientData) {
			s.IsHTTP2 = true
			s.Protocol = "HTTP/2"
			return "HTTP/2"
		}
	}

	// Check for WebSocket upgrade (before generic HTTP check)
	if IsWebSocketUpgrade(clientData) && IsWebSocketResponse(serverData) {
		s.IsWebSocket = true
		s.Protocol = "WebSocket"
		return "WebSocket"
	}

	// Check for HTTP/1.x
	if len(clientData) > 0 {
		// Simple heuristic: HTTP methods
		methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}
		for _, m := range methods {
			if len(clientData) >= len(m) && string(clientData[:len(m)]) == m {
				s.Protocol = "HTTP/1.1"
				return "HTTP/1.1"
			}
		}
	}

	// Check for TLS
	if len(clientData) >= 5 {
		// TLS record header: content type (1 byte) + version (2 bytes) + length (2 bytes)
		if clientData[0] == 0x16 { // Handshake
			version := uint16(clientData[1])<<8 | uint16(clientData[2])
			if version >= 0x0300 && version <= 0x0304 {
				s.Protocol = "TLS"
				return "TLS"
			}
		}
	}

	// Check for HTTP/2 response (in case we missed the preface)
	if len(serverData) >= HTTP2FrameHeaderSize {
		// Try to parse as HTTP/2 frame
		if frame, _, err := ParseHTTP2Frame(serverData); err == nil {
			// Valid frame types for HTTP/2
			if frame.Type <= HTTP2FrameContinuation {
				s.IsHTTP2 = true
				s.Protocol = "HTTP/2"
				return "HTTP/2"
			}
		}
	}

	return ""
}

// InitHTTP2Parser initializes the HTTP/2 parser for this stream
func (s *TCPStream) InitHTTP2Parser() {
	if s.HTTP2Parser == nil {
		s.HTTP2Parser = NewHTTP2Parser()
		s.IsHTTP2 = true
		s.Protocol = "HTTP/2"
	}
}

// ParseHTTP2 parses the stream as HTTP/2
func (s *TCPStream) ParseHTTP2() error {
	if s.HTTP2Parser == nil {
		s.InitHTTP2Parser()
	}
	return s.HTTP2Parser.ParseStream(s)
}

// GetHTTP2Streams returns all HTTP/2 streams if this is an HTTP/2 connection
func (s *TCPStream) GetHTTP2Streams() []*HTTP2Stream {
	if s.HTTP2Parser == nil {
		return nil
	}
	return s.HTTP2Parser.Connection.GetAllStreams()
}

// GetHTTP2Summary returns a summary of HTTP/2 content
func (s *TCPStream) GetHTTP2Summary() string {
	if s.HTTP2Parser == nil {
		return ""
	}
	return s.HTTP2Parser.Connection.Summary()
}

// InitWebSocketParser initializes the WebSocket parser for this stream
func (s *TCPStream) InitWebSocketParser() {
	if s.WebSocketParser == nil {
		s.WebSocketParser = NewWebSocketParser()
		s.IsWebSocket = true
		s.Protocol = "WebSocket"
	}
}

// ParseWebSocket parses the stream as WebSocket
func (s *TCPStream) ParseWebSocket() error {
	if s.WebSocketParser == nil {
		s.InitWebSocketParser()
	}
	return s.WebSocketParser.ParseStream(s)
}

// GetWebSocketFrames returns all WebSocket frames if this is a WebSocket connection
func (s *TCPStream) GetWebSocketFrames() []*WebSocketFrame {
	if s.WebSocketParser == nil {
		return nil
	}
	return s.WebSocketParser.Connection.Frames
}

// GetWebSocketMessages returns all complete WebSocket messages
func (s *TCPStream) GetWebSocketMessages() []*WebSocketMessage {
	if s.WebSocketParser == nil {
		return nil
	}
	return s.WebSocketParser.Connection.Messages
}

// GetWebSocketSummary returns a summary of WebSocket content
func (s *TCPStream) GetWebSocketSummary() string {
	if s.WebSocketParser == nil {
		return ""
	}
	return s.WebSocketParser.Connection.Summary()
}

// GetWebSocketHandshake returns the WebSocket handshake info
func (s *TCPStream) GetWebSocketHandshake() *WebSocketHandshake {
	if s.WebSocketParser == nil {
		return nil
	}
	return s.WebSocketParser.Connection.Handshake
}

// StreamCallbacks contains optional callbacks for stream events
type StreamCallbacks struct {
	OnStreamCreated   func(*TCPStream)
	OnStreamClosed    func(*TCPStream)
	OnDataReassembled func(stream *TCPStream, data []byte, isFromClient bool)
}

// StreamManager manages all TCP streams
type StreamManager struct {
	mu        sync.RWMutex
	streams   map[string]*TCPStream
	streamIDs map[string]int
	nextID    int
	enabled   bool
	callbacks *StreamCallbacks
}

// NewStreamManager creates a new stream manager
func NewStreamManager() *StreamManager {
	return &StreamManager{
		streams:   make(map[string]*TCPStream),
		streamIDs: make(map[string]int),
		nextID:    1,
		enabled:   true,
	}
}

// SetCallbacks sets the stream event callbacks
func (m *StreamManager) SetCallbacks(cb *StreamCallbacks) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks = cb
}

// StreamKey generates a normalized stream key from connection tuple
func StreamKey(srcIP, dstIP string, srcPort, dstPort uint16) string {
	// Normalize: ensure both directions map to same stream
	if srcIP < dstIP || (srcIP == dstIP && srcPort < dstPort) {
		return fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	}
	return fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)
}

// TCPPacket contains TCP packet info for stream processing
type TCPPacket struct {
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Seq       uint32
	Ack       uint32
	Flags     TCPFlags
	Payload   []byte
	Timestamp time.Time
	PacketNum int
}

// ProcessPacket processes a TCP packet and updates stream state
func (m *StreamManager) ProcessPacket(pkt *TCPPacket) string {
	if !m.enabled {
		return ""
	}

	key := StreamKey(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort)

	m.mu.Lock()
	defer m.mu.Unlock()

	stream, exists := m.streams[key]
	isNewStream := false
	if !exists {
		isNewStream = true
		// Create new stream on SYN
		if !pkt.Flags.Has(FlagSYN) {
			// Not a SYN, might be mid-stream capture
			stream = m.createMidStream(key, pkt)
		} else {
			stream = m.createStream(key, pkt)
		}
		m.streams[key] = stream
	}

	// Update stream
	prevState := stream.State
	m.updateStream(stream, pkt)

	// Fire callbacks (outside of holding write lock for too long would be better,
	// but for simplicity we keep it here)
	if m.callbacks != nil {
		if isNewStream && m.callbacks.OnStreamCreated != nil {
			m.callbacks.OnStreamCreated(stream)
		}
		if stream.State == StateClosed && prevState != StateClosed && m.callbacks.OnStreamClosed != nil {
			m.callbacks.OnStreamClosed(stream)
		}
	}

	return key
}

// createStream creates a new stream from SYN packet
func (m *StreamManager) createStream(key string, pkt *TCPPacket) *TCPStream {
	stream := &TCPStream{
		ID:             m.nextID,
		Key:            key,
		ClientAddr:     fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort),
		ServerAddr:     fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort),
		State:          StateSynSent,
		ClientISN:      pkt.Seq,
		ClientData:     NewReassemblyBuffer(pkt.Seq + 1), // ISN + 1
		ServerData:     nil,                              // Will be set on SYN-ACK
		StartTime:      pkt.Timestamp,
		LastSeen:       pkt.Timestamp,
		PacketNums:     []int{pkt.PacketNum},
		DirectionKnown: true, // SYN clearly indicates direction
	}
	m.nextID++
	return stream
}

// createMidStream creates a stream for mid-stream capture
func (m *StreamManager) createMidStream(key string, pkt *TCPPacket) *TCPStream {
	// Use port heuristic: lower port is usually the server
	srcAddr := fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)
	dstAddr := fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort)
	clientAddr, serverAddr := srcAddr, dstAddr
	clientSeq, serverSeq := pkt.Seq, pkt.Ack

	// Heuristic: well-known ports (< 1024) or common server ports are likely servers
	if isLikelyServerPort(pkt.SrcPort) && !isLikelyServerPort(pkt.DstPort) {
		// Swap: src is server, dst is client
		clientAddr, serverAddr = dstAddr, srcAddr
		clientSeq, serverSeq = pkt.Ack, pkt.Seq
	}

	stream := &TCPStream{
		ID:             m.nextID,
		Key:            key,
		ClientAddr:     clientAddr,
		ServerAddr:     serverAddr,
		State:          StateEstablished, // Assume established
		ClientISN:      clientSeq,
		ServerISN:      serverSeq,
		ClientData:     NewReassemblyBuffer(clientSeq),
		ServerData:     NewReassemblyBuffer(serverSeq),
		StartTime:      pkt.Timestamp,
		LastSeen:       pkt.Timestamp,
		PacketNums:     []int{pkt.PacketNum},
		DirectionKnown: false, // Mid-stream, direction is heuristic
	}
	m.nextID++
	return stream
}

// isLikelyServerPort returns true if the port is likely a server port
func isLikelyServerPort(port uint16) bool {
	// Well-known ports
	if port < 1024 {
		return true
	}
	// Common server ports
	commonPorts := map[uint16]bool{
		3306: true, 5432: true, 6379: true, 27017: true, // Databases
		8080: true, 8443: true, 3000: true, 5000: true, // Web servers
		9000: true, 9090: true, // Various services
	}
	return commonPorts[port]
}

// updateStream updates stream state based on packet
func (m *StreamManager) updateStream(stream *TCPStream, pkt *TCPPacket) {
	stream.LastSeen = pkt.Timestamp
	stream.PacketNums = append(stream.PacketNums, pkt.PacketNum)
	stream.PacketCount++

	// Determine direction
	isFromClient := fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort) == stream.ClientAddr

	// Handle state transitions
	switch {
	case pkt.Flags.Has(FlagRST):
		stream.State = StateClosed
		stream.EndTime = pkt.Timestamp

	case pkt.Flags.Has(FlagSYN) && pkt.Flags.Has(FlagACK):
		// SYN-ACK from server
		if stream.State == StateSynSent && !isFromClient {
			stream.ServerISN = pkt.Seq
			stream.ServerData = NewReassemblyBuffer(pkt.Seq + 1)
			stream.State = StateSynReceived
		}

	case pkt.Flags.Has(FlagSYN):
		// SYN retransmit or new connection
		if isFromClient && stream.State == StateClosed {
			stream.ClientISN = pkt.Seq
			stream.State = StateSynSent
		}

	case pkt.Flags.Has(FlagFIN):
		// Track which side sent FIN
		if isFromClient {
			stream.ClientFinSeen = true
		} else {
			stream.ServerFinSeen = true
		}

		// Handle FIN state transitions
		switch stream.State {
		case StateEstablished:
			if isFromClient {
				stream.State = StateFinWait1
			} else {
				stream.State = StateCloseWait
			}
		case StateFinWait1:
			if !isFromClient {
				// Received FIN from server while waiting for ACK of our FIN
				// This is simultaneous close
				if stream.ClientFinSeen && stream.ServerFinSeen {
					stream.State = StateTimeWait
					stream.EndTime = pkt.Timestamp
				} else {
					stream.State = StateFinWait2
				}
			}
		case StateFinWait2:
			if !isFromClient {
				// Received FIN from server
				stream.State = StateTimeWait
				stream.EndTime = pkt.Timestamp
			}
		case StateCloseWait:
			if isFromClient {
				// Our FIN sent
				stream.State = StateLastAck
			}
		}

		// Check for simultaneous close (both FINs seen)
		if stream.ClientFinSeen && stream.ServerFinSeen && stream.State != StateClosed {
			stream.State = StateTimeWait
			stream.EndTime = pkt.Timestamp
		}

	case pkt.Flags.Has(FlagACK):
		// Regular ACK or data
		switch stream.State {
		case StateSynReceived:
			stream.State = StateEstablished
		case StateLastAck:
			stream.State = StateClosed
			stream.EndTime = pkt.Timestamp
		case StateTimeWait:
			// ACK in TIME_WAIT, connection fully closed
			stream.State = StateClosed
			stream.EndTime = pkt.Timestamp
		case StateFinWait1:
			// ACK of our FIN
			if stream.ServerFinSeen {
				// Already received server's FIN, go to TIME_WAIT
				stream.State = StateTimeWait
				stream.EndTime = pkt.Timestamp
			} else {
				stream.State = StateFinWait2
			}
		}
	}

	// Add payload to reassembly buffer
	// Allow data in established and closing states (data can arrive during graceful close)
	validDataStates := stream.State == StateEstablished ||
		stream.State == StateFinWait1 ||
		stream.State == StateFinWait2 ||
		stream.State == StateCloseWait
	if len(pkt.Payload) > 0 && validDataStates {
		if isFromClient {
			if stream.ClientData != nil {
				added := stream.ClientData.AddSegment(pkt.Seq, pkt.Payload, pkt.Timestamp)
				stream.ClientBytes += added
			}
		} else {
			if stream.ServerData != nil {
				added := stream.ServerData.AddSegment(pkt.Seq, pkt.Payload, pkt.Timestamp)
				stream.ServerBytes += added
			}
		}
	}
}

// GetStream returns a stream by key
func (m *StreamManager) GetStream(key string) *TCPStream {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.streams[key]
}

// GetAllStreams returns all streams sorted by ID
func (m *StreamManager) GetAllStreams() []*TCPStream {
	m.mu.RLock()
	defer m.mu.RUnlock()

	streams := make([]*TCPStream, 0, len(m.streams))
	for _, s := range m.streams {
		streams = append(streams, s)
	}

	sort.Slice(streams, func(i, j int) bool {
		return streams[i].ID < streams[j].ID
	})

	return streams
}

// GetStreams is an alias for GetAllStreams
func (m *StreamManager) GetStreams() []*TCPStream {
	return m.GetAllStreams()
}

// GetStreamByID returns a stream by its ID
func (m *StreamManager) GetStreamByID(id int) *TCPStream {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.streams {
		if s.ID == id {
			return s
		}
	}
	return nil
}

// StreamCount returns the number of streams
func (m *StreamManager) StreamCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.streams)
}

// SetEnabled enables or disables stream tracking
func (m *StreamManager) SetEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = enabled
}

// IsEnabled returns whether stream tracking is enabled
func (m *StreamManager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// CleanExpiredStreams removes streams that have been inactive for longer than timeout
// Returns the number of streams removed
func (m *StreamManager) CleanExpiredStreams(timeout time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	removed := 0
	keysToDelete := make([]string, 0)

	for key, stream := range m.streams {
		// Only clean closed streams or streams inactive for too long
		if stream.State == StateClosed || now.Sub(stream.LastSeen) > timeout {
			keysToDelete = append(keysToDelete, key)
			removed++
		}
	}

	for _, key := range keysToDelete {
		delete(m.streams, key)
	}

	return removed
}

// CleanStaleSegments cleans stale out-of-order segments from all streams
// Returns total segments removed
func (m *StreamManager) CleanStaleSegments(timeout time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	total := 0
	for _, stream := range m.streams {
		if stream.ClientData != nil {
			total += stream.ClientData.CleanStaleSegments(timeout)
		}
		if stream.ServerData != nil {
			total += stream.ServerData.CleanStaleSegments(timeout)
		}
	}
	return total
}
