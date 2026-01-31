package uiadapter

import (
	"sync"

	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/pkg/model"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
)

const (
	// DefaultMaxPackets is the default maximum number of packets to keep in memory.
	DefaultMaxPackets = 100000
)

// MemoryStore is a PacketStore implementation that keeps packets in memory.
// It uses a ring buffer to limit memory usage for live capture scenarios.
//
// Thread-safe for concurrent read/write access.
type MemoryStore struct {
	mu         sync.RWMutex
	packets    []*DisplayPacket
	maxPackets int
	nextNumber int // next packet number to assign

	// Filtering
	filterExpr     string
	filteredIdx    []int // indices of packets matching filter
	filterCompiled bool

	// Statistics
	stats *Stats

	// Stop signal for receiver
	stopCh    chan struct{}
	closeOnce sync.Once
}

// NewMemoryStore creates a new MemoryStore with default capacity.
func NewMemoryStore() *MemoryStore {
	return NewMemoryStoreWithCapacity(DefaultMaxPackets)
}

// NewMemoryStoreWithCapacity creates a new MemoryStore with the given capacity.
func NewMemoryStoreWithCapacity(maxPackets int) *MemoryStore {
	if maxPackets <= 0 {
		maxPackets = DefaultMaxPackets
	}
	return &MemoryStore{
		packets:    make([]*DisplayPacket, 0, min(maxPackets, 10000)), // pre-allocate reasonably
		maxPackets: maxPackets,
		nextNumber: 1,
		stats:      NewStats(),
		stopCh:     make(chan struct{}),
	}
}

// --- Mode identification ---

func (s *MemoryStore) IsLive() bool    { return true }
func (s *MemoryStore) IsIndexed() bool { return false }

// --- Packet access ---

func (s *MemoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.packets)
}

func (s *MemoryStore) Get(number int) *DisplayPacket {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find packet by number (packets may have been rotated out)
	for _, p := range s.packets {
		if p.Number == number {
			return p
		}
	}
	return nil
}

func (s *MemoryStore) GetRange(offset, limit int) []*DisplayPacket {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if offset < 0 {
		offset = 0
	}
	if offset >= len(s.packets) {
		return nil
	}

	end := offset + limit
	if end > len(s.packets) {
		end = len(s.packets)
	}

	// Return slice copy to avoid data races
	result := make([]*DisplayPacket, end-offset)
	copy(result, s.packets[offset:end])
	return result
}

func (s *MemoryStore) GetRaw(number int) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, p := range s.packets {
		if p.Number == number && p.RawPacketInfo != nil {
			return p.RawPacketInfo.RawData, nil
		}
	}
	return nil, nil
}

// --- Agent interface (PacketReader) ---

// GetPacketsForAgent returns packets as capture.PacketInfo for agent tools.
func (s *MemoryStore) GetPacketsForAgent(offset, limit int) []capture.PacketInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if offset < 0 {
		offset = 0
	}
	if offset >= len(s.packets) {
		return nil
	}

	end := offset + limit
	if end > len(s.packets) {
		end = len(s.packets)
	}

	result := make([]capture.PacketInfo, 0, end-offset)
	for _, p := range s.packets[offset:end] {
		result = append(result, convertToPacketInfo(p))
	}
	return result
}

// GetPacketForAgent returns a single packet as capture.PacketInfo for agent tools.
func (s *MemoryStore) GetPacketForAgent(number int) *capture.PacketInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, p := range s.packets {
		if p.Number == number {
			pkt := convertToPacketInfo(p)
			return &pkt
		}
	}
	return nil
}

// convertToPacketInfo converts DisplayPacket to capture.PacketInfo.
func convertToPacketInfo(p *DisplayPacket) capture.PacketInfo {
	// If we have the original RawPacketInfo, return it directly
	if p.RawPacketInfo != nil {
		return *p.RawPacketInfo
	}

	// Otherwise, reconstruct from DisplayPacket fields
	pkt := capture.PacketInfo{
		Number:    p.Number,
		Timestamp: p.Timestamp,
		Length:    p.Length,
		SrcMAC:    p.SrcMAC,
		DstMAC:    p.DstMAC,
		SrcIP:     p.SrcIP,
		DstIP:     p.DstIP,
		SrcPort:   p.SrcPort,
		DstPort:   p.DstPort,
		Protocol:  p.Protocol,
		Info:      p.Info,
		SNI:       p.SNI,
		Decrypted: p.Decrypted,
		TCPFlags:  p.TCPFlags,
		TCPSeq:    p.TCPSeq,
		TCPAck:    p.TCPAck,
		TCPWindow: p.TCPWindow,
		StreamKey: p.FlowID,
	}

	// Convert layers
	for _, l := range p.Layers {
		pkt.Layers = append(pkt.Layers, capture.LayerInfo{
			Name:    l.Name,
			Details: l.Details,
		})
	}

	return pkt
}

// --- Write operations ---

func (s *MemoryStore) Add(pkt *DisplayPacket) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Assign number if not set
	if pkt.Number == 0 {
		pkt.Number = s.nextNumber
	}
	s.nextNumber = pkt.Number + 1

	// Add to buffer
	s.packets = append(s.packets, pkt)

	// Enforce max capacity (ring buffer behavior)
	if len(s.packets) > s.maxPackets {
		// Remove oldest packets
		excess := len(s.packets) - s.maxPackets
		s.packets = s.packets[excess:]
	}

	// Update stats
	s.stats.Update(pkt)

	// Invalidate filter cache
	if s.filterCompiled {
		s.filteredIdx = nil
		s.filterCompiled = false
	}
}

// --- Filtering ---

func (s *MemoryStore) SetFilter(expr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.filterExpr = expr
	s.filteredIdx = nil
	s.filterCompiled = false

	if expr == "" {
		return nil
	}

	// TODO: Compile and apply filter expression
	// For now, just store the expression
	return nil
}

func (s *MemoryStore) IsFiltered() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.filterExpr != ""
}

func (s *MemoryStore) FilteredCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.filterExpr == "" {
		return len(s.packets)
	}

	// TODO: Apply filter and return count
	return len(s.packets)
}

func (s *MemoryStore) GetFilteredRange(offset, limit int) []*DisplayPacket {
	// TODO: Implement filtering
	return s.GetRange(offset, limit)
}

// --- Flow and statistics ---

func (s *MemoryStore) GetFlows(offset, limit int) ([]*model.Flow, error) {
	// MemoryStore doesn't track flows
	return nil, nil
}

func (s *MemoryStore) FlowCount() int {
	return 0
}

func (s *MemoryStore) GetOverview() (*query.Overview, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var totalBytes int64
	for _, p := range s.packets {
		totalBytes += int64(p.Length)
	}

	return &query.Overview{
		TotalPackets: len(s.packets),
		TotalBytes:   totalBytes,
	}, nil
}

// --- Expert events ---

func (s *MemoryStore) GetExpertEvents(minSeverity int) ([]*model.ExpertEvent, error) {
	// MemoryStore doesn't track expert events
	return nil, nil
}

// --- Lifecycle ---

func (s *MemoryStore) Close() error {
	s.closeOnce.Do(func() {
		close(s.stopCh)
	})
	return nil
}

// --- PacketReceiver implementation ---

func (s *MemoryStore) ReceiveFrom(ch <-chan *DisplayPacket) {
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				return
			}
			s.Add(pkt)
		case <-s.stopCh:
			return
		}
	}
}

func (s *MemoryStore) Stop() {
	select {
	case <-s.stopCh:
		// Already closed
	default:
		close(s.stopCh)
	}
}
