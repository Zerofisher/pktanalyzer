package uiadapter

import (
	"context"
	"fmt"

	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/pkg/model"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
	"github.com/Zerofisher/pktanalyzer/pkg/store/sqlite"
)

// IndexedStore is a PacketStore implementation that reads from SQLite index.
// It provides efficient access to large pcap files without loading everything into memory.
//
// This replaces the old IndexedProvider and implements the PacketStore interface.
type IndexedStore struct {
	engine   *query.SQLiteEngine
	store    *sqlite.SQLiteStore
	pcapPath string

	// Cached counts
	packetCount int
	flowCount   int

	// Filtering
	filterExpr string
}

// NewIndexedStore creates a new IndexedStore from a pcap file path.
// The pcap file must already be indexed (call ingest.IndexFile first).
func NewIndexedStore(pcapPath string) (*IndexedStore, error) {
	store, err := sqlite.NewFromPcap(pcapPath, true)
	if err != nil {
		return nil, fmt.Errorf("open index: %w", err)
	}

	engine := query.NewSQLiteEngine(store, pcapPath)

	// Get cached counts
	ctx := context.Background()
	packetCount, _ := engine.GetPacketCount(ctx)
	flowCount, _ := engine.GetFlowCount(ctx)

	return &IndexedStore{
		engine:      engine,
		store:       store,
		pcapPath:    pcapPath,
		packetCount: packetCount,
		flowCount:   flowCount,
	}, nil
}

// --- Mode identification ---

func (s *IndexedStore) IsLive() bool    { return false }
func (s *IndexedStore) IsIndexed() bool { return true }

// --- Packet access ---

func (s *IndexedStore) Count() int {
	return s.packetCount
}

func (s *IndexedStore) Get(number int) *DisplayPacket {
	ctx := context.Background()
	pkt, err := s.engine.GetPacket(ctx, number)
	if err != nil {
		return nil
	}
	return ConvertFromPacketSummary(pkt)
}

func (s *IndexedStore) GetRange(offset, limit int) []*DisplayPacket {
	ctx := context.Background()
	packets, err := s.engine.GetPackets(ctx, query.PacketFilter{
		Offset: offset,
		Limit:  limit,
	})
	if err != nil {
		return nil
	}

	result := make([]*DisplayPacket, len(packets))
	for i, pkt := range packets {
		result[i] = ConvertFromPacketSummary(pkt)
	}
	return result
}

func (s *IndexedStore) GetRaw(number int) ([]byte, error) {
	// TODO: Implement raw packet reading from pcap file using file offset
	// The offset is stored in PacketSummary.Evidence.FileOffset
	return nil, fmt.Errorf("raw packet reading not implemented yet")
}

// --- Agent interface (PacketReader) ---

// GetPacketsForAgent returns packets as capture.PacketInfo for agent tools.
func (s *IndexedStore) GetPacketsForAgent(offset, limit int) []capture.PacketInfo {
	packets := s.GetRange(offset, limit)
	if packets == nil {
		return nil
	}

	result := make([]capture.PacketInfo, len(packets))
	for i, p := range packets {
		result[i] = convertDisplayPacketToPacketInfo(p)
	}
	return result
}

// GetPacketForAgent returns a single packet as capture.PacketInfo for agent tools.
func (s *IndexedStore) GetPacketForAgent(number int) *capture.PacketInfo {
	p := s.Get(number)
	if p == nil {
		return nil
	}
	pkt := convertDisplayPacketToPacketInfo(p)
	return &pkt
}

// convertDisplayPacketToPacketInfo converts DisplayPacket to capture.PacketInfo.
func convertDisplayPacketToPacketInfo(p *DisplayPacket) capture.PacketInfo {
	// If we have the original RawPacketInfo, return it directly
	if p.RawPacketInfo != nil {
		return *p.RawPacketInfo
	}

	// Reconstruct from DisplayPacket fields
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

func (s *IndexedStore) Add(pkt *DisplayPacket) {
	// IndexedStore is read-only; data comes from indexing
}

// --- Filtering ---

func (s *IndexedStore) SetFilter(expr string) error {
	s.filterExpr = expr
	// TODO: Compile and validate filter expression
	return nil
}

func (s *IndexedStore) IsFiltered() bool {
	return s.filterExpr != ""
}

func (s *IndexedStore) FilteredCount() int {
	if s.filterExpr == "" {
		return s.packetCount
	}
	// TODO: Query count with filter
	return s.packetCount
}

func (s *IndexedStore) GetFilteredRange(offset, limit int) []*DisplayPacket {
	if s.filterExpr == "" {
		return s.GetRange(offset, limit)
	}
	// TODO: Apply filter to query
	return s.GetRange(offset, limit)
}

// --- Flow and statistics ---

func (s *IndexedStore) GetFlows(offset, limit int) ([]*model.Flow, error) {
	ctx := context.Background()
	return s.engine.GetFlows(ctx, query.FlowFilter{
		Offset:    offset,
		Limit:     limit,
		SortBy:    "bytes",
		SortOrder: "desc",
	})
}

func (s *IndexedStore) FlowCount() int {
	return s.flowCount
}

func (s *IndexedStore) GetOverview() (*query.Overview, error) {
	ctx := context.Background()
	return s.engine.GetOverview(ctx)
}

// --- Expert events ---

func (s *IndexedStore) GetExpertEvents(minSeverity int) ([]*model.ExpertEvent, error) {
	ctx := context.Background()
	return s.engine.GetExpertEvents(ctx, query.EventFilter{
		MinSeverity: minSeverity,
		Limit:       1000,
	})
}

// --- Lifecycle ---

func (s *IndexedStore) Close() error {
	return s.store.Close()
}

// --- Legacy compatibility ---
// These methods maintain compatibility with existing code that uses IndexedProvider.

// NewIndexedProvider creates a new IndexedStore (legacy name).
// Deprecated: Use NewIndexedStore instead.
func NewIndexedProvider(pcapPath string) (*IndexedStore, error) {
	return NewIndexedStore(pcapPath)
}

// Alias for DataProvider compatibility
type IndexedProvider = IndexedStore

// Legacy methods for DataProvider interface

func (s *IndexedStore) GetPacketCount() int {
	return s.Count()
}

func (s *IndexedStore) GetPackets(offset, limit int) ([]*DisplayPacket, error) {
	return s.GetRange(offset, limit), nil
}

func (s *IndexedStore) GetPacket(number int) (*DisplayPacket, error) {
	pkt := s.Get(number)
	if pkt == nil {
		return nil, fmt.Errorf("packet %d not found", number)
	}
	return pkt, nil
}

func (s *IndexedStore) GetRawPacket(number int) ([]byte, error) {
	return s.GetRaw(number)
}

func (s *IndexedStore) GetFlowCount() int {
	return s.FlowCount()
}

func (s *IndexedStore) GetFlow(id string) (*model.Flow, error) {
	ctx := context.Background()
	return s.engine.GetFlow(ctx, id)
}

func (s *IndexedStore) GetExpertEventCount() int {
	return 0 // TODO: Implement
}

func (s *IndexedStore) GetStats() *Stats {
	return NewStats()
}

func (s *IndexedStore) ReceivePacket() <-chan *DisplayPacket {
	return nil // Not applicable for indexed mode
}
