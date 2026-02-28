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
		result[i] = ConvertToPacketInfo(p)
	}
	return result
}

// GetPacketForAgent returns a single packet as capture.PacketInfo for agent tools.
func (s *IndexedStore) GetPacketForAgent(number int) *capture.PacketInfo {
	p := s.Get(number)
	if p == nil {
		return nil
	}
	pkt := ConvertToPacketInfo(p)
	return &pkt
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

