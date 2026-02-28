package uiadapter

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Zerofisher/pktanalyzer/pkg/model"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
	"github.com/Zerofisher/pktanalyzer/pkg/store/sqlite"
)

// IndexedStore provides read-only access to packets indexed in SQLite.
// It implements PacketReadStore, PacketFilterStore, FlowQueryable, and EventQueryable.
// It provides efficient access to large pcap files without loading everything into memory.
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
	// Look up packet to get evidence
	ctx := context.Background()
	pkt, err := s.engine.GetPacket(ctx, number)
	if err != nil {
		return nil, fmt.Errorf("get packet %d: %w", number, err)
	}

	if pkt.Evidence.FilePath == "" {
		return nil, fmt.Errorf("no file path for packet %d", number)
	}
	if pkt.Evidence.FileOffset <= 0 {
		return nil, fmt.Errorf("no file offset for packet %d (indexed before offset tracking)", number)
	}

	// Detect pcapng by extension — offset tracking is not reliable for pcapng
	if strings.HasSuffix(pkt.Evidence.FilePath, ".pcapng") {
		return nil, fmt.Errorf("raw read not supported for pcapng files")
	}

	// Open pcap file and seek to packet data
	f, err := os.Open(pkt.Evidence.FilePath)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	defer f.Close()

	// FileOffset points to pcap record header (16 bytes), skip it to get to data
	dataOffset := pkt.Evidence.FileOffset + 16
	if _, err := f.Seek(dataOffset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek to packet data: %w", err)
	}

	buf := make([]byte, pkt.CaptureLength)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, fmt.Errorf("read packet data: %w", err)
	}

	return buf, nil
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

