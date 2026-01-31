// Package uiadapter provides unified data access for TUI.
package uiadapter

import (
	"github.com/Zerofisher/pktanalyzer/pkg/model"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
)

// PacketStore provides unified packet storage for the TUI.
// It abstracts the difference between memory mode (live capture) and indexed mode (file analysis).
//
// Design principles:
//   - Single source of truth: all packet access goes through this interface
//   - No data duplication: raw data stays in pcap file or ring buffer
//   - Pagination: large datasets accessed via GetRange, not loaded entirely
//   - Lazy loading: raw packet data loaded on demand via GetRaw
type PacketStore interface {
	// Mode identification
	IsLive() bool
	IsIndexed() bool

	// --- Packet access ---

	// Count returns the total number of packets.
	Count() int

	// Get returns a single packet by number (1-based).
	// Returns nil if number is out of range.
	Get(number int) *DisplayPacket

	// GetRange returns packets in the given range (0-based offset, limit).
	// This is the preferred method for displaying packet lists.
	GetRange(offset, limit int) []*DisplayPacket

	// GetRaw returns raw packet bytes by number (1-based).
	// For IndexedStore, this reads from the pcap file.
	// For MemoryStore, this returns data from the ring buffer.
	GetRaw(number int) ([]byte, error)

	// --- Write operations (for live capture) ---

	// Add appends a packet to the store.
	// For IndexedStore, this is a no-op (data comes from indexing).
	// For MemoryStore, this adds to the ring buffer.
	Add(pkt *DisplayPacket)

	// --- Filtering ---

	// SetFilter sets the display filter expression.
	// Pass empty string to clear the filter.
	SetFilter(expr string) error

	// IsFiltered returns true if a filter is active.
	IsFiltered() bool

	// FilteredCount returns the number of packets matching the current filter.
	// Returns Count() if no filter is active.
	FilteredCount() int

	// GetFilteredRange returns filtered packets in the given range.
	// Returns GetRange() if no filter is active.
	GetFilteredRange(offset, limit int) []*DisplayPacket

	// --- Flow and statistics (optional, may return nil/zero) ---

	// GetFlows returns flows in the given range.
	GetFlows(offset, limit int) ([]*model.Flow, error)

	// FlowCount returns the total number of flows.
	FlowCount() int

	// GetOverview returns capture statistics.
	GetOverview() (*query.Overview, error)

	// --- Expert events (optional) ---

	// GetExpertEvents returns expert events at or above the given severity.
	GetExpertEvents(minSeverity int) ([]*model.ExpertEvent, error)

	// --- Lifecycle ---

	// Close releases resources.
	Close() error
}

// PacketReceiver is implemented by stores that can receive packets from a channel.
// Only MemoryStore implements this; IndexedStore does not.
type PacketReceiver interface {
	// ReceiveFrom starts receiving packets from the given channel.
	// This method blocks until the channel is closed or Stop is called.
	ReceiveFrom(ch <-chan *DisplayPacket)

	// Stop stops receiving packets.
	Stop()
}
