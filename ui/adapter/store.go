// Package uiadapter provides unified data access for TUI.
package uiadapter

import (
	"github.com/Zerofisher/pktanalyzer/pkg/model"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
)

// PacketReadStore provides core read-only packet access.
// All stores (MemoryStore and IndexedStore) implement this interface.
type PacketReadStore interface {
	// IsLive returns true for live capture stores (MemoryStore).
	IsLive() bool
	// IsIndexed returns true for indexed file stores (IndexedStore).
	IsIndexed() bool
	// Count returns the total number of packets in the store.
	Count() int
	// Get returns the packet with the given 1-based number, or nil if not found.
	Get(number int) *DisplayPacket
	// GetRange returns packets starting at the 0-based offset, up to limit items.
	GetRange(offset, limit int) []*DisplayPacket
	// GetRaw returns the raw bytes for the given 1-based packet number.
	// Returns (nil, nil) if raw data is unavailable.
	GetRaw(number int) ([]byte, error)
	// Close releases resources held by the store.
	Close() error
}

// PacketFilterStore provides display filter capabilities.
// Both MemoryStore and IndexedStore implement this interface.
type PacketFilterStore interface {
	// SetFilter applies a display filter expression. Pass "" to clear the filter.
	SetFilter(expr string) error
	// IsFiltered returns true when a filter expression is active.
	IsFiltered() bool
	// FilteredCount returns the number of packets matching the filter.
	// Returns Count() when no filter is active.
	FilteredCount() int
	// GetFilteredRange returns filtered packets at the 0-based offset, up to limit.
	// Falls back to GetRange when no filter is active.
	GetFilteredRange(offset, limit int) []*DisplayPacket
}

// PacketAppendStore provides write access for live capture.
// Only MemoryStore implements this; IndexedStore does not.
type PacketAppendStore interface {
	// Add appends a packet to the store. If pkt.Number is 0, a sequential
	// number is assigned automatically. Ring-buffer eviction applies when
	// the store reaches capacity.
	Add(pkt *DisplayPacket)
}

// FlowQueryable provides flow and overview query capabilities.
// Only IndexedStore implements this; MemoryStore does not.
type FlowQueryable interface {
	// GetFlows returns flows starting at offset, up to limit items.
	GetFlows(offset, limit int) ([]*model.Flow, error)
	// FlowCount returns the total number of flows.
	FlowCount() int
	// GetOverview returns aggregate capture statistics.
	GetOverview() (*query.Overview, error)
}

// EventQueryable provides expert event query capabilities.
// Only IndexedStore implements this; MemoryStore does not.
type EventQueryable interface {
	// GetExpertEvents returns events at or above minSeverity.
	GetExpertEvents(minSeverity int) ([]*model.ExpertEvent, error)
}

// PacketStore is the composite interface embedding all sub-interfaces.
// Retained during the transition period so that call sites migrating
// incrementally can still accept a single "full" store type.
// TODO: remove once all consumers use the focused interfaces.
type PacketStore interface {
	PacketReadStore
	PacketFilterStore
	PacketAppendStore
	FlowQueryable
	EventQueryable
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
