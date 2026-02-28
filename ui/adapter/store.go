// Package uiadapter provides unified data access for TUI.
package uiadapter

import (
	"github.com/Zerofisher/pktanalyzer/pkg/model"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
)

// PacketReadStore provides core read-only packet access.
type PacketReadStore interface {
	IsLive() bool
	IsIndexed() bool
	Count() int
	Get(number int) *DisplayPacket
	GetRange(offset, limit int) []*DisplayPacket
	GetRaw(number int) ([]byte, error)
	Close() error
}

// PacketFilterStore provides display filter capabilities.
type PacketFilterStore interface {
	SetFilter(expr string) error
	IsFiltered() bool
	FilteredCount() int
	GetFilteredRange(offset, limit int) []*DisplayPacket
}

// PacketAppendStore provides write access (live capture only).
type PacketAppendStore interface {
	Add(pkt *DisplayPacket)
}

// FlowQueryable provides flow query capabilities (indexed mode only).
type FlowQueryable interface {
	GetFlows(offset, limit int) ([]*model.Flow, error)
	FlowCount() int
	GetOverview() (*query.Overview, error)
}

// EventQueryable provides expert event capabilities (indexed mode only).
type EventQueryable interface {
	GetExpertEvents(minSeverity int) ([]*model.ExpertEvent, error)
}

// PacketStore is the composite interface for backward compatibility.
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
