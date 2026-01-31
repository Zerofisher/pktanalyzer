// Package store defines the storage interface and SQLite implementation.
package store

import (
	"github.com/Zerofisher/pktanalyzer/pkg/model"
)

// SchemaVersion is incremented when schema changes require re-indexing.
const SchemaVersion = 1

// Store defines the interface for packet index storage.
type Store interface {
	// Lifecycle
	Close() error

	// Metadata
	GetMeta() (*model.IndexMeta, error)
	SetMeta(meta *model.IndexMeta) error

	// Write operations (used by ingest pipeline)
	Writer
}

// Writer defines write-side operations for the ingest pipeline.
type Writer interface {
	// BeginBatch starts a batch write transaction.
	BeginBatch() error
	
	// CommitBatch commits the current batch.
	CommitBatch() error
	
	// RollbackBatch rolls back the current batch.
	RollbackBatch() error
	
	// InsertPacket inserts a packet summary.
	InsertPacket(p *model.PacketSummary) error
	
	// InsertPackets inserts multiple packet summaries (batch optimized).
	InsertPackets(packets []*model.PacketSummary) error
	
	// UpsertFlow inserts or updates a flow.
	UpsertFlow(f *model.Flow) error
	
	// UpsertFlows inserts or updates multiple flows.
	UpsertFlows(flows []*model.Flow) error
	
	// InsertTransaction inserts a transaction.
	InsertTransaction(t *model.Transaction) error
	
	// InsertExpertEvent inserts an expert event.
	InsertExpertEvent(e *model.ExpertEvent) error
	
	// InsertExpertEvents inserts multiple expert events.
	InsertExpertEvents(events []*model.ExpertEvent) error
}

