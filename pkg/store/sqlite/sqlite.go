// Package sqlite provides the SQLite implementation of store.Store.
package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/Zerofisher/pktanalyzer/pkg/model"
)

// SQLite schema version for migrations.
const schemaVersion = 1

// Config holds configuration for the SQLite store.
type Config struct {
	// Path to the SQLite database file.
	// If empty, defaults to <pcapfile>.idx.db
	DBPath string
	
	// ReadOnly opens the database in read-only mode.
	ReadOnly bool
	
	// WAL enables WAL mode for better concurrency.
	WAL bool
}

// SQLiteStore is the SQLite implementation of store.Store.
type SQLiteStore struct {
	db   *sql.DB
	path string
	cfg  Config
	
	// Write transaction state
	mu    sync.Mutex
	tx    *sql.Tx
	stmts map[string]*sql.Stmt // Prepared statements within tx
}

// New creates a new SQLite store.
func New(cfg Config) (*SQLiteStore, error) {
	// Ensure directory exists
	dir := filepath.Dir(cfg.DBPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}
	
	// Build DSN
	dsn := cfg.DBPath
	params := "?_foreign_keys=on"
	if cfg.ReadOnly {
		params += "&mode=ro"
	}
	if cfg.WAL {
		params += "&_journal_mode=WAL"
	}
	dsn += params
	
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	
	// Set connection pool (single writer is best practice for SQLite)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	
	s := &SQLiteStore{
		db:    db,
		path:  cfg.DBPath,
		cfg:   cfg,
		stmts: make(map[string]*sql.Stmt),
	}
	
	// Initialize schema
	if !cfg.ReadOnly {
		if err := s.initSchema(); err != nil {
			db.Close()
			return nil, fmt.Errorf("init schema: %w", err)
		}
	}
	
	return s, nil
}

// NewFromPcap creates a store with the standard naming convention.
func NewFromPcap(pcapPath string, readOnly bool) (*SQLiteStore, error) {
	dbPath := pcapPath + ".idx.db"
	return New(Config{
		DBPath:   dbPath,
		ReadOnly: readOnly,
		WAL:      !readOnly,
	})
}

// Close closes the database.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// Path returns the database file path.
func (s *SQLiteStore) Path() string {
	return s.path
}

// DB returns the underlying database connection for direct queries.
// Use with caution - prefer using the Store interface methods.
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

// ────────────────────────────────────────────────────────────────────────────────
// Schema Initialization
// ────────────────────────────────────────────────────────────────────────────────

func (s *SQLiteStore) initSchema() error {
	schema := `
-- Meta table for index metadata
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT
);

-- Packets table (summaries only, no raw data)
CREATE TABLE IF NOT EXISTS packets (
	number       INTEGER PRIMARY KEY,
	timestamp_ns INTEGER NOT NULL,
	length       INTEGER NOT NULL,
	cap_length   INTEGER NOT NULL,
	src_mac      TEXT,
	dst_mac      TEXT,
	eth_type     INTEGER,
	src_ip       TEXT,
	dst_ip       TEXT,
	ip_version   INTEGER,
	ip_proto     INTEGER,
	ttl          INTEGER,
	src_port     INTEGER,
	dst_port     INTEGER,
	tcp_flags    INTEGER,
	tcp_seq      INTEGER,
	tcp_ack      INTEGER,
	tcp_window   INTEGER,
	protocol     TEXT,
	info         TEXT,
	flow_id      TEXT,
	file_offset  INTEGER,
	file_path    TEXT
);

-- Flows table
CREATE TABLE IF NOT EXISTS flows (
	id           TEXT PRIMARY KEY,
	src_ip       TEXT NOT NULL,
	dst_ip       TEXT NOT NULL,
	src_port     INTEGER,
	dst_port     INTEGER,
	protocol     TEXT NOT NULL,
	state        TEXT NOT NULL DEFAULT 'unknown',
	start_ns     INTEGER NOT NULL,
	end_ns       INTEGER,
	packets      INTEGER NOT NULL DEFAULT 0,
	bytes        INTEGER NOT NULL DEFAULT 0,
	fwd_packets  INTEGER NOT NULL DEFAULT 0,
	fwd_bytes    INTEGER NOT NULL DEFAULT 0,
	bwd_packets  INTEGER NOT NULL DEFAULT 0,
	bwd_bytes    INTEGER NOT NULL DEFAULT 0,
	retrans      INTEGER NOT NULL DEFAULT 0,
	rtt_samples  TEXT,     -- JSON array of RTT samples
	rtt_avg_us   INTEGER,
	rtt_min_us   INTEGER,
	rtt_max_us   INTEGER,
	metadata     TEXT      -- JSON for protocol-specific data
);

-- Transactions table (request/response pairs)
CREATE TABLE IF NOT EXISTS transactions (
	id               TEXT PRIMARY KEY,
	type             TEXT NOT NULL,
	flow_id          TEXT NOT NULL,
	start_ns         INTEGER NOT NULL,
	end_ns           INTEGER,
	request_packets  TEXT,  -- JSON array of packet numbers
	response_packets TEXT,  -- JSON array of packet numbers
	status           TEXT,
	latency_us       INTEGER,
	metadata         TEXT,
	FOREIGN KEY (flow_id) REFERENCES flows(id)
);

-- Expert events table
CREATE TABLE IF NOT EXISTS expert_events (
	id           TEXT PRIMARY KEY,
	timestamp_ns INTEGER NOT NULL,
	severity     INTEGER NOT NULL,
	grp          TEXT NOT NULL,
	type         TEXT NOT NULL,
	message      TEXT NOT NULL,
	detail       TEXT,
	flow_id      TEXT,
	packet_start INTEGER,
	packet_end   INTEGER,
	FOREIGN KEY (flow_id) REFERENCES flows(id)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_packets_flow ON packets(flow_id);
CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip);
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);

CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_protocol ON flows(protocol);
CREATE INDEX IF NOT EXISTS idx_flows_bytes ON flows(bytes DESC);
CREATE INDEX IF NOT EXISTS idx_flows_retrans ON flows(retrans DESC);

CREATE INDEX IF NOT EXISTS idx_transactions_flow ON transactions(flow_id);
CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type);

CREATE INDEX IF NOT EXISTS idx_expert_severity ON expert_events(severity);
CREATE INDEX IF NOT EXISTS idx_expert_flow ON expert_events(flow_id);
CREATE INDEX IF NOT EXISTS idx_expert_type ON expert_events(type);
`
	
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("execute schema: %w", err)
	}
	
	// Set schema version
	_, err = s.db.Exec(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)`,
		"schema_version", fmt.Sprintf("%d", schemaVersion))
	return err
}

// ────────────────────────────────────────────────────────────────────────────────
// Metadata Operations
// ────────────────────────────────────────────────────────────────────────────────

// GetMeta retrieves the index metadata.
func (s *SQLiteStore) GetMeta() (*model.IndexMeta, error) {
	meta := &model.IndexMeta{}
	
	rows, err := s.db.Query(`SELECT key, value FROM meta`)
	if err != nil {
		return nil, fmt.Errorf("query meta: %w", err)
	}
	defer rows.Close()
	
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		switch key {
		case "schema_version":
			fmt.Sscanf(value, "%d", &meta.SchemaVersion)
		case "pcap_path":
			meta.PcapPath = value
		case "pcap_size":
			fmt.Sscanf(value, "%d", &meta.PcapSize)
		case "pcap_modified":
			t, _ := time.Parse(time.RFC3339Nano, value)
			meta.PcapModified = t
		case "indexed_at":
			t, _ := time.Parse(time.RFC3339Nano, value)
			meta.IndexedAt = t
		case "total_packets":
			fmt.Sscanf(value, "%d", &meta.TotalPackets)
		case "total_bytes":
			fmt.Sscanf(value, "%d", &meta.TotalBytes)
		case "duration_ns":
			fmt.Sscanf(value, "%d", &meta.DurationNS)
		case "index_complete":
			meta.IndexComplete = value == "true"
		}
	}
	
	return meta, rows.Err()
}

// SetMeta stores the index metadata.
func (s *SQLiteStore) SetMeta(meta *model.IndexMeta) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	
	stmt, err := tx.Prepare(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	
	pairs := []struct{ k, v string }{
		{"schema_version", fmt.Sprintf("%d", meta.SchemaVersion)},
		{"pcap_path", meta.PcapPath},
		{"pcap_size", fmt.Sprintf("%d", meta.PcapSize)},
		{"pcap_modified", meta.PcapModified.Format(time.RFC3339Nano)},
		{"indexed_at", meta.IndexedAt.Format(time.RFC3339Nano)},
		{"total_packets", fmt.Sprintf("%d", meta.TotalPackets)},
		{"total_bytes", fmt.Sprintf("%d", meta.TotalBytes)},
		{"duration_ns", fmt.Sprintf("%d", meta.DurationNS)},
		{"index_complete", fmt.Sprintf("%t", meta.IndexComplete)},
	}
	
	for _, p := range pairs {
		if _, err := stmt.Exec(p.k, p.v); err != nil {
			return err
		}
	}
	
	return tx.Commit()
}

// ────────────────────────────────────────────────────────────────────────────────
// Batch Write Operations
// ────────────────────────────────────────────────────────────────────────────────

// BeginBatch starts a batch write transaction.
func (s *SQLiteStore) BeginBatch() error {
	s.mu.Lock()
	if s.tx != nil {
		s.mu.Unlock()
		return fmt.Errorf("batch already in progress")
	}
	
	tx, err := s.db.Begin()
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.tx = tx
	s.stmts = make(map[string]*sql.Stmt)
	s.mu.Unlock()
	return nil
}

// CommitBatch commits the current batch.
func (s *SQLiteStore) CommitBatch() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.tx == nil {
		return fmt.Errorf("no batch in progress")
	}
	
	// Close prepared statements
	for _, stmt := range s.stmts {
		stmt.Close()
	}
	s.stmts = nil
	
	err := s.tx.Commit()
	s.tx = nil
	return err
}

// RollbackBatch rolls back the current batch.
func (s *SQLiteStore) RollbackBatch() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.tx == nil {
		return nil
	}
	
	for _, stmt := range s.stmts {
		stmt.Close()
	}
	s.stmts = nil
	
	err := s.tx.Rollback()
	s.tx = nil
	return err
}

func (s *SQLiteStore) getStmt(name, query string) (*sql.Stmt, error) {
	if stmt, ok := s.stmts[name]; ok {
		return stmt, nil
	}
	
	stmt, err := s.tx.Prepare(query)
	if err != nil {
		return nil, err
	}
	s.stmts[name] = stmt
	return stmt, nil
}

// InsertPacket inserts a single packet summary.
func (s *SQLiteStore) InsertPacket(p *model.PacketSummary) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.tx == nil {
		return fmt.Errorf("no batch in progress")
	}
	
	const query = `INSERT INTO packets (
		number, timestamp_ns, length, cap_length,
		src_mac, dst_mac, eth_type,
		src_ip, dst_ip, ip_version, ip_proto, ttl,
		src_port, dst_port, tcp_flags, tcp_seq, tcp_ack, tcp_window,
		protocol, info, flow_id, file_offset, file_path
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	stmt, err := s.getStmt("insert_packet", query)
	if err != nil {
		return err
	}
	
	_, err = stmt.Exec(
		p.Number, p.TimestampNS, p.Length, p.CaptureLength,
		p.SrcMAC, p.DstMAC, p.EthType,
		p.SrcIP, p.DstIP, p.IPVersion, p.IPProto, p.TTL,
		p.SrcPort, p.DstPort, p.TCPFlags, p.TCPSeq, p.TCPAck, p.TCPWindow,
		p.Protocol, p.Info, p.FlowID,
		p.Evidence.FileOffset, p.Evidence.FilePath,
	)
	return err
}

// InsertPackets inserts multiple packet summaries.
func (s *SQLiteStore) InsertPackets(packets []*model.PacketSummary) error {
	for _, p := range packets {
		if err := s.InsertPacket(p); err != nil {
			return err
		}
	}
	return nil
}

// UpsertFlow inserts or updates a flow.
func (s *SQLiteStore) UpsertFlow(f *model.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.tx == nil {
		return fmt.Errorf("no batch in progress")
	}
	
	rttJSON, _ := json.Marshal(f.RTTSamples)
	metaJSON, _ := json.Marshal(f.Metadata)
	
	const query = `INSERT INTO flows (
		id, src_ip, dst_ip, src_port, dst_port, protocol, state,
		start_ns, end_ns, packets, bytes,
		fwd_packets, fwd_bytes, bwd_packets, bwd_bytes,
		retrans, rtt_samples, rtt_avg_us, rtt_min_us, rtt_max_us, metadata
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		state = excluded.state,
		end_ns = excluded.end_ns,
		packets = excluded.packets,
		bytes = excluded.bytes,
		fwd_packets = excluded.fwd_packets,
		fwd_bytes = excluded.fwd_bytes,
		bwd_packets = excluded.bwd_packets,
		bwd_bytes = excluded.bwd_bytes,
		retrans = excluded.retrans,
		rtt_samples = excluded.rtt_samples,
		rtt_avg_us = excluded.rtt_avg_us,
		rtt_min_us = excluded.rtt_min_us,
		rtt_max_us = excluded.rtt_max_us,
		metadata = excluded.metadata`
	
	stmt, err := s.getStmt("upsert_flow", query)
	if err != nil {
		return err
	}
	
	_, err = stmt.Exec(
		f.ID, f.SrcIP, f.DstIP, f.SrcPort, f.DstPort, f.Protocol, f.State,
		f.StartNS, f.EndNS, f.Packets, f.Bytes,
		f.FwdPackets, f.FwdBytes, f.BwdPackets, f.BwdBytes,
		f.Retrans, string(rttJSON), f.RTTAvgUS, f.RTTMinUS, f.RTTMaxUS,
		string(metaJSON),
	)
	return err
}

// UpsertFlows inserts or updates multiple flows.
func (s *SQLiteStore) UpsertFlows(flows []*model.Flow) error {
	for _, f := range flows {
		if err := s.UpsertFlow(f); err != nil {
			return err
		}
	}
	return nil
}

// InsertTransaction inserts a transaction.
func (s *SQLiteStore) InsertTransaction(t *model.Transaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.tx == nil {
		return fmt.Errorf("no batch in progress")
	}
	
	reqJSON, _ := json.Marshal(t.RequestPackets)
	respJSON, _ := json.Marshal(t.ResponsePackets)
	metaJSON, _ := json.Marshal(t.Metadata)
	
	const query = `INSERT INTO transactions (
		id, type, flow_id, start_ns, end_ns,
		request_packets, response_packets, status, latency_us, metadata
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	stmt, err := s.getStmt("insert_transaction", query)
	if err != nil {
		return err
	}
	
	_, err = stmt.Exec(
		t.ID, t.Type, t.FlowID, t.StartNS, t.EndNS,
		string(reqJSON), string(respJSON), t.Status, t.LatencyUS,
		string(metaJSON),
	)
	return err
}

// InsertExpertEvent inserts an expert event.
func (s *SQLiteStore) InsertExpertEvent(e *model.ExpertEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.tx == nil {
		return fmt.Errorf("no batch in progress")
	}
	
	const query = `INSERT INTO expert_events (
		id, timestamp_ns, severity, grp, type, message, detail, flow_id, packet_start, packet_end
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	stmt, err := s.getStmt("insert_expert", query)
	if err != nil {
		return err
	}
	
	_, err = stmt.Exec(
		e.ID, e.TimestampNS, e.Severity.Order(), e.Group, e.Type,
		e.Message, e.Summary, e.FlowID, e.PacketStart, e.PacketEnd,
	)
	return err
}

// InsertExpertEvents inserts multiple expert events.
func (s *SQLiteStore) InsertExpertEvents(events []*model.ExpertEvent) error {
	for _, e := range events {
		if err := s.InsertExpertEvent(e); err != nil {
			return err
		}
	}
	return nil
}
