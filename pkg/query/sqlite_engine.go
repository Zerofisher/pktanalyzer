// Package query provides unified query interfaces for TUI and AI modules.
package query

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Zerofisher/pktanalyzer/pkg/model"
	"github.com/Zerofisher/pktanalyzer/pkg/store/sqlite"
)

// SQLiteEngine implements QueryEngine using SQLite storage.
type SQLiteEngine struct {
	store    *sqlite.SQLiteStore
	pcapPath string
}

// NewSQLiteEngine creates a new SQLite-backed query engine.
func NewSQLiteEngine(store *sqlite.SQLiteStore, pcapPath string) *SQLiteEngine {
	return &SQLiteEngine{
		store:    store,
		pcapPath: pcapPath,
	}
}

// NewFromPcap opens an existing index for a pcap file.
func NewFromPcap(pcapPath string) (*SQLiteEngine, error) {
	store, err := sqlite.NewFromPcap(pcapPath, true) // read-only
	if err != nil {
		return nil, fmt.Errorf("open index: %w", err)
	}
	return NewSQLiteEngine(store, pcapPath), nil
}

// Close closes the underlying store.
func (e *SQLiteEngine) Close() error {
	return e.store.Close()
}

// GetPacket retrieves a single packet by number.
func (e *SQLiteEngine) GetPacket(ctx context.Context, number int) (*model.PacketSummary, error) {
	row := e.store.DB().QueryRowContext(ctx, `
		SELECT number, timestamp_ns, length, cap_length,
		       src_mac, dst_mac, eth_type,
		       src_ip, dst_ip, ip_version, ip_proto, ttl,
		       src_port, dst_port, tcp_flags, tcp_seq, tcp_ack, tcp_window,
		       protocol, info, flow_id, file_offset, file_path
		FROM packets WHERE number = ?`, number)

	return scanPacket(row)
}

// GetPackets retrieves packets with optional filtering.
func (e *SQLiteEngine) GetPackets(ctx context.Context, filter PacketFilter) ([]*model.PacketSummary, error) {
	query := `SELECT number, timestamp_ns, length, cap_length,
	                 src_mac, dst_mac, eth_type,
	                 src_ip, dst_ip, ip_version, ip_proto, ttl,
	                 src_port, dst_port, tcp_flags, tcp_seq, tcp_ack, tcp_window,
	                 protocol, info, flow_id, file_offset, file_path
	          FROM packets WHERE 1=1`

	args := []interface{}{}

	if filter.SrcIP != "" {
		query += " AND src_ip = ?"
		args = append(args, filter.SrcIP)
	}
	if filter.DstIP != "" {
		query += " AND dst_ip = ?"
		args = append(args, filter.DstIP)
	}
	if filter.IP != "" {
		query += " AND (src_ip = ? OR dst_ip = ?)"
		args = append(args, filter.IP, filter.IP)
	}
	if filter.Protocol != "" {
		query += " AND protocol = ?"
		args = append(args, filter.Protocol)
	}
	if filter.FlowID != "" {
		query += " AND flow_id = ?"
		args = append(args, filter.FlowID)
	}
	if filter.SearchText != "" {
		query += " AND info LIKE ?"
		args = append(args, "%"+filter.SearchText+"%")
	}
	if !filter.StartTime.IsZero() {
		query += " AND timestamp_ns >= ?"
		args = append(args, filter.StartTime.UnixNano())
	}
	if !filter.EndTime.IsZero() {
		query += " AND timestamp_ns <= ?"
		args = append(args, filter.EndTime.UnixNano())
	}

	// Sorting
	sortCol := "number"
	if filter.SortBy != "" {
		switch filter.SortBy {
		case "timestamp":
			sortCol = "timestamp_ns"
		case "protocol":
			sortCol = "protocol"
		case "length":
			sortCol = "length"
		}
	}
	sortOrder := "ASC"
	if filter.SortOrder == "desc" {
		sortOrder = "DESC"
	}
	query += fmt.Sprintf(" ORDER BY %s %s", sortCol, sortOrder)

	// Pagination
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := e.store.DB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query packets: %w", err)
	}
	defer rows.Close()

	var packets []*model.PacketSummary
	for rows.Next() {
		pkt, err := scanPacketRow(rows)
		if err != nil {
			return nil, err
		}
		packets = append(packets, pkt)
	}
	return packets, rows.Err()
}

// GetPacketCount returns total packet count.
func (e *SQLiteEngine) GetPacketCount(ctx context.Context) (int, error) {
	var count int
	err := e.store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM packets").Scan(&count)
	return count, err
}

// GetFlow retrieves a single flow by ID.
func (e *SQLiteEngine) GetFlow(ctx context.Context, id string) (*model.Flow, error) {
	row := e.store.DB().QueryRowContext(ctx, `
		SELECT id, src_ip, dst_ip, src_port, dst_port, protocol, state,
		       start_ns, end_ns, packets, bytes,
		       fwd_packets, fwd_bytes, bwd_packets, bwd_bytes,
		       retrans, rtt_samples, rtt_avg_us, rtt_min_us, rtt_max_us, metadata
		FROM flows WHERE id = ?`, id)

	return scanFlow(row)
}

// GetFlows retrieves flows with optional filtering.
func (e *SQLiteEngine) GetFlows(ctx context.Context, filter FlowFilter) ([]*model.Flow, error) {
	query := `SELECT id, src_ip, dst_ip, src_port, dst_port, protocol, state,
	                 start_ns, end_ns, packets, bytes,
	                 fwd_packets, fwd_bytes, bwd_packets, bwd_bytes,
	                 retrans, rtt_samples, rtt_avg_us, rtt_min_us, rtt_max_us, metadata
	          FROM flows WHERE 1=1`

	args := []interface{}{}

	if filter.IP != "" {
		query += " AND (src_ip = ? OR dst_ip = ?)"
		args = append(args, filter.IP, filter.IP)
	}
	if filter.Protocol != "" {
		query += " AND protocol = ?"
		args = append(args, filter.Protocol)
	}
	if filter.MinPackets > 0 {
		query += " AND packets >= ?"
		args = append(args, filter.MinPackets)
	}
	if filter.MinBytes > 0 {
		query += " AND bytes >= ?"
		args = append(args, filter.MinBytes)
	}

	// Sorting
	sortCol := "bytes"
	if filter.SortBy != "" {
		switch filter.SortBy {
		case "packets":
			sortCol = "packets"
		case "start_time":
			sortCol = "start_ns"
		case "duration":
			sortCol = "end_ns - start_ns"
		}
	}
	sortOrder := "DESC"
	if filter.SortOrder == "asc" {
		sortOrder = "ASC"
	}
	query += fmt.Sprintf(" ORDER BY %s %s", sortCol, sortOrder)

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := e.store.DB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query flows: %w", err)
	}
	defer rows.Close()

	var flows []*model.Flow
	for rows.Next() {
		flow, err := scanFlowRow(rows)
		if err != nil {
			return nil, err
		}
		flows = append(flows, flow)
	}
	return flows, rows.Err()
}

// GetFlowCount returns total flow count.
func (e *SQLiteEngine) GetFlowCount(ctx context.Context) (int, error) {
	var count int
	err := e.store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM flows").Scan(&count)
	return count, err
}

// GetFlowPackets returns packets for a specific flow.
func (e *SQLiteEngine) GetFlowPackets(ctx context.Context, flowID string, limit int) ([]*model.PacketSummary, error) {
	return e.GetPackets(ctx, PacketFilter{
		FlowID: flowID,
		Limit:  limit,
	})
}

// GetExpertEvents retrieves expert events with optional filtering.
func (e *SQLiteEngine) GetExpertEvents(ctx context.Context, filter EventFilter) ([]*model.ExpertEvent, error) {
	query := `SELECT id, timestamp_ns, severity, grp, type, message, detail, flow_id, packet_start, packet_end
	          FROM expert_events WHERE 1=1`

	args := []interface{}{}

	if filter.MinSeverity > 0 {
		query += " AND severity >= ?"
		args = append(args, filter.MinSeverity)
	}
	if len(filter.Categories) > 0 {
		placeholders := strings.Repeat("?,", len(filter.Categories))
		placeholders = placeholders[:len(placeholders)-1]
		query += fmt.Sprintf(" AND grp IN (%s)", placeholders)
		for _, cat := range filter.Categories {
			args = append(args, cat)
		}
	}
	if filter.SearchText != "" {
		query += " AND message LIKE ?"
		args = append(args, "%"+filter.SearchText+"%")
	}

	sortCol := "severity"
	if filter.SortBy != "" {
		switch filter.SortBy {
		case "timestamp":
			sortCol = "timestamp_ns"
		case "category":
			sortCol = "grp"
		}
	}
	sortOrder := "DESC"
	if filter.SortOrder == "asc" {
		sortOrder = "ASC"
	}
	query += fmt.Sprintf(" ORDER BY %s %s", sortCol, sortOrder)

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := e.store.DB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query expert events: %w", err)
	}
	defer rows.Close()

	var events []*model.ExpertEvent
	for rows.Next() {
		event, err := scanEventRow(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// GetExpertEventsByFlow returns events for a specific flow.
func (e *SQLiteEngine) GetExpertEventsByFlow(ctx context.Context, flowID string) ([]*model.ExpertEvent, error) {
	return e.GetExpertEvents(ctx, EventFilter{FlowID: flowID})
}

// GetExpertEventsByPacket returns events that reference a specific packet.
func (e *SQLiteEngine) GetExpertEventsByPacket(ctx context.Context, packetNum int) ([]*model.ExpertEvent, error) {
	rows, err := e.store.DB().QueryContext(ctx, `
		SELECT id, timestamp_ns, severity, grp, type, message, detail, flow_id, packet_start, packet_end
		FROM expert_events
		WHERE packet_start <= ? AND packet_end >= ?`,
		packetNum, packetNum)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*model.ExpertEvent
	for rows.Next() {
		event, err := scanEventRow(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// GetEventSummary returns a summary of expert events.
func (e *SQLiteEngine) GetEventSummary(ctx context.Context) (*EventSummary, error) {
	summary := &EventSummary{
		BySeverity: make(map[string]int),
		ByCategory: make(map[string]int),
	}

	// Count by severity
	rows, err := e.store.DB().QueryContext(ctx, `
		SELECT severity, COUNT(*) FROM expert_events GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev, count int
		if err := rows.Scan(&sev, &count); err != nil {
			rows.Close()
			return nil, err
		}
		summary.TotalEvents += count
		switch sev {
		case 4:
			summary.BySeverity["error"] = count
		case 3:
			summary.BySeverity["warning"] = count
		case 2:
			summary.BySeverity["note"] = count
		case 1:
			summary.BySeverity["chat"] = count
		}
	}
	rows.Close()

	// Count by category
	rows, err = e.store.DB().QueryContext(ctx, `
		SELECT grp, COUNT(*) FROM expert_events GROUP BY grp`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var grp string
		var count int
		if err := rows.Scan(&grp, &count); err != nil {
			rows.Close()
			return nil, err
		}
		summary.ByCategory[grp] = count
	}
	rows.Close()

	// Top events
	summary.TopEvents, _ = e.GetExpertEvents(ctx, EventFilter{
		Limit:   10,
		SortBy:  "severity",
	})

	return summary, nil
}

// GetProtocolStats returns protocol distribution statistics.
func (e *SQLiteEngine) GetProtocolStats(ctx context.Context) ([]*ProtocolStat, error) {
	rows, err := e.store.DB().QueryContext(ctx, `
		SELECT protocol, COUNT(*) as cnt, SUM(length) as total_bytes
		FROM packets
		GROUP BY protocol
		ORDER BY cnt DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []*ProtocolStat
	var totalPackets int
	for rows.Next() {
		var stat ProtocolStat
		if err := rows.Scan(&stat.Protocol, &stat.Packets, &stat.Bytes); err != nil {
			return nil, err
		}
		totalPackets += stat.Packets
		stats = append(stats, &stat)
	}

	// Calculate percentages
	for _, stat := range stats {
		if totalPackets > 0 {
			stat.Percent = float64(stat.Packets) / float64(totalPackets) * 100
		}
	}

	return stats, rows.Err()
}

// GetTopTalkers returns hosts with highest traffic.
func (e *SQLiteEngine) GetTopTalkers(ctx context.Context, limit int) ([]*TopTalker, error) {
	rows, err := e.store.DB().QueryContext(ctx, `
		SELECT ip, SUM(packets) as pkts, SUM(bytes) as total_bytes, COUNT(*) as flow_count
		FROM (
			SELECT src_ip as ip, packets, bytes FROM flows
			UNION ALL
			SELECT dst_ip as ip, packets, bytes FROM flows
		)
		GROUP BY ip
		ORDER BY total_bytes DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var talkers []*TopTalker
	for rows.Next() {
		var t TopTalker
		if err := rows.Scan(&t.IP, &t.Packets, &t.Bytes, &t.Flows); err != nil {
			return nil, err
		}
		talkers = append(talkers, &t)
	}
	return talkers, rows.Err()
}

// GetOverview returns high-level summary.
func (e *SQLiteEngine) GetOverview(ctx context.Context) (*Overview, error) {
	overview := &Overview{
		PcapPath: e.pcapPath,
	}

	// Get meta
	meta, err := e.store.GetMeta()
	if err == nil {
		overview.IndexedAt = meta.IndexedAt
		overview.TotalPackets = meta.TotalPackets
		overview.TotalBytes = meta.TotalBytes
		overview.Duration = time.Duration(meta.DurationNS)
	}

	// Get time range from packets
	row := e.store.DB().QueryRowContext(ctx, `
		SELECT MIN(timestamp_ns), MAX(timestamp_ns) FROM packets`)
	var minNS, maxNS sql.NullInt64
	row.Scan(&minNS, &maxNS)
	if minNS.Valid && maxNS.Valid {
		overview.StartTime = time.Unix(0, minNS.Int64)
		overview.EndTime = time.Unix(0, maxNS.Int64)
		overview.Duration = overview.EndTime.Sub(overview.StartTime)
	}

	// Calculate rates
	if overview.Duration > 0 {
		secs := overview.Duration.Seconds()
		overview.PacketsPerSec = float64(overview.TotalPackets) / secs
		overview.BytesPerSec = float64(overview.TotalBytes) / secs
	}
	if overview.TotalPackets > 0 {
		overview.AvgPacketSize = float64(overview.TotalBytes) / float64(overview.TotalPackets)
	}

	// Flow count
	overview.TotalFlows, _ = e.GetFlowCount(ctx)

	// Event counts
	eventSummary, _ := e.GetEventSummary(ctx)
	if eventSummary != nil {
		overview.ErrorEvents = eventSummary.BySeverity["error"]
		overview.WarningEvents = eventSummary.BySeverity["warning"]
		overview.NoteEvents = eventSummary.BySeverity["note"]
	}

	// Top protocols
	overview.TopProtocols, _ = e.GetProtocolStats(ctx)
	if len(overview.TopProtocols) > 5 {
		overview.TopProtocols = overview.TopProtocols[:5]
	}

	return overview, nil
}

// GetIndexMeta returns index metadata.
func (e *SQLiteEngine) GetIndexMeta(ctx context.Context) (*model.IndexMeta, error) {
	return e.store.GetMeta()
}

// IsIndexed returns whether the pcap is indexed.
func (e *SQLiteEngine) IsIndexed(ctx context.Context) bool {
	meta, err := e.store.GetMeta()
	return err == nil && meta.IndexComplete
}

// GetPcapPath returns the pcap file path.
func (e *SQLiteEngine) GetPcapPath(ctx context.Context) string {
	return e.pcapPath
}

// ────────────────────────────────────────────────────────────────────────────────
// Scanner helpers
// ────────────────────────────────────────────────────────────────────────────────

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanPacket(row rowScanner) (*model.PacketSummary, error) {
	p := &model.PacketSummary{}
	var ethType sql.NullInt64
	var ipVersion, ipProto, ttl sql.NullInt64
	var srcPort, dstPort, tcpFlags, tcpSeq, tcpAck, tcpWindow sql.NullInt64
	var srcMAC, dstMAC, srcIP, dstIP, protocol, info, flowID sql.NullString
	var fileOffset sql.NullInt64
	var filePath sql.NullString

	err := row.Scan(
		&p.Number, &p.TimestampNS, &p.Length, &p.CaptureLength,
		&srcMAC, &dstMAC, &ethType,
		&srcIP, &dstIP, &ipVersion, &ipProto, &ttl,
		&srcPort, &dstPort, &tcpFlags, &tcpSeq, &tcpAck, &tcpWindow,
		&protocol, &info, &flowID, &fileOffset, &filePath,
	)
	if err != nil {
		return nil, err
	}

	p.SrcMAC = srcMAC.String
	p.DstMAC = dstMAC.String
	p.EthType = uint16(ethType.Int64)
	p.SrcIP = srcIP.String
	p.DstIP = dstIP.String
	p.IPVersion = int(ipVersion.Int64)
	p.IPProto = int(ipProto.Int64)
	p.TTL = int(ttl.Int64)
	p.SrcPort = int(srcPort.Int64)
	p.DstPort = int(dstPort.Int64)
	p.TCPFlags = uint16(tcpFlags.Int64)
	p.TCPSeq = uint32(tcpSeq.Int64)
	p.TCPAck = uint32(tcpAck.Int64)
	p.TCPWindow = uint16(tcpWindow.Int64)
	p.Protocol = protocol.String
	p.Info = info.String
	p.FlowID = flowID.String
	p.Evidence.FileOffset = fileOffset.Int64
	p.Evidence.FilePath = filePath.String

	return p, nil
}

func scanPacketRow(rows *sql.Rows) (*model.PacketSummary, error) {
	return scanPacket(rows)
}

func scanFlow(row rowScanner) (*model.Flow, error) {
	f := &model.Flow{}
	var srcPort, dstPort sql.NullInt64
	var endNS sql.NullInt64
	var retrans, rttAvg, rttMin, rttMax sql.NullInt64
	var rttSamples, metadata sql.NullString

	err := row.Scan(
		&f.ID, &f.SrcIP, &f.DstIP, &srcPort, &dstPort, &f.Protocol, &f.State,
		&f.StartNS, &endNS, &f.Packets, &f.Bytes,
		&f.FwdPackets, &f.FwdBytes, &f.BwdPackets, &f.BwdBytes,
		&retrans, &rttSamples, &rttAvg, &rttMin, &rttMax, &metadata,
	)
	if err != nil {
		return nil, err
	}

	f.SrcPort = int(srcPort.Int64)
	f.DstPort = int(dstPort.Int64)
	f.EndNS = endNS.Int64
	f.Retrans = int(retrans.Int64)
	f.RTTAvgUS = int(rttAvg.Int64)
	f.RTTMinUS = int(rttMin.Int64)
	f.RTTMaxUS = int(rttMax.Int64)

	if rttSamples.Valid && rttSamples.String != "" {
		json.Unmarshal([]byte(rttSamples.String), &f.RTTSamples)
	}
	if metadata.Valid && metadata.String != "" {
		json.Unmarshal([]byte(metadata.String), &f.Metadata)
	}

	return f, nil
}

func scanFlowRow(rows *sql.Rows) (*model.Flow, error) {
	return scanFlow(rows)
}

func scanEventRow(rows *sql.Rows) (*model.ExpertEvent, error) {
	e := &model.ExpertEvent{}
	var severity int
	var grp, detail, flowID sql.NullString
	var packetStart, packetEnd sql.NullInt64

	err := rows.Scan(
		&e.ID, &e.TimestampNS, &severity, &grp, &e.Type,
		&e.Message, &detail, &flowID, &packetStart, &packetEnd,
	)
	if err != nil {
		return nil, err
	}

	// Convert severity int to Severity type
	switch severity {
	case 4:
		e.Severity = model.SeverityError
	case 3:
		e.Severity = model.SeverityWarning
	case 2:
		e.Severity = model.SeverityNote
	default:
		e.Severity = model.SeverityChat
	}

	e.Group = model.EventGroup(grp.String)
	e.Summary = detail.String
	e.FlowID = flowID.String
	e.PacketStart = int(packetStart.Int64)
	e.PacketEnd = int(packetEnd.Int64)

	return e, nil
}
