// Package ingest provides the indexing pipeline for pcap files.
// It reads packets, decodes them in parallel, aggregates flows, and writes to store.
package ingest

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/pkg/model"
	"github.com/Zerofisher/pktanalyzer/pkg/store"
	"github.com/Zerofisher/pktanalyzer/pkg/store/sqlite"
)

// Config holds configuration for the ingest pipeline.
type Config struct {
	// PcapPath is the path to the pcap/pcapng file.
	PcapPath string

	// Workers is the number of parallel decode workers.
	// Defaults to runtime.GOMAXPROCS(0) if <= 0.
	Workers int

	// BatchSize is the number of packets per batch commit.
	// Defaults to 1000 if <= 0.
	BatchSize int

	// BPFFilter is an optional BPF filter expression.
	BPFFilter string

	// ProgressCallback is called periodically with progress updates.
	ProgressCallback func(processed, total int, elapsed time.Duration)
}

// Result holds the result of an ingest operation.
type Result struct {
	IndexPath    string
	TotalPackets int
	TotalBytes   int64
	TotalFlows   int
	Duration     time.Duration
	Error        error
}

// Progress holds progress information during indexing.
type Progress struct {
	Processed int
	Total     int // May be 0 if unknown
	Elapsed   time.Duration
	Rate      float64 // packets per second
}

// Pipeline is the main ingest pipeline.
type Pipeline struct {
	cfg    Config
	store  *sqlite.SQLiteStore
	ctx    context.Context
	cancel context.CancelFunc

	// State
	processed atomic.Int64
	totalBytes atomic.Int64

	// Flow aggregation (single goroutine access)
	flows     map[string]*model.Flow
	flowMu    sync.Mutex
}

// New creates a new ingest pipeline.
func New(cfg Config) *Pipeline {
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.GOMAXPROCS(0)
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 1000
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Pipeline{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
		flows:  make(map[string]*model.Flow),
	}
}

// Run executes the ingest pipeline.
func (p *Pipeline) Run() (*Result, error) {
	startTime := time.Now()
	result := &Result{
		IndexPath: p.cfg.PcapPath + ".idx.db",
	}

	// Check if pcap file exists
	fileInfo, err := os.Stat(p.cfg.PcapPath)
	if err != nil {
		return nil, fmt.Errorf("stat pcap file: %w", err)
	}

	// Create store
	p.store, err = sqlite.NewFromPcap(p.cfg.PcapPath, false)
	if err != nil {
		return nil, fmt.Errorf("create store: %w", err)
	}
	defer p.store.Close()

	// Check if index already exists and is valid
	meta, err := p.store.GetMeta()
	if err == nil && meta.IndexComplete {
		// Validate against current file
		if meta.PcapPath == p.cfg.PcapPath &&
			meta.PcapSize == fileInfo.Size() &&
			meta.SchemaVersion == store.SchemaVersion {
			// Index is valid, skip re-indexing
			result.TotalPackets = meta.TotalPackets
			result.TotalBytes = meta.TotalBytes
			result.Duration = time.Since(startTime)
			return result, nil
		}
	}

	// Create capturer for pcap file
	capturer, err := capture.NewFileCapturer(p.cfg.PcapPath, p.cfg.BPFFilter)
	if err != nil {
		return nil, fmt.Errorf("create capturer: %w", err)
	}
	defer capturer.Stop()

	// Start capture
	packetChan := capturer.Start()

	// Setup channels
	decodeChan := make(chan *model.PacketSummary, p.cfg.BatchSize*2)
	errChan := make(chan error, 1)

	// Start writer goroutine
	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		if err := p.writerLoop(decodeChan); err != nil {
			select {
			case errChan <- err:
			default:
			}
		}
	}()

	// Process packets
	var packetNumber int
	for pkt := range packetChan {
		select {
		case <-p.ctx.Done():
			goto done
		default:
		}

		packetNumber++

		// Convert capture.PacketInfo to model.PacketSummary
		summary := p.convertPacket(&pkt, packetNumber)
		
		// Update flow aggregation
		p.updateFlow(summary)

		// Send to writer
		select {
		case decodeChan <- summary:
		case <-p.ctx.Done():
			goto done
		}

		p.processed.Add(1)
		p.totalBytes.Add(int64(pkt.Length))

		// Progress callback
		if p.cfg.ProgressCallback != nil && packetNumber%1000 == 0 {
			p.cfg.ProgressCallback(packetNumber, 0, time.Since(startTime))
		}
	}

done:
	// Close decode channel and wait for writer
	close(decodeChan)
	writerWg.Wait()

	// Check for errors
	select {
	case err := <-errChan:
		result.Error = err
		return result, err
	default:
	}

	// Flush remaining flows
	if err := p.flushFlows(); err != nil {
		return nil, fmt.Errorf("flush flows: %w", err)
	}

	// Update metadata
	result.TotalPackets = int(p.processed.Load())
	result.TotalBytes = p.totalBytes.Load()
	result.TotalFlows = len(p.flows)
	result.Duration = time.Since(startTime)

	// Save metadata
	indexMeta := &model.IndexMeta{
		SchemaVersion: store.SchemaVersion,
		PcapPath:      p.cfg.PcapPath,
		PcapSize:      fileInfo.Size(),
		PcapModified:  fileInfo.ModTime(),
		IndexedAt:     time.Now(),
		TotalPackets:  result.TotalPackets,
		TotalBytes:    result.TotalBytes,
		DurationNS:    result.Duration.Nanoseconds(),
		IndexComplete: true,
	}
	if err := p.store.SetMeta(indexMeta); err != nil {
		return nil, fmt.Errorf("save metadata: %w", err)
	}

	return result, nil
}

// Stop cancels the pipeline.
func (p *Pipeline) Stop() {
	p.cancel()
}

// Progress returns current progress.
func (p *Pipeline) Progress() Progress {
	return Progress{
		Processed: int(p.processed.Load()),
	}
}

// convertPacket converts capture.PacketInfo to model.PacketSummary.
func (p *Pipeline) convertPacket(pkt *capture.PacketInfo, number int) *model.PacketSummary {
	summary := &model.PacketSummary{
		Number:        number,
		TimestampNS:   pkt.Timestamp.UnixNano(),
		Length:        pkt.Length,
		CaptureLength: pkt.Length,
		SrcMAC:        pkt.SrcMAC,
		DstMAC:        pkt.DstMAC,
		SrcIP:         pkt.SrcIP,
		DstIP:         pkt.DstIP,
		Protocol:      pkt.Protocol,
		Info:          pkt.Info,
		SNI:           pkt.SNI,
		Decrypted:     pkt.Decrypted,
		Evidence: model.PacketEvidence{
			FilePath: p.cfg.PcapPath,
		},
	}

	// Parse ports
	if pkt.SrcPort != "" {
		fmt.Sscanf(pkt.SrcPort, "%d", &summary.SrcPort)
	}
	if pkt.DstPort != "" {
		fmt.Sscanf(pkt.DstPort, "%d", &summary.DstPort)
	}

	// TCP fields
	summary.TCPFlags = pkt.TCPFlags
	summary.TCPSeq = pkt.TCPSeq
	summary.TCPAck = pkt.TCPAck
	summary.TCPWindow = pkt.TCPWindow

	// Generate flow ID
	if summary.SrcIP != "" && summary.DstIP != "" {
		flowKey := model.FlowKey{
			SrcIP:    summary.SrcIP,
			DstIP:    summary.DstIP,
			SrcPort:  summary.SrcPort,
			DstPort:  summary.DstPort,
			Protocol: summary.Protocol,
		}
		summary.FlowID = flowKey.ID()
	}

	return summary
}

// updateFlow updates flow aggregation state.
func (p *Pipeline) updateFlow(pkt *model.PacketSummary) {
	if pkt.FlowID == "" {
		return
	}

	p.flowMu.Lock()
	defer p.flowMu.Unlock()

	flow, exists := p.flows[pkt.FlowID]
	if !exists {
		// Create new flow
		flowKey := model.FlowKey{
			SrcIP:    pkt.SrcIP,
			DstIP:    pkt.DstIP,
			SrcPort:  pkt.SrcPort,
			DstPort:  pkt.DstPort,
			Protocol: pkt.Protocol,
		}.Normalize()

		flow = &model.Flow{
			ID:       pkt.FlowID,
			SrcIP:    flowKey.SrcIP,
			DstIP:    flowKey.DstIP,
			SrcPort:  flowKey.SrcPort,
			DstPort:  flowKey.DstPort,
			Protocol: pkt.Protocol,
			State:    "active",
			StartNS:  pkt.TimestampNS,
			EndNS:    pkt.TimestampNS,
		}
		p.flows[pkt.FlowID] = flow
	}

	// Update counters
	flow.Packets++
	flow.Bytes += int64(pkt.Length)
	flow.EndNS = pkt.TimestampNS

	// Track direction
	isForward := pkt.SrcIP == flow.SrcIP && pkt.SrcPort == flow.SrcPort
	if isForward {
		flow.FwdPackets++
		flow.FwdBytes += int64(pkt.Length)
	} else {
		flow.BwdPackets++
		flow.BwdBytes += int64(pkt.Length)
	}

	// Track first N packet numbers for evidence
	if len(flow.PacketNumbers) < 10 {
		flow.PacketNumbers = append(flow.PacketNumbers, pkt.Number)
	}

	// TLS SNI
	if pkt.SNI != "" && flow.TLSServerName == "" {
		flow.TLSServerName = pkt.SNI
	}
}

// writerLoop handles batch writing to the store.
func (p *Pipeline) writerLoop(packets <-chan *model.PacketSummary) error {
	batch := make([]*model.PacketSummary, 0, p.cfg.BatchSize)

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}

		if err := p.store.BeginBatch(); err != nil {
			return fmt.Errorf("begin batch: %w", err)
		}

		if err := p.store.InsertPackets(batch); err != nil {
			p.store.RollbackBatch()
			return fmt.Errorf("insert packets: %w", err)
		}

		if err := p.store.CommitBatch(); err != nil {
			return fmt.Errorf("commit batch: %w", err)
		}

		batch = batch[:0]
		return nil
	}

	for pkt := range packets {
		batch = append(batch, pkt)
		if len(batch) >= p.cfg.BatchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}

	// Final flush
	return flush()
}

// flushFlows writes all accumulated flows to the store.
func (p *Pipeline) flushFlows() error {
	p.flowMu.Lock()
	flows := make([]*model.Flow, 0, len(p.flows))
	for _, f := range p.flows {
		flows = append(flows, f)
	}
	p.flowMu.Unlock()

	if len(flows) == 0 {
		return nil
	}

	if err := p.store.BeginBatch(); err != nil {
		return err
	}

	if err := p.store.UpsertFlows(flows); err != nil {
		p.store.RollbackBatch()
		return err
	}

	return p.store.CommitBatch()
}

// IndexFile is a convenience function to index a pcap file.
func IndexFile(pcapPath string, progressFn func(processed, total int, elapsed time.Duration)) (*Result, error) {
	pipeline := New(Config{
		PcapPath:         pcapPath,
		ProgressCallback: progressFn,
	})
	return pipeline.Run()
}

// NeedsReindex checks if a pcap file needs to be re-indexed.
func NeedsReindex(pcapPath string) (bool, error) {
	fileInfo, err := os.Stat(pcapPath)
	if err != nil {
		return false, err
	}

	dbPath := pcapPath + ".idx.db"
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return true, nil
	}

	s, err := sqlite.NewFromPcap(pcapPath, true)
	if err != nil {
		return true, nil // Can't open, needs reindex
	}
	defer s.Close()

	meta, err := s.GetMeta()
	if err != nil {
		return true, nil
	}

	// Check validity
	if !meta.IndexComplete {
		return true, nil
	}
	if meta.PcapPath != pcapPath {
		return true, nil
	}
	if meta.PcapSize != fileInfo.Size() {
		return true, nil
	}
	if meta.SchemaVersion != store.SchemaVersion {
		return true, nil
	}

	return false, nil
}
