// Package expert provides TCP sequence analysis and anomaly detection
package expert

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/Zerofisher/pktanalyzer/capture"
)

// TCPAnalysisContext maintains state for TCP sequence analysis
type TCPAnalysisContext struct {
	mu sync.RWMutex

	// Per-stream state
	streams map[string]*TCPStreamState

	// Detection thresholds
	retransmitWindow  time.Duration // Window to detect retransmits
	duplicateACKCount int           // Number of dup ACKs to trigger warning
}

// TCPStreamState holds analysis state for a single TCP stream
type TCPStreamState struct {
	// Basic info
	StreamKey  string
	FirstSeen  time.Time
	LastSeen   time.Time
	PacketList []TCPPacketRecord

	// Sequence tracking (for each direction)
	ClientSeq *SequenceTracker // Client -> Server
	ServerSeq *SequenceTracker // Server -> Client

	// Window tracking
	LastClientWindow uint16
	LastServerWindow uint16
	ZeroWindowSeen   bool

	// Connection state
	SYNSeen    bool
	SYNACKSeen bool
	FINSeen    bool
	RSTSeen    bool
}

// TCPPacketRecord stores minimal info about a TCP packet for analysis
type TCPPacketRecord struct {
	PacketNum   int
	Timestamp   time.Time
	Seq         uint32
	Ack         uint32
	Flags       uint16
	PayloadLen  int
	Window      uint16
	IsFromClient bool
}

// SequenceTracker tracks sequence numbers for one direction
type SequenceTracker struct {
	NextExpectedSeq uint32            // Next expected sequence number
	MaxSeqSeen      uint32            // Highest sequence number seen
	SeenSegments    map[uint32]SegmentInfo // Maps seq -> segment info
	LastAckNum      uint32            // Last ACK number received
	DupACKCount     int               // Consecutive duplicate ACKs
	LastDupACK      uint32            // Last duplicate ACK value
}

// SegmentInfo stores info about a seen segment
type SegmentInfo struct {
	PacketNum  int
	Timestamp  time.Time
	Seq        uint32
	NextSeq    uint32 // Seq + PayloadLen
	PayloadLen int
	Flags      uint16
}

// NewTCPAnalysisContext creates a new TCP analysis context
func NewTCPAnalysisContext() *TCPAnalysisContext {
	return &TCPAnalysisContext{
		streams:           make(map[string]*TCPStreamState),
		retransmitWindow:  time.Second * 3,
		duplicateACKCount: 3,
	}
}

// Analyze processes a TCP packet and returns any expert info
func (ctx *TCPAnalysisContext) Analyze(pkt *capture.PacketInfo) []*ExpertInfo {
	if pkt.StreamKey == "" {
		return nil
	}

	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	// Get or create stream state
	stream, ok := ctx.streams[pkt.StreamKey]
	if !ok {
		stream = ctx.newStreamState(pkt)
		ctx.streams[pkt.StreamKey] = stream
	}

	// Determine direction
	isFromClient := ctx.isClientPacket(pkt, stream)

	// Create packet record
	record := TCPPacketRecord{
		PacketNum:    pkt.Number,
		Timestamp:    pkt.Timestamp,
		Seq:          pkt.TCPSeq,
		Ack:          pkt.TCPAck,
		Flags:        pkt.TCPFlags,
		PayloadLen:   len(pkt.TCPPayload),
		Window:       pkt.TCPWindow,
		IsFromClient: isFromClient,
	}

	stream.PacketList = append(stream.PacketList, record)
	stream.LastSeen = pkt.Timestamp

	// Run all TCP analysis checks
	var results []*ExpertInfo

	// 1. Check TCP flags
	flagResults := ctx.checkFlags(pkt, stream, record)
	results = append(results, flagResults...)

	// 2. Check for retransmissions and out-of-order
	seqResults := ctx.checkSequence(pkt, stream, record, isFromClient)
	results = append(results, seqResults...)

	// 3. Check for duplicate ACKs
	ackResults := ctx.checkDuplicateACK(pkt, stream, record, isFromClient)
	results = append(results, ackResults...)

	// 4. Check window issues
	windowResults := ctx.checkWindow(pkt, stream, record, isFromClient)
	results = append(results, windowResults...)

	// 5. Check for keep-alive
	keepAliveResults := ctx.checkKeepAlive(pkt, stream, record, isFromClient)
	results = append(results, keepAliveResults...)

	// Update stream state
	ctx.updateStreamState(stream, record, isFromClient)

	return results
}

func (ctx *TCPAnalysisContext) newStreamState(pkt *capture.PacketInfo) *TCPStreamState {
	return &TCPStreamState{
		StreamKey:  pkt.StreamKey,
		FirstSeen:  pkt.Timestamp,
		LastSeen:   pkt.Timestamp,
		PacketList: make([]TCPPacketRecord, 0),
		ClientSeq:  newSequenceTracker(),
		ServerSeq:  newSequenceTracker(),
	}
}

func newSequenceTracker() *SequenceTracker {
	return &SequenceTracker{
		SeenSegments: make(map[uint32]SegmentInfo),
	}
}

// isClientPacket determines if packet is from client based on first packet
func (ctx *TCPAnalysisContext) isClientPacket(pkt *capture.PacketInfo, stream *TCPStreamState) bool {
	// SYN without ACK is always from client
	if pkt.TCPFlags&0x002 != 0 && pkt.TCPFlags&0x010 == 0 {
		return true
	}
	// SYN+ACK is always from server
	if pkt.TCPFlags&0x002 != 0 && pkt.TCPFlags&0x010 != 0 {
		return false
	}
	// Use first packet's direction as client
	if len(stream.PacketList) == 0 {
		return true
	}
	// Compare with first packet
	first := stream.PacketList[0]
	// Simple heuristic: same direction if source matches
	srcPort, _ := strconv.ParseUint(pkt.SrcPort, 10, 16)
	// For the first packet, check if it was a SYN
	if first.Flags&0x002 != 0 && first.Flags&0x010 == 0 {
		// First packet was SYN from client, check if this is same source
		return uint16(srcPort) == extractPort(stream.PacketList, true)
	}
	return first.IsFromClient == (pkt.TCPSeq == first.Seq || pkt.SrcPort == strconv.Itoa(int(extractPort(stream.PacketList, true))))
}

func extractPort(records []TCPPacketRecord, fromClient bool) uint16 {
	for _, r := range records {
		if r.IsFromClient == fromClient {
			return 0 // Would need full info
		}
	}
	return 0
}

// checkFlags checks for RST, SYN flood, etc.
func (ctx *TCPAnalysisContext) checkFlags(pkt *capture.PacketInfo, stream *TCPStreamState, record TCPPacketRecord) []*ExpertInfo {
	var results []*ExpertInfo
	flags := record.Flags

	// RST flag
	if flags&0x004 != 0 {
		info := &ExpertInfo{
			PacketNum: pkt.Number,
			Timestamp: pkt.Timestamp,
			Severity:  SeverityError,
			Group:     GroupSequence,
			Protocol:  "TCP",
			Summary:   TCPRSTFlag.String(),
			Details:   fmt.Sprintf("Connection reset by %s", getEndpoint(pkt, record.IsFromClient)),
			StreamKey: pkt.StreamKey,
		}

		// If RST comes early without established connection
		if !stream.SYNACKSeen {
			info.Summary = TCPConnectionRefused.String()
			info.Details = "Connection refused (RST without established handshake)"
		}

		results = append(results, info)
		stream.RSTSeen = true
	}

	// Track SYN/SYN-ACK
	if flags&0x002 != 0 {
		if flags&0x010 != 0 {
			stream.SYNACKSeen = true
		} else {
			stream.SYNSeen = true
		}
	}

	// FIN flag
	if flags&0x001 != 0 {
		stream.FINSeen = true
	}

	return results
}

// checkSequence checks for retransmissions and out-of-order
func (ctx *TCPAnalysisContext) checkSequence(pkt *capture.PacketInfo, stream *TCPStreamState, record TCPPacketRecord, isFromClient bool) []*ExpertInfo {
	var results []*ExpertInfo

	// Skip SYN and FIN-only packets for sequence analysis
	if record.PayloadLen == 0 && (record.Flags&0x002 != 0 || record.Flags&0x001 != 0) {
		return results
	}

	// Get the appropriate sequence tracker
	var tracker *SequenceTracker
	if isFromClient {
		tracker = stream.ClientSeq
	} else {
		tracker = stream.ServerSeq
	}

	seq := record.Seq
	nextSeq := seq + uint32(record.PayloadLen)

	// Check if this is a data packet
	if record.PayloadLen > 0 {
		// Check if we've seen this segment before (retransmission)
		if existingInfo, ok := tracker.SeenSegments[seq]; ok {
			// This is a retransmission
			retxType := TCPRetransmission

			// Check if it's a fast retransmission (within RTT and after dup ACKs)
			timeSince := pkt.Timestamp.Sub(existingInfo.Timestamp)
			if timeSince < 50*time.Millisecond && tracker.DupACKCount >= 3 {
				retxType = TCPFastRetransmission
			}

			// Check for spurious retransmission (already ACKed)
			if isAlreadyAcked(seq, tracker.LastAckNum) {
				retxType = TCPSpuriousRetransmission
			}

			results = append(results, &ExpertInfo{
				PacketNum:   pkt.Number,
				Timestamp:   pkt.Timestamp,
				Severity:    retxType.Severity(),
				Group:       GroupSequence,
				Protocol:    "TCP",
				Summary:     retxType.String(),
				Details:     fmt.Sprintf("Seq=%d Len=%d (original in #%d)", seq, record.PayloadLen, existingInfo.PacketNum),
				RelatedPkts: []int{existingInfo.PacketNum},
				StreamKey:   pkt.StreamKey,
			})
		} else {
			// New segment - check for out-of-order
			if tracker.NextExpectedSeq != 0 && seq != tracker.NextExpectedSeq {
				if seqLessThan(seq, tracker.NextExpectedSeq) {
					// Already have data after this - could be out-of-order or retransmission
					// Since we didn't find it in SeenSegments, it might be a partial overlap
				} else if seqGreaterThan(seq, tracker.NextExpectedSeq) {
					// Gap in sequence - out of order or previous segment lost
					gap := seq - tracker.NextExpectedSeq

					// Check if this looks like out-of-order vs lost segment
					if gap < 65535 { // Reasonable gap
						results = append(results, &ExpertInfo{
							PacketNum: pkt.Number,
							Timestamp: pkt.Timestamp,
							Severity:  SeverityNote,
							Group:     GroupSequence,
							Protocol:  "TCP",
							Summary:   TCPOutOfOrder.String(),
							Details:   fmt.Sprintf("Expected Seq=%d, got Seq=%d (gap=%d)", tracker.NextExpectedSeq, seq, gap),
							StreamKey: pkt.StreamKey,
						})
					} else {
						results = append(results, &ExpertInfo{
							PacketNum: pkt.Number,
							Timestamp: pkt.Timestamp,
							Severity:  SeverityWarning,
							Group:     GroupSequence,
							Protocol:  "TCP",
							Summary:   TCPPreviousSegmentNotCaptured.String(),
							Details:   fmt.Sprintf("Expected Seq=%d, got Seq=%d", tracker.NextExpectedSeq, seq),
							StreamKey: pkt.StreamKey,
						})
					}
				}
			}

			// Record this segment
			tracker.SeenSegments[seq] = SegmentInfo{
				PacketNum:  pkt.Number,
				Timestamp:  pkt.Timestamp,
				Seq:        seq,
				NextSeq:    nextSeq,
				PayloadLen: record.PayloadLen,
				Flags:      record.Flags,
			}
		}

		// Update max seq seen
		if tracker.NextExpectedSeq == 0 || seqGreaterThanOrEqual(nextSeq, tracker.MaxSeqSeen) {
			tracker.MaxSeqSeen = nextSeq
		}
	}

	return results
}

// checkDuplicateACK checks for duplicate ACKs
func (ctx *TCPAnalysisContext) checkDuplicateACK(pkt *capture.PacketInfo, stream *TCPStreamState, record TCPPacketRecord, isFromClient bool) []*ExpertInfo {
	var results []*ExpertInfo

	// Get the tracker for the direction being ACKed (opposite direction)
	var tracker *SequenceTracker
	if isFromClient {
		tracker = stream.ServerSeq // Client ACKing server's data
	} else {
		tracker = stream.ClientSeq // Server ACKing client's data
	}

	// Only check pure ACKs (no data, not SYN/FIN)
	if record.PayloadLen == 0 && record.Flags&0x010 != 0 && record.Flags&0x003 == 0 {
		ack := record.Ack

		if ack == tracker.LastDupACK && ack != 0 {
			tracker.DupACKCount++

			if tracker.DupACKCount == 3 {
				results = append(results, &ExpertInfo{
					PacketNum: pkt.Number,
					Timestamp: pkt.Timestamp,
					Severity:  SeverityWarning,
					Group:     GroupSequence,
					Protocol:  "TCP",
					Summary:   TCPTripleDuplicateACK.String(),
					Details:   fmt.Sprintf("ACK=%d seen %d times (possible packet loss)", ack, tracker.DupACKCount+1),
					StreamKey: pkt.StreamKey,
				})
			} else if tracker.DupACKCount > 1 {
				results = append(results, &ExpertInfo{
					PacketNum: pkt.Number,
					Timestamp: pkt.Timestamp,
					Severity:  SeverityNote,
					Group:     GroupSequence,
					Protocol:  "TCP",
					Summary:   TCPDuplicateACK.String(),
					Details:   fmt.Sprintf("ACK=%d (#%d)", ack, tracker.DupACKCount+1),
					StreamKey: pkt.StreamKey,
				})
			}
		} else {
			tracker.LastDupACK = ack
			tracker.DupACKCount = 0
		}

		tracker.LastAckNum = ack
	}

	return results
}

// checkWindow checks for window-related issues
func (ctx *TCPAnalysisContext) checkWindow(pkt *capture.PacketInfo, stream *TCPStreamState, record TCPPacketRecord, isFromClient bool) []*ExpertInfo {
	var results []*ExpertInfo

	window := record.Window

	// Zero window
	if window == 0 && record.PayloadLen == 0 {
		// Skip if it's a FIN or RST
		if record.Flags&0x005 == 0 {
			// Check if this is a zero window probe or actual zero window
			if !stream.ZeroWindowSeen {
				results = append(results, &ExpertInfo{
					PacketNum: pkt.Number,
					Timestamp: pkt.Timestamp,
					Severity:  SeverityWarning,
					Group:     GroupSequence,
					Protocol:  "TCP",
					Summary:   TCPZeroWindow.String(),
					Details:   fmt.Sprintf("%s advertised zero window", getEndpoint(pkt, isFromClient)),
					StreamKey: pkt.StreamKey,
				})
				stream.ZeroWindowSeen = true
			}
		}
	} else if stream.ZeroWindowSeen && window > 0 {
		// Window update after zero window
		results = append(results, &ExpertInfo{
			PacketNum: pkt.Number,
			Timestamp: pkt.Timestamp,
			Severity:  SeverityChat,
			Group:     GroupSequence,
			Protocol:  "TCP",
			Summary:   TCPWindowUpdate.String(),
			Details:   fmt.Sprintf("Window opened to %d", window),
			StreamKey: pkt.StreamKey,
		})
		stream.ZeroWindowSeen = false
	}

	// Update window tracking
	if isFromClient {
		stream.LastClientWindow = window
	} else {
		stream.LastServerWindow = window
	}

	return results
}

// checkKeepAlive checks for TCP keep-alive packets
func (ctx *TCPAnalysisContext) checkKeepAlive(pkt *capture.PacketInfo, stream *TCPStreamState, record TCPPacketRecord, isFromClient bool) []*ExpertInfo {
	var results []*ExpertInfo

	// Keep-alive detection: ACK with seq = previous seq - 1 and len = 0 or 1
	if record.PayloadLen <= 1 && record.Flags&0x010 != 0 && record.Flags&0x003 == 0 {
		var tracker *SequenceTracker
		if isFromClient {
			tracker = stream.ClientSeq
		} else {
			tracker = stream.ServerSeq
		}

		// Check if seq is one less than expected (keep-alive pattern)
		if tracker.NextExpectedSeq > 0 && record.Seq == tracker.NextExpectedSeq-1 {
			results = append(results, &ExpertInfo{
				PacketNum: pkt.Number,
				Timestamp: pkt.Timestamp,
				Severity:  SeverityChat,
				Group:     GroupSequence,
				Protocol:  "TCP",
				Summary:   TCPKeepAlive.String(),
				Details:   fmt.Sprintf("Seq=%d (expected %d)", record.Seq, tracker.NextExpectedSeq),
				StreamKey: pkt.StreamKey,
			})
		}
	}

	return results
}

// updateStreamState updates tracking after analyzing a packet
func (ctx *TCPAnalysisContext) updateStreamState(stream *TCPStreamState, record TCPPacketRecord, isFromClient bool) {
	var tracker *SequenceTracker
	if isFromClient {
		tracker = stream.ClientSeq
	} else {
		tracker = stream.ServerSeq
	}

	// Update next expected sequence
	if record.PayloadLen > 0 || record.Flags&0x002 != 0 || record.Flags&0x001 != 0 {
		nextSeq := record.Seq + uint32(record.PayloadLen)
		// Account for SYN and FIN consuming a sequence number
		if record.Flags&0x002 != 0 {
			nextSeq++
		}
		if record.Flags&0x001 != 0 {
			nextSeq++
		}

		if tracker.NextExpectedSeq == 0 || seqGreaterThan(nextSeq, tracker.NextExpectedSeq) {
			tracker.NextExpectedSeq = nextSeq
		}
	}
}

// Helper functions for sequence number comparison (handling wrap-around)
func seqLessThan(a, b uint32) bool {
	return int32(a-b) < 0
}

func seqGreaterThan(a, b uint32) bool {
	return int32(a-b) > 0
}

func seqGreaterThanOrEqual(a, b uint32) bool {
	return int32(a-b) >= 0
}

func isAlreadyAcked(seq, lastAck uint32) bool {
	if lastAck == 0 {
		return false
	}
	return seqLessThan(seq, lastAck)
}

func getEndpoint(pkt *capture.PacketInfo, isFromClient bool) string {
	if isFromClient {
		return fmt.Sprintf("client (%s:%s)", pkt.SrcIP, pkt.SrcPort)
	}
	return fmt.Sprintf("server (%s:%s)", pkt.SrcIP, pkt.SrcPort)
}
