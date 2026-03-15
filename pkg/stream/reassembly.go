package stream

import (
	"sort"
	"time"
)

// Default limits for memory management
const (
	DefaultMaxAssembledSize = 10 * 1024 * 1024 // 10MB max assembled data
	DefaultMaxPendingSegs   = 1000             // Max pending out-of-order segments
	DefaultSegmentTimeout   = 30 * time.Second // Timeout for stale segments
)

// Segment represents a TCP segment with sequence number
type Segment struct {
	Seq  uint32
	Data []byte
	Seen time.Time
}

// ReassemblyBuffer handles TCP segment reassembly
type ReassemblyBuffer struct {
	segments  []Segment
	nextSeq   uint32 // Expected next sequence number
	assembled []byte // Assembled continuous data
	baseSeq   uint32 // Base sequence number (ISN + 1)

	// Memory management limits
	maxAssembledSize int
	maxPendingSegs   int

	// Statistics
	droppedBytes int
	droppedSegs  int
}

// NewReassemblyBuffer creates a new reassembly buffer with default limits
func NewReassemblyBuffer(initialSeq uint32) *ReassemblyBuffer {
	return &ReassemblyBuffer{
		segments:         make([]Segment, 0),
		nextSeq:          initialSeq,
		baseSeq:          initialSeq,
		assembled:        make([]byte, 0),
		maxAssembledSize: DefaultMaxAssembledSize,
		maxPendingSegs:   DefaultMaxPendingSegs,
	}
}

// NewReassemblyBufferWithLimits creates a new reassembly buffer with custom limits
func NewReassemblyBufferWithLimits(initialSeq uint32, maxAssembled, maxPending int) *ReassemblyBuffer {
	return &ReassemblyBuffer{
		segments:         make([]Segment, 0),
		nextSeq:          initialSeq,
		baseSeq:          initialSeq,
		assembled:        make([]byte, 0),
		maxAssembledSize: maxAssembled,
		maxPendingSegs:   maxPending,
	}
}

// AddSegment adds a TCP segment to the buffer and returns the number of new bytes added
func (b *ReassemblyBuffer) AddSegment(seq uint32, data []byte, timestamp time.Time) int {
	if len(data) == 0 {
		return 0
	}

	// Check assembled size limit
	if b.maxAssembledSize > 0 && len(b.assembled) >= b.maxAssembledSize {
		b.droppedBytes += len(data)
		b.droppedSegs++
		return 0
	}

	// Check for retransmission (sequence number before nextSeq)
	if seqBefore(seq+uint32(len(data)), b.nextSeq) {
		// Complete retransmission, ignore
		return 0
	}

	// Check for partial retransmission (handle sequence number wrap-around safely)
	if seqBefore(seq, b.nextSeq) {
		// Trim already received data - use signed arithmetic to handle wrap-around
		overlap := int32(b.nextSeq - seq)
		if overlap < 0 || overlap >= int32(len(data)) {
			return 0
		}
		data = data[overlap:]
		seq = b.nextSeq
	}

	// Check pending segments limit before adding out-of-order segment
	if seqAfter(seq, b.nextSeq) && b.maxPendingSegs > 0 && len(b.segments) >= b.maxPendingSegs {
		b.droppedBytes += len(data)
		b.droppedSegs++
		return 0
	}

	// Add segment
	segment := Segment{
		Seq:  seq,
		Data: make([]byte, len(data)),
		Seen: timestamp,
	}
	copy(segment.Data, data)

	// Insert in sorted order
	b.insertSegment(segment)

	// Try to assemble continuous data
	assembledBefore := len(b.assembled)
	b.tryAssemble()
	assembledAfter := len(b.assembled)

	// Return actual bytes assembled
	actualAdded := assembledAfter - assembledBefore
	if actualAdded > 0 {
		return actualAdded
	}

	// Data went to pending segments
	return len(data)
}

// insertSegment inserts a segment maintaining sorted order by Seq
func (b *ReassemblyBuffer) insertSegment(seg Segment) {
	// Find insertion point
	idx := sort.Search(len(b.segments), func(i int) bool {
		return seqAfterOrEqual(b.segments[i].Seq, seg.Seq)
	})

	// Check for duplicate
	if idx < len(b.segments) && b.segments[idx].Seq == seg.Seq {
		// Duplicate, keep longer one
		if len(seg.Data) > len(b.segments[idx].Data) {
			b.segments[idx] = seg
		}
		return
	}

	// Insert
	b.segments = append(b.segments, Segment{})
	copy(b.segments[idx+1:], b.segments[idx:])
	b.segments[idx] = seg
}

// tryAssemble tries to assemble continuous data from segments
func (b *ReassemblyBuffer) tryAssemble() {
	for len(b.segments) > 0 {
		seg := b.segments[0]

		// Check if this segment is next in sequence
		if seqAfter(seg.Seq, b.nextSeq) {
			// Gap, cannot continue
			break
		}

		// Handle overlap with already assembled data
		startOffset := 0
		if seqBefore(seg.Seq, b.nextSeq) {
			startOffset = int(b.nextSeq - seg.Seq)
			if startOffset >= len(seg.Data) {
				// Fully overlapping, remove and continue
				b.segments = b.segments[1:]
				continue
			}
		}

		// Append new data
		b.assembled = append(b.assembled, seg.Data[startOffset:]...)
		b.nextSeq = seg.Seq + uint32(len(seg.Data))

		// Remove processed segment
		b.segments = b.segments[1:]
	}
}

// GetAssembled returns the assembled data
func (b *ReassemblyBuffer) GetAssembled() []byte {
	return b.assembled
}

// GetAssembledLen returns the length of assembled data
func (b *ReassemblyBuffer) GetAssembledLen() int {
	return len(b.assembled)
}

// GetPendingSegments returns the number of pending (out-of-order) segments
func (b *ReassemblyBuffer) GetPendingSegments() int {
	return len(b.segments)
}

// GetNextSeq returns the next expected sequence number
func (b *ReassemblyBuffer) GetNextSeq() uint32 {
	return b.nextSeq
}

// RelativeSeq returns sequence number relative to base
func (b *ReassemblyBuffer) RelativeSeq(seq uint32) uint32 {
	return seq - b.baseSeq
}

// GetDroppedStats returns dropped bytes and segments count
func (b *ReassemblyBuffer) GetDroppedStats() (bytes, segs int) {
	return b.droppedBytes, b.droppedSegs
}

// CleanStaleSegments removes segments older than timeout and returns count removed
func (b *ReassemblyBuffer) CleanStaleSegments(timeout time.Duration) int {
	if len(b.segments) == 0 {
		return 0
	}

	now := time.Now()
	removed := 0
	newSegments := make([]Segment, 0, len(b.segments))

	for _, seg := range b.segments {
		if now.Sub(seg.Seen) > timeout {
			b.droppedBytes += len(seg.Data)
			b.droppedSegs++
			removed++
		} else {
			newSegments = append(newSegments, seg)
		}
	}

	b.segments = newSegments
	return removed
}

// Clear clears the buffer
func (b *ReassemblyBuffer) Clear() {
	b.segments = b.segments[:0]
	b.assembled = b.assembled[:0]
}

// seqBefore returns true if a < b (handling wrap-around)
func seqBefore(a, b uint32) bool {
	return int32(a-b) < 0
}

// seqAfter returns true if a > b (handling wrap-around)
func seqAfter(a, b uint32) bool {
	return int32(a-b) > 0
}

// seqAfterOrEqual returns true if a >= b (handling wrap-around)
func seqAfterOrEqual(a, b uint32) bool {
	return int32(a-b) >= 0
}
