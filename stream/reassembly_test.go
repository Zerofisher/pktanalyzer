package stream

import (
	"bytes"
	"fmt"
	"math"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 1. TestNewReassemblyBuffer
// ---------------------------------------------------------------------------

func TestNewReassemblyBuffer(t *testing.T) {
	tests := []struct {
		name       string
		initialSeq uint32
	}{
		{"zero_seq", 0},
		{"typical_seq", 1000},
		{"large_seq", 0xFFFFFF00},
		{"max_uint32", math.MaxUint32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := NewReassemblyBuffer(tt.initialSeq)

			if buf.GetNextSeq() != tt.initialSeq {
				t.Errorf("GetNextSeq() = %d, want %d", buf.GetNextSeq(), tt.initialSeq)
			}
			if buf.GetAssembledLen() != 0 {
				t.Errorf("GetAssembledLen() = %d, want 0", buf.GetAssembledLen())
			}
			if buf.GetPendingSegments() != 0 {
				t.Errorf("GetPendingSegments() = %d, want 0", buf.GetPendingSegments())
			}
			if buf.RelativeSeq(tt.initialSeq) != 0 {
				t.Errorf("RelativeSeq(initialSeq) = %d, want 0", buf.RelativeSeq(tt.initialSeq))
			}

			droppedBytes, droppedSegs := buf.GetDroppedStats()
			if droppedBytes != 0 || droppedSegs != 0 {
				t.Errorf("GetDroppedStats() = (%d, %d), want (0, 0)", droppedBytes, droppedSegs)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. TestNewReassemblyBufferWithLimits
// ---------------------------------------------------------------------------

func TestNewReassemblyBufferWithLimits(t *testing.T) {
	tests := []struct {
		name         string
		initialSeq   uint32
		maxAssembled int
		maxPending   int
	}{
		{"small_limits", 100, 512, 10},
		{"large_limits", 0, 100 * 1024 * 1024, 50000},
		{"zero_limits", 500, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := NewReassemblyBufferWithLimits(tt.initialSeq, tt.maxAssembled, tt.maxPending)

			if buf.GetNextSeq() != tt.initialSeq {
				t.Errorf("GetNextSeq() = %d, want %d", buf.GetNextSeq(), tt.initialSeq)
			}
			if buf.GetAssembledLen() != 0 {
				t.Errorf("GetAssembledLen() = %d, want 0", buf.GetAssembledLen())
			}
			if buf.maxAssembledSize != tt.maxAssembled {
				t.Errorf("maxAssembledSize = %d, want %d", buf.maxAssembledSize, tt.maxAssembled)
			}
			if buf.maxPendingSegs != tt.maxPending {
				t.Errorf("maxPendingSegs = %d, want %d", buf.maxPendingSegs, tt.maxPending)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. TestAddSegment_InOrder
// ---------------------------------------------------------------------------

func TestAddSegment_InOrder(t *testing.T) {
	tests := []struct {
		name       string
		initialSeq uint32
		segments   []struct {
			seq  uint32
			data string
		}
		wantReturns   []int
		wantAssembled string
		wantNextSeq   uint32
		wantPending   int
	}{
		{
			name:       "single_segment",
			initialSeq: 1000,
			segments: []struct {
				seq  uint32
				data string
			}{
				{1000, "hello"},
			},
			wantReturns:   []int{5},
			wantAssembled: "hello",
			wantNextSeq:   1005,
			wantPending:   0,
		},
		{
			name:       "two_sequential_segments",
			initialSeq: 1000,
			segments: []struct {
				seq  uint32
				data string
			}{
				{1000, "hello"},
				{1005, "world"},
			},
			wantReturns:   []int{5, 5},
			wantAssembled: "helloworld",
			wantNextSeq:   1010,
			wantPending:   0,
		},
		{
			name:       "three_sequential_segments",
			initialSeq: 0,
			segments: []struct {
				seq  uint32
				data string
			}{
				{0, "aaa"},
				{3, "bbb"},
				{6, "ccc"},
			},
			wantReturns:   []int{3, 3, 3},
			wantAssembled: "aaabbbccc",
			wantNextSeq:   9,
			wantPending:   0,
		},
		{
			name:       "single_byte_segments",
			initialSeq: 100,
			segments: []struct {
				seq  uint32
				data string
			}{
				{100, "A"},
				{101, "B"},
				{102, "C"},
			},
			wantReturns:   []int{1, 1, 1},
			wantAssembled: "ABC",
			wantNextSeq:   103,
			wantPending:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := NewReassemblyBuffer(tt.initialSeq)
			now := time.Now()

			for i, seg := range tt.segments {
				got := buf.AddSegment(seg.seq, []byte(seg.data), now)
				if got != tt.wantReturns[i] {
					t.Errorf("AddSegment(%d, %q) = %d, want %d", seg.seq, seg.data, got, tt.wantReturns[i])
				}
			}

			if !bytes.Equal(buf.GetAssembled(), []byte(tt.wantAssembled)) {
				t.Errorf("GetAssembled() = %q, want %q", buf.GetAssembled(), tt.wantAssembled)
			}
			if buf.GetNextSeq() != tt.wantNextSeq {
				t.Errorf("GetNextSeq() = %d, want %d", buf.GetNextSeq(), tt.wantNextSeq)
			}
			if buf.GetPendingSegments() != tt.wantPending {
				t.Errorf("GetPendingSegments() = %d, want %d", buf.GetPendingSegments(), tt.wantPending)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 4. TestAddSegment_OutOfOrder
// ---------------------------------------------------------------------------

func TestAddSegment_OutOfOrder(t *testing.T) {
	tests := []struct {
		name       string
		initialSeq uint32
		segments   []struct {
			seq  uint32
			data string
		}
		wantReturns   []int
		wantAssembled string
		wantNextSeq   uint32
		wantPending   int
	}{
		{
			name:       "reversed_two_segments",
			initialSeq: 1000,
			segments: []struct {
				seq  uint32
				data string
			}{
				{1005, "world"},
				{1000, "hello"},
			},
			// First goes to pending (returns len=5), second assembles both (returns 10).
			wantReturns:   []int{5, 10},
			wantAssembled: "helloworld",
			wantNextSeq:   1010,
			wantPending:   0,
		},
		{
			name:       "reversed_three_segments",
			initialSeq: 0,
			segments: []struct {
				seq  uint32
				data string
			}{
				{6, "ccc"},
				{3, "bbb"},
				{0, "aaa"},
			},
			// ccc -> pending (3), bbb -> pending (3), aaa -> assembles all 9.
			wantReturns:   []int{3, 3, 9},
			wantAssembled: "aaabbbccc",
			wantNextSeq:   9,
			wantPending:   0,
		},
		{
			name:       "middle_last_first",
			initialSeq: 100,
			segments: []struct {
				seq  uint32
				data string
			}{
				{103, "bbb"},
				{100, "aaa"},
				{106, "ccc"},
			},
			// bbb -> pending (3), aaa -> assembles aaa+bbb=6, ccc -> assembles 3.
			wantReturns:   []int{3, 6, 3},
			wantAssembled: "aaabbbccc",
			wantNextSeq:   109,
			wantPending:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := NewReassemblyBuffer(tt.initialSeq)
			now := time.Now()

			for i, seg := range tt.segments {
				got := buf.AddSegment(seg.seq, []byte(seg.data), now)
				if got != tt.wantReturns[i] {
					t.Errorf("step %d: AddSegment(%d, %q) = %d, want %d",
						i, seg.seq, seg.data, got, tt.wantReturns[i])
				}
			}

			if !bytes.Equal(buf.GetAssembled(), []byte(tt.wantAssembled)) {
				t.Errorf("GetAssembled() = %q, want %q", buf.GetAssembled(), tt.wantAssembled)
			}
			if buf.GetNextSeq() != tt.wantNextSeq {
				t.Errorf("GetNextSeq() = %d, want %d", buf.GetNextSeq(), tt.wantNextSeq)
			}
			if buf.GetPendingSegments() != tt.wantPending {
				t.Errorf("GetPendingSegments() = %d, want %d", buf.GetPendingSegments(), tt.wantPending)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 5. TestAddSegment_WithGap
// ---------------------------------------------------------------------------

func TestAddSegment_WithGap(t *testing.T) {
	tests := []struct {
		name       string
		initialSeq uint32
		segments   []struct {
			seq  uint32
			data string
		}
		wantReturns       []int
		wantAssembled     string
		wantPendingBefore int // pending count before gap-fill
		wantPendingAfter  int
	}{
		{
			name:       "gap_then_fill",
			initialSeq: 1000,
			segments: []struct {
				seq  uint32
				data string
			}{
				{1000, "aaa"}, // assembles 3 bytes
				{1006, "ccc"}, // gap at 1003-1006, pending (returns len(data)=3)
				{1003, "bbb"}, // fills gap, assembles bbb+ccc = 6 new bytes
			},
			wantReturns:       []int{3, 3, 6},
			wantAssembled:     "aaabbbccc",
			wantPendingBefore: 1, // checked after step 1, before step 2
			wantPendingAfter:  0,
		},
		{
			name:       "multiple_gaps",
			initialSeq: 0,
			segments: []struct {
				seq  uint32
				data string
			}{
				{0, "aa"}, // assembles 2 bytes
				{4, "cc"}, // gap at 2-4, pending (returns 2)
				{8, "ee"}, // gap at 6-8, pending (returns 2)
				{2, "bb"}, // fills first gap, assembles bb+cc = 4 new bytes
				{6, "dd"}, // fills second gap, assembles dd+ee = 4 new bytes
			},
			wantReturns:       []int{2, 2, 2, 4, 4},
			wantAssembled:     "aabbccddee",
			wantPendingBefore: 1, // after step 3 fills first gap, only "ee" at seq 8 remains pending
			wantPendingAfter:  0,
		},
		{
			name:       "gap_never_filled",
			initialSeq: 100,
			segments: []struct {
				seq  uint32
				data string
			}{
				{100, "xx"},
				{105, "yy"},
			},
			wantReturns:       []int{2, 2},
			wantAssembled:     "xx",
			wantPendingBefore: -1, // skip check
			wantPendingAfter:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := NewReassemblyBuffer(tt.initialSeq)
			now := time.Now()

			for i, seg := range tt.segments {
				// Check pending count before the last gap-fill step
				if tt.wantPendingBefore >= 0 && i == len(tt.segments)-1 {
					if got := buf.GetPendingSegments(); got != tt.wantPendingBefore {
						t.Errorf("pending before gap-fill = %d, want %d", got, tt.wantPendingBefore)
					}
				}

				got := buf.AddSegment(seg.seq, []byte(seg.data), now)
				if got != tt.wantReturns[i] {
					t.Errorf("step %d: AddSegment(%d, %q) = %d, want %d",
						i, seg.seq, seg.data, got, tt.wantReturns[i])
				}
			}

			if !bytes.Equal(buf.GetAssembled(), []byte(tt.wantAssembled)) {
				t.Errorf("GetAssembled() = %q, want %q", buf.GetAssembled(), tt.wantAssembled)
			}
			if buf.GetPendingSegments() != tt.wantPendingAfter {
				t.Errorf("GetPendingSegments() = %d, want %d", buf.GetPendingSegments(), tt.wantPendingAfter)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 6. TestAddSegment_Retransmission
// ---------------------------------------------------------------------------

func TestAddSegment_Retransmission(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name          string
		setupFunc     func() *ReassemblyBuffer
		retransmitSeq uint32
		retransmitDat string
		wantReturn    int
		wantAssembled string
		wantNextSeq   uint32
	}{
		{
			name: "complete_retransmission",
			setupFunc: func() *ReassemblyBuffer {
				buf := NewReassemblyBuffer(1000)
				buf.AddSegment(1000, []byte("hello"), now)
				return buf // nextSeq=1005
			},
			retransmitSeq: 1000,
			retransmitDat: "hello",
			wantReturn:    0,
			wantAssembled: "hello",
			wantNextSeq:   1005,
		},
		{
			name: "partial_retransmission_start_overlap",
			setupFunc: func() *ReassemblyBuffer {
				buf := NewReassemblyBuffer(1000)
				buf.AddSegment(1000, []byte("hello"), now)
				return buf // nextSeq=1005
			},
			retransmitSeq: 1003,
			retransmitDat: "loworld",
			wantReturn:    5,            // "world" assembled
			wantAssembled: "helloworld", // "lo" trimmed, "world" appended
			wantNextSeq:   1010,
		},
		{
			name: "old_retransmission_well_before",
			setupFunc: func() *ReassemblyBuffer {
				buf := NewReassemblyBuffer(1000)
				buf.AddSegment(1000, []byte("abcdefghij"), now)
				return buf // nextSeq=1010
			},
			retransmitSeq: 1000,
			retransmitDat: "abc",
			wantReturn:    0,
			wantAssembled: "abcdefghij",
			wantNextSeq:   1010,
		},
		{
			name: "retransmission_single_byte_overlap",
			setupFunc: func() *ReassemblyBuffer {
				buf := NewReassemblyBuffer(100)
				buf.AddSegment(100, []byte("AB"), now)
				return buf // nextSeq=102
			},
			retransmitSeq: 101,
			retransmitDat: "BCD",
			wantReturn:    2,      // "CD" assembled
			wantAssembled: "ABCD", // "B" trimmed, "CD" appended
			wantNextSeq:   104,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := tt.setupFunc()

			got := buf.AddSegment(tt.retransmitSeq, []byte(tt.retransmitDat), now)
			if got != tt.wantReturn {
				t.Errorf("AddSegment() = %d, want %d", got, tt.wantReturn)
			}

			if !bytes.Equal(buf.GetAssembled(), []byte(tt.wantAssembled)) {
				t.Errorf("GetAssembled() = %q, want %q", buf.GetAssembled(), tt.wantAssembled)
			}
			if buf.GetNextSeq() != tt.wantNextSeq {
				t.Errorf("GetNextSeq() = %d, want %d", buf.GetNextSeq(), tt.wantNextSeq)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 7. TestAddSegment_Overlap
// ---------------------------------------------------------------------------

func TestAddSegment_Overlap(t *testing.T) {
	now := time.Now()

	t.Run("overlapping_in_order_segments", func(t *testing.T) {
		buf := NewReassemblyBuffer(1000)

		// First segment: "hello" at 1000-1005
		n := buf.AddSegment(1000, []byte("hello"), now)
		if n != 5 {
			t.Errorf("first AddSegment() = %d, want 5", n)
		}

		// Overlapping segment: starts at 1003 ("lo" overlaps, "wor" is new)
		n = buf.AddSegment(1003, []byte("lowor"), now)
		if n != 3 {
			t.Errorf("overlapping AddSegment() = %d, want 3", n)
		}

		want := []byte("hellowor")
		if !bytes.Equal(buf.GetAssembled(), want) {
			t.Errorf("GetAssembled() = %q, want %q", buf.GetAssembled(), want)
		}
	})

	t.Run("overlapping_out_of_order_resolved_during_assembly", func(t *testing.T) {
		buf := NewReassemblyBuffer(1000)

		// Add overlapping out-of-order segments
		buf.AddSegment(1003, []byte("xxworld"), now) // pending: seq 1003, len 7, end 1010
		buf.AddSegment(1005, []byte("world"), now)   // pending: seq 1005, len 5, end 1010

		// Fill the gap - triggers assembly with overlap resolution:
		//   "abcde" at 1000 assembles (5 bytes), nextSeq -> 1005
		//   "xxworld" at 1003: overlap 2 bytes trimmed -> "world" appended (5 bytes), nextSeq -> 1010
		//   "world" at 1005: fully overlapped (startOffset 5 >= len 5), skipped
		n := buf.AddSegment(1000, []byte("abcde"), now)

		if n != 10 {
			t.Errorf("gap-fill AddSegment() = %d, want 10", n)
		}

		want := []byte("abcdeworld")
		if !bytes.Equal(buf.GetAssembled(), want) {
			t.Errorf("GetAssembled() = %q, want %q", buf.GetAssembled(), want)
		}
		if buf.GetPendingSegments() != 0 {
			t.Errorf("GetPendingSegments() = %d, want 0", buf.GetPendingSegments())
		}
	})

	t.Run("duplicate_segment_same_seq", func(t *testing.T) {
		buf := NewReassemblyBuffer(1000)

		// Out-of-order segment
		buf.AddSegment(1005, []byte("world"), now)
		if buf.GetPendingSegments() != 1 {
			t.Fatalf("expected 1 pending, got %d", buf.GetPendingSegments())
		}

		// Duplicate with same seq - shorter data, should be kept as-is
		buf.AddSegment(1005, []byte("wor"), now)
		if buf.GetPendingSegments() != 1 {
			t.Errorf("pending should still be 1 after duplicate, got %d", buf.GetPendingSegments())
		}

		// Duplicate with same seq - longer data, should replace
		buf.AddSegment(1005, []byte("worldX"), now)
		if buf.GetPendingSegments() != 1 {
			t.Errorf("pending should still be 1 after longer duplicate, got %d", buf.GetPendingSegments())
		}

		// Fill gap and verify the longer data was kept
		buf.AddSegment(1000, []byte("hello"), now)
		want := []byte("helloworldX")
		if !bytes.Equal(buf.GetAssembled(), want) {
			t.Errorf("GetAssembled() = %q, want %q", buf.GetAssembled(), want)
		}
	})
}

// ---------------------------------------------------------------------------
// 8. TestAddSegment_EmptyData
// ---------------------------------------------------------------------------

func TestAddSegment_EmptyData(t *testing.T) {
	tests := []struct {
		name string
		seq  uint32
		data []byte
	}{
		{"nil_data", 1000, nil},
		{"empty_slice", 1000, []byte{}},
		{"empty_string", 1000, []byte("")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := NewReassemblyBuffer(1000)
			got := buf.AddSegment(tt.seq, tt.data, time.Now())
			if got != 0 {
				t.Errorf("AddSegment() with empty data = %d, want 0", got)
			}
			if buf.GetAssembledLen() != 0 {
				t.Errorf("GetAssembledLen() = %d, want 0", buf.GetAssembledLen())
			}
			if buf.GetPendingSegments() != 0 {
				t.Errorf("GetPendingSegments() = %d, want 0", buf.GetPendingSegments())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 9. TestAddSegment_SequenceWrapAround
// ---------------------------------------------------------------------------

func TestAddSegment_SequenceWrapAround(t *testing.T) {
	now := time.Now()

	t.Run("wrap_around_assembly", func(t *testing.T) {
		// Start near MaxUint32 so sequence wraps to 0+
		initialSeq := uint32(math.MaxUint32 - 2) // 4294967293
		buf := NewReassemblyBuffer(initialSeq)

		// Segment covers 4294967293..4294967295 (3 bytes), wraps nextSeq to 0
		n := buf.AddSegment(initialSeq, []byte("abc"), now)
		if n != 3 {
			t.Errorf("pre-wrap AddSegment() = %d, want 3", n)
		}
		if buf.GetNextSeq() != initialSeq+3 {
			t.Errorf("GetNextSeq() = %d, want %d", buf.GetNextSeq(), initialSeq+3)
		}

		// Next segment at seq=0 (wrapped)
		wrappedSeq := initialSeq + 3 // should be 0 due to uint32 overflow
		n = buf.AddSegment(wrappedSeq, []byte("def"), now)
		if n != 3 {
			t.Errorf("post-wrap AddSegment() = %d, want 3", n)
		}

		want := []byte("abcdef")
		if !bytes.Equal(buf.GetAssembled(), want) {
			t.Errorf("GetAssembled() = %q, want %q", buf.GetAssembled(), want)
		}
	})

	t.Run("wrap_around_out_of_order", func(t *testing.T) {
		initialSeq := uint32(math.MaxUint32 - 4) // 4294967291
		buf := NewReassemblyBuffer(initialSeq)

		// Add segment that would be at seq 0 (after wrap) - out of order
		postWrapSeq := initialSeq + 5 // wraps to 0
		buf.AddSegment(postWrapSeq, []byte("post"), now)

		if buf.GetPendingSegments() != 1 {
			t.Fatalf("expected 1 pending, got %d", buf.GetPendingSegments())
		}

		// Fill gap with pre-wrap data
		n := buf.AddSegment(initialSeq, []byte("preWR"), now)
		// Should assemble both "preWR" (5) + "post" (4) = 9
		if n != 9 {
			t.Errorf("gap-fill AddSegment() = %d, want 9", n)
		}

		want := []byte("preWRpost")
		if !bytes.Equal(buf.GetAssembled(), want) {
			t.Errorf("GetAssembled() = %q, want %q", buf.GetAssembled(), want)
		}
	})

	t.Run("retransmission_across_wrap", func(t *testing.T) {
		initialSeq := uint32(math.MaxUint32 - 1) // 4294967294
		buf := NewReassemblyBuffer(initialSeq)

		// Assemble 4 bytes, nextSeq wraps to 2
		buf.AddSegment(initialSeq, []byte("abcd"), now)
		if buf.GetNextSeq() != initialSeq+4 {
			t.Fatalf("nextSeq = %d, want %d", buf.GetNextSeq(), initialSeq+4)
		}

		// Retransmit the same data - should return 0
		got := buf.AddSegment(initialSeq, []byte("abcd"), now)
		if got != 0 {
			t.Errorf("retransmission across wrap = %d, want 0", got)
		}
	})
}

// ---------------------------------------------------------------------------
// 10. TestAddSegment_MaxAssembledSize
// ---------------------------------------------------------------------------

func TestAddSegment_MaxAssembledSize(t *testing.T) {
	now := time.Now()

	t.Run("drops_when_at_limit", func(t *testing.T) {
		// Max assembled = 10 bytes
		buf := NewReassemblyBufferWithLimits(1000, 10, DefaultMaxPendingSegs)

		// Add 10 bytes (fills to limit)
		n := buf.AddSegment(1000, []byte("1234567890"), now)
		if n != 10 {
			t.Errorf("AddSegment() = %d, want 10", n)
		}

		// Next segment should be dropped (assembled is at limit)
		n = buf.AddSegment(1010, []byte("overflow"), now)
		if n != 0 {
			t.Errorf("AddSegment() at limit = %d, want 0", n)
		}

		droppedBytes, droppedSegs := buf.GetDroppedStats()
		if droppedBytes != 8 {
			t.Errorf("droppedBytes = %d, want 8", droppedBytes)
		}
		if droppedSegs != 1 {
			t.Errorf("droppedSegs = %d, want 1", droppedSegs)
		}
	})

	t.Run("allows_until_limit_reached", func(t *testing.T) {
		buf := NewReassemblyBufferWithLimits(0, 8, DefaultMaxPendingSegs)

		// Add 5 bytes (under limit)
		buf.AddSegment(0, []byte("aaaaa"), now)
		if buf.GetAssembledLen() != 5 {
			t.Fatalf("assembled len = %d, want 5", buf.GetAssembledLen())
		}

		// Add 5 more (assembled is 5 < 8, so not dropped at entry check,
		// but the assembly will push it to 10)
		n := buf.AddSegment(5, []byte("bbbbb"), now)
		if n != 5 {
			t.Errorf("AddSegment() under limit = %d, want 5", n)
		}

		// Now assembled is 10 >= 8, next segment should be dropped
		n = buf.AddSegment(10, []byte("c"), now)
		if n != 0 {
			t.Errorf("AddSegment() over limit = %d, want 0", n)
		}
	})

	t.Run("zero_max_disables_limit", func(t *testing.T) {
		buf := NewReassemblyBufferWithLimits(0, 0, DefaultMaxPendingSegs)

		// maxAssembledSize=0, so the condition `maxAssembledSize > 0` is false,
		// meaning no limit enforcement.
		n := buf.AddSegment(0, []byte("data"), now)
		if n != 4 {
			t.Errorf("AddSegment() = %d, want 4", n)
		}
	})
}

// ---------------------------------------------------------------------------
// 11. TestAddSegment_MaxPendingSegments
// ---------------------------------------------------------------------------

func TestAddSegment_MaxPendingSegments(t *testing.T) {
	now := time.Now()

	t.Run("enforces_pending_limit", func(t *testing.T) {
		buf := NewReassemblyBufferWithLimits(1000, DefaultMaxAssembledSize, 2)

		// Two out-of-order segments fill pending
		buf.AddSegment(1010, []byte("aa"), now)
		buf.AddSegment(1020, []byte("bb"), now)

		if buf.GetPendingSegments() != 2 {
			t.Fatalf("pending = %d, want 2", buf.GetPendingSegments())
		}

		// Third out-of-order segment should be dropped
		n := buf.AddSegment(1030, []byte("cc"), now)
		if n != 0 {
			t.Errorf("AddSegment() over pending limit = %d, want 0", n)
		}

		droppedBytes, droppedSegs := buf.GetDroppedStats()
		if droppedBytes != 2 {
			t.Errorf("droppedBytes = %d, want 2", droppedBytes)
		}
		if droppedSegs != 1 {
			t.Errorf("droppedSegs = %d, want 1", droppedSegs)
		}
	})

	t.Run("in_order_not_affected_by_pending_limit", func(t *testing.T) {
		buf := NewReassemblyBufferWithLimits(1000, DefaultMaxAssembledSize, 1)

		// In-order segment assembles immediately, does not count as pending
		n := buf.AddSegment(1000, []byte("hello"), now)
		if n != 5 {
			t.Errorf("in-order AddSegment() = %d, want 5", n)
		}

		// Another in-order segment
		n = buf.AddSegment(1005, []byte("world"), now)
		if n != 5 {
			t.Errorf("in-order AddSegment() = %d, want 5", n)
		}

		if buf.GetPendingSegments() != 0 {
			t.Errorf("pending = %d, want 0", buf.GetPendingSegments())
		}
	})

	t.Run("zero_max_pending_disables_limit", func(t *testing.T) {
		buf := NewReassemblyBufferWithLimits(1000, DefaultMaxAssembledSize, 0)

		// maxPendingSegs=0, condition `maxPendingSegs > 0` is false, no limit.
		n := buf.AddSegment(1010, []byte("out"), now)
		if n != 3 {
			t.Errorf("AddSegment() = %d, want 3", n)
		}
		if buf.GetPendingSegments() != 1 {
			t.Errorf("pending = %d, want 1", buf.GetPendingSegments())
		}
	})
}

// ---------------------------------------------------------------------------
// 12. TestCleanStaleSegments
// ---------------------------------------------------------------------------

func TestCleanStaleSegments(t *testing.T) {
	t.Run("removes_stale_segments", func(t *testing.T) {
		buf := NewReassemblyBuffer(1000)
		oldTime := time.Now().Add(-2 * time.Minute) // 2 minutes ago

		// Add stale out-of-order segments with old timestamps
		buf.AddSegment(1010, []byte("stale1"), oldTime)
		buf.AddSegment(1020, []byte("stale2"), oldTime)

		if buf.GetPendingSegments() != 2 {
			t.Fatalf("pending before clean = %d, want 2", buf.GetPendingSegments())
		}

		removed := buf.CleanStaleSegments(1 * time.Minute)
		if removed != 2 {
			t.Errorf("CleanStaleSegments() = %d, want 2", removed)
		}
		if buf.GetPendingSegments() != 0 {
			t.Errorf("pending after clean = %d, want 0", buf.GetPendingSegments())
		}

		droppedBytes, droppedSegs := buf.GetDroppedStats()
		if droppedBytes != 12 {
			t.Errorf("droppedBytes = %d, want 12", droppedBytes)
		}
		if droppedSegs != 2 {
			t.Errorf("droppedSegs = %d, want 2", droppedSegs)
		}
	})

	t.Run("keeps_fresh_segments", func(t *testing.T) {
		buf := NewReassemblyBuffer(1000)
		freshTime := time.Now() // just now

		buf.AddSegment(1010, []byte("fresh"), freshTime)

		removed := buf.CleanStaleSegments(1 * time.Minute)
		if removed != 0 {
			t.Errorf("CleanStaleSegments() = %d, want 0", removed)
		}
		if buf.GetPendingSegments() != 1 {
			t.Errorf("pending = %d, want 1", buf.GetPendingSegments())
		}
	})

	t.Run("mixed_stale_and_fresh", func(t *testing.T) {
		buf := NewReassemblyBuffer(1000)
		staleTime := time.Now().Add(-5 * time.Minute)
		freshTime := time.Now()

		buf.AddSegment(1010, []byte("stale"), staleTime)
		buf.AddSegment(1020, []byte("fresh"), freshTime)

		removed := buf.CleanStaleSegments(1 * time.Minute)
		if removed != 1 {
			t.Errorf("CleanStaleSegments() = %d, want 1", removed)
		}
		if buf.GetPendingSegments() != 1 {
			t.Errorf("pending = %d, want 1", buf.GetPendingSegments())
		}
	})

	t.Run("empty_buffer", func(t *testing.T) {
		buf := NewReassemblyBuffer(0)
		removed := buf.CleanStaleSegments(1 * time.Second)
		if removed != 0 {
			t.Errorf("CleanStaleSegments() on empty = %d, want 0", removed)
		}
	})
}

// ---------------------------------------------------------------------------
// 13. TestClear
// ---------------------------------------------------------------------------

func TestClear(t *testing.T) {
	now := time.Now()

	t.Run("clears_assembled_and_pending", func(t *testing.T) {
		buf := NewReassemblyBuffer(1000)

		// Build up some state
		buf.AddSegment(1000, []byte("hello"), now) // assembled
		buf.AddSegment(1010, []byte("pend"), now)  // pending

		if buf.GetAssembledLen() == 0 || buf.GetPendingSegments() == 0 {
			t.Fatal("precondition failed: buffer should have data")
		}

		buf.Clear()

		if buf.GetAssembledLen() != 0 {
			t.Errorf("assembled len after Clear() = %d, want 0", buf.GetAssembledLen())
		}
		if buf.GetPendingSegments() != 0 {
			t.Errorf("pending after Clear() = %d, want 0", buf.GetPendingSegments())
		}
	})

	t.Run("preserves_sequence_numbers", func(t *testing.T) {
		buf := NewReassemblyBuffer(1000)
		buf.AddSegment(1000, []byte("data"), now)
		nextSeqBefore := buf.GetNextSeq()

		buf.Clear()

		// nextSeq and baseSeq should be preserved
		if buf.GetNextSeq() != nextSeqBefore {
			t.Errorf("nextSeq changed after Clear(): %d != %d", buf.GetNextSeq(), nextSeqBefore)
		}
		if buf.RelativeSeq(1000) != 0 {
			t.Errorf("baseSeq changed after Clear()")
		}
	})

	t.Run("clear_empty_buffer", func(t *testing.T) {
		buf := NewReassemblyBuffer(0)
		buf.Clear() // should not panic

		if buf.GetAssembledLen() != 0 {
			t.Errorf("assembled len = %d, want 0", buf.GetAssembledLen())
		}
	})
}

// ---------------------------------------------------------------------------
// 14. TestGetDroppedStats
// ---------------------------------------------------------------------------

func TestGetDroppedStats(t *testing.T) {
	now := time.Now()

	t.Run("initial_zero", func(t *testing.T) {
		buf := NewReassemblyBuffer(0)
		b, s := buf.GetDroppedStats()
		if b != 0 || s != 0 {
			t.Errorf("initial stats = (%d, %d), want (0, 0)", b, s)
		}
	})

	t.Run("accumulates_drops_from_assembled_limit", func(t *testing.T) {
		buf := NewReassemblyBufferWithLimits(0, 5, DefaultMaxPendingSegs)

		buf.AddSegment(0, []byte("12345"), now) // fills to limit

		buf.AddSegment(5, []byte("abc"), now) // dropped (3 bytes)
		buf.AddSegment(8, []byte("de"), now)  // dropped (2 bytes)

		droppedBytes, droppedSegs := buf.GetDroppedStats()
		if droppedBytes != 5 {
			t.Errorf("droppedBytes = %d, want 5", droppedBytes)
		}
		if droppedSegs != 2 {
			t.Errorf("droppedSegs = %d, want 2", droppedSegs)
		}
	})

	t.Run("accumulates_drops_from_pending_limit", func(t *testing.T) {
		buf := NewReassemblyBufferWithLimits(0, DefaultMaxAssembledSize, 1)

		buf.AddSegment(10, []byte("first"), now)  // pending (1 slot)
		buf.AddSegment(20, []byte("second"), now) // dropped (6 bytes)
		buf.AddSegment(30, []byte("third"), now)  // dropped (5 bytes)

		droppedBytes, droppedSegs := buf.GetDroppedStats()
		if droppedBytes != 11 {
			t.Errorf("droppedBytes = %d, want 11", droppedBytes)
		}
		if droppedSegs != 2 {
			t.Errorf("droppedSegs = %d, want 2", droppedSegs)
		}
	})

	t.Run("accumulates_from_stale_cleanup", func(t *testing.T) {
		buf := NewReassemblyBuffer(0)
		staleTime := time.Now().Add(-10 * time.Minute)

		buf.AddSegment(10, []byte("old"), staleTime)
		buf.CleanStaleSegments(1 * time.Minute)

		droppedBytes, droppedSegs := buf.GetDroppedStats()
		if droppedBytes != 3 {
			t.Errorf("droppedBytes = %d, want 3", droppedBytes)
		}
		if droppedSegs != 1 {
			t.Errorf("droppedSegs = %d, want 1", droppedSegs)
		}
	})
}

// ---------------------------------------------------------------------------
// 15. TestGetPendingSegments
// ---------------------------------------------------------------------------

func TestGetPendingSegments(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		setup     func(*ReassemblyBuffer)
		wantCount int
	}{
		{
			name:      "empty_buffer",
			setup:     func(b *ReassemblyBuffer) {},
			wantCount: 0,
		},
		{
			name: "only_assembled_data",
			setup: func(b *ReassemblyBuffer) {
				b.AddSegment(0, []byte("hello"), now)
			},
			wantCount: 0,
		},
		{
			name: "one_pending",
			setup: func(b *ReassemblyBuffer) {
				b.AddSegment(10, []byte("gap"), now)
			},
			wantCount: 1,
		},
		{
			name: "multiple_pending",
			setup: func(b *ReassemblyBuffer) {
				b.AddSegment(10, []byte("a"), now)
				b.AddSegment(20, []byte("b"), now)
				b.AddSegment(30, []byte("c"), now)
			},
			wantCount: 3,
		},
		{
			name: "pending_resolved_by_gap_fill",
			setup: func(b *ReassemblyBuffer) {
				b.AddSegment(5, []byte("world"), now)
				b.AddSegment(0, []byte("hello"), now) // fills gap, resolves pending
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := NewReassemblyBuffer(0)
			tt.setup(buf)

			if got := buf.GetPendingSegments(); got != tt.wantCount {
				t.Errorf("GetPendingSegments() = %d, want %d", got, tt.wantCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 16. TestRelativeSeq
// ---------------------------------------------------------------------------

func TestRelativeSeq(t *testing.T) {
	tests := []struct {
		name       string
		initialSeq uint32
		absSeq     uint32
		wantRel    uint32
	}{
		{"zero_base", 0, 100, 100},
		{"same_as_base", 1000, 1000, 0},
		{"offset_from_base", 1000, 1050, 50},
		{"wrap_around", math.MaxUint32 - 10, 5, 16}, // 5 - (MaxUint32-10) = 16 with uint32 wrapping
		{"large_offset", 0, math.MaxUint32, math.MaxUint32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := NewReassemblyBuffer(tt.initialSeq)
			got := buf.RelativeSeq(tt.absSeq)
			if got != tt.wantRel {
				t.Errorf("RelativeSeq(%d) = %d, want %d", tt.absSeq, got, tt.wantRel)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 17. BenchmarkAddSegment_InOrder
// ---------------------------------------------------------------------------

func BenchmarkAddSegment_InOrder(b *testing.B) {
	data := make([]byte, 1460) // typical MSS
	for i := range data {
		data[i] = byte(i % 256)
	}
	now := time.Now()

	b.ResetTimer()
	b.ReportAllocs()

	buf := NewReassemblyBuffer(0)
	seq := uint32(0)
	for i := 0; i < b.N; i++ {
		buf.AddSegment(seq, data, now)
		seq += uint32(len(data))

		// Periodically clear to prevent unbounded memory growth
		if i%10000 == 0 && i > 0 {
			buf.Clear()
		}
	}
}

// ---------------------------------------------------------------------------
// 18. BenchmarkAddSegment_OutOfOrder
// ---------------------------------------------------------------------------

func BenchmarkAddSegment_OutOfOrder(b *testing.B) {
	segSize := uint32(100)
	data := make([]byte, segSize)
	for i := range data {
		data[i] = byte(i % 256)
	}
	now := time.Now()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Create a fresh buffer for each batch of out-of-order segments
		buf := NewReassemblyBufferWithLimits(0, 1024*1024, 1000)

		// Add segments in reverse order (worst case for pending)
		numSegs := 100
		for j := numSegs - 1; j >= 0; j-- {
			seq := uint32(j) * segSize
			buf.AddSegment(seq, data, now)
		}
	}
}

// ---------------------------------------------------------------------------
// 19. BenchmarkAddSegment_Large
// ---------------------------------------------------------------------------

func BenchmarkAddSegment_Large(b *testing.B) {
	sizes := []int{64, 1460, 8192, 65535}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i % 256)
			}
			now := time.Now()

			b.ResetTimer()
			b.ReportAllocs()

			buf := NewReassemblyBuffer(0)
			seq := uint32(0)
			for i := 0; i < b.N; i++ {
				buf.AddSegment(seq, data, now)
				seq += uint32(len(data))

				if i%1000 == 0 && i > 0 {
					buf.Clear()
				}
			}
		})
	}
}
