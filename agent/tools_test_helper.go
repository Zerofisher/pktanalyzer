package agent

import (
	"github.com/Zerofisher/pktanalyzer/pkg/capture"
	uiadapter "github.com/Zerofisher/pktanalyzer/ui/adapter"
)

// MockPacketReadStore is a test implementation of uiadapter.PacketReadStore.
type MockPacketReadStore struct {
	packets []*uiadapter.DisplayPacket
}

// NewMockPacketReadStore creates a new MockPacketReadStore.
func NewMockPacketReadStore() *MockPacketReadStore {
	return &MockPacketReadStore{
		packets: make([]*uiadapter.DisplayPacket, 0),
	}
}

// AddPacket adds a packet to the mock store.
// Accepts capture.PacketInfo for test convenience and converts internally.
func (m *MockPacketReadStore) AddPacket(p capture.PacketInfo) {
	dp := &uiadapter.DisplayPacket{
		Number:        p.Number,
		Timestamp:     p.Timestamp,
		Length:        p.Length,
		SrcMAC:        p.SrcMAC,
		DstMAC:        p.DstMAC,
		SrcIP:         p.SrcIP,
		DstIP:         p.DstIP,
		SrcPort:       p.SrcPort,
		DstPort:       p.DstPort,
		Protocol:      p.Protocol,
		Info:          p.Info,
		SNI:           p.SNI,
		Decrypted:     p.Decrypted,
		TCPFlags:      p.TCPFlags,
		TCPSeq:        p.TCPSeq,
		TCPAck:        p.TCPAck,
		TCPWindow:     p.TCPWindow,
		FlowID:        p.StreamKey,
		RawPacketInfo: &p,
	}
	m.packets = append(m.packets, dp)
}

func (m *MockPacketReadStore) IsLive() bool    { return false }
func (m *MockPacketReadStore) IsIndexed() bool { return false }

// Count returns the number of packets.
func (m *MockPacketReadStore) Count() int {
	return len(m.packets)
}

// Get returns a single packet by number (1-based).
func (m *MockPacketReadStore) Get(number int) *uiadapter.DisplayPacket {
	for _, p := range m.packets {
		if p.Number == number {
			return p
		}
	}
	return nil
}

// GetRange returns packets in the given range.
func (m *MockPacketReadStore) GetRange(offset, limit int) []*uiadapter.DisplayPacket {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(m.packets) {
		return nil
	}
	end := offset + limit
	if end > len(m.packets) {
		end = len(m.packets)
	}
	result := make([]*uiadapter.DisplayPacket, end-offset)
	copy(result, m.packets[offset:end])
	return result
}

// GetRaw returns raw packet bytes.
func (m *MockPacketReadStore) GetRaw(number int) ([]byte, error) {
	for _, p := range m.packets {
		if p.Number == number && p.RawPacketInfo != nil {
			return p.RawPacketInfo.RawData, nil
		}
	}
	return nil, nil
}

// Close is a no-op for the mock store.
func (m *MockPacketReadStore) Close() error {
	return nil
}

// NewToolExecutorWithMock creates a ToolExecutor with a mock PacketReadStore for testing.
func NewToolExecutorWithMock() (*ToolExecutor, *MockPacketReadStore) {
	exec := NewToolExecutor()
	mock := NewMockPacketReadStore()
	exec.SetPacketReader(mock)
	return exec, mock
}
