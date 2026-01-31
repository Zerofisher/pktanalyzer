package agent

import (
	"github.com/Zerofisher/pktanalyzer/capture"
)

// MockPacketReader is a test implementation of PacketReader.
type MockPacketReader struct {
	packets []capture.PacketInfo
}

// NewMockPacketReader creates a new MockPacketReader.
func NewMockPacketReader() *MockPacketReader {
	return &MockPacketReader{
		packets: make([]capture.PacketInfo, 0),
	}
}

// AddPacket adds a packet to the mock reader.
func (m *MockPacketReader) AddPacket(p capture.PacketInfo) {
	m.packets = append(m.packets, p)
}

// Count returns the number of packets.
func (m *MockPacketReader) Count() int {
	return len(m.packets)
}

// GetPacketsForAgent returns packets in the given range.
func (m *MockPacketReader) GetPacketsForAgent(offset, limit int) []capture.PacketInfo {
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
	result := make([]capture.PacketInfo, end-offset)
	copy(result, m.packets[offset:end])
	return result
}

// GetPacketForAgent returns a single packet by number.
func (m *MockPacketReader) GetPacketForAgent(number int) *capture.PacketInfo {
	for i := range m.packets {
		if m.packets[i].Number == number {
			return &m.packets[i]
		}
	}
	return nil
}

// GetRaw returns raw packet bytes.
func (m *MockPacketReader) GetRaw(number int) ([]byte, error) {
	for i := range m.packets {
		if m.packets[i].Number == number {
			return m.packets[i].RawData, nil
		}
	}
	return nil, nil
}

// NewToolExecutorWithMock creates a ToolExecutor with a mock PacketReader for testing.
func NewToolExecutorWithMock() (*ToolExecutor, *MockPacketReader) {
	exec := NewToolExecutor()
	mock := NewMockPacketReader()
	exec.SetPacketReader(mock)
	return exec, mock
}
