package uiadapter

import (
	"fmt"
	"sync"

	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/pkg/model"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
)

const (
	// MaxLivePackets is the maximum number of packets to keep in memory during live capture.
	MaxLivePackets = 100000
)

// LiveProvider provides data access for live capture mode.
type LiveProvider struct {
	mu      sync.RWMutex
	packets []*DisplayPacket
	flows   map[string]*model.Flow
	events  []*model.ExpertEvent

	packetChan chan *DisplayPacket
	stats      *Stats
}

// NewLiveProvider creates a new live data provider.
func NewLiveProvider() *LiveProvider {
	return &LiveProvider{
		packets:    make([]*DisplayPacket, 0, MaxLivePackets),
		flows:      make(map[string]*model.Flow),
		events:     make([]*model.ExpertEvent, 0),
		packetChan: make(chan *DisplayPacket, 1000),
		stats:      NewStats(),
	}
}

func (p *LiveProvider) IsLive() bool    { return true }
func (p *LiveProvider) IsIndexed() bool { return false }

func (p *LiveProvider) GetPacketCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.packets)
}

func (p *LiveProvider) GetPackets(offset, limit int) ([]*DisplayPacket, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if offset >= len(p.packets) {
		return nil, nil
	}

	end := offset + limit
	if end > len(p.packets) {
		end = len(p.packets)
	}

	return p.packets[offset:end], nil
}

func (p *LiveProvider) GetPacket(number int) (*DisplayPacket, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Packet number is 1-indexed
	idx := number - 1
	if idx < 0 || idx >= len(p.packets) {
		return nil, fmt.Errorf("packet not found: %d", number)
	}
	return p.packets[idx], nil
}

func (p *LiveProvider) GetRawPacket(number int) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	idx := number - 1
	if idx < 0 || idx >= len(p.packets) {
		return nil, fmt.Errorf("packet not found: %d", number)
	}
	
	if p.packets[idx].RawPacketInfo != nil {
		return p.packets[idx].RawPacketInfo.RawData, nil
	}
	return nil, fmt.Errorf("raw data not available")
}

func (p *LiveProvider) GetFlowCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.flows)
}

func (p *LiveProvider) GetFlows(offset, limit int) ([]*model.Flow, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	flows := make([]*model.Flow, 0, len(p.flows))
	for _, f := range p.flows {
		flows = append(flows, f)
	}

	// Simple pagination
	if offset >= len(flows) {
		return nil, nil
	}
	end := offset + limit
	if end > len(flows) {
		end = len(flows)
	}

	return flows[offset:end], nil
}

func (p *LiveProvider) GetFlow(id string) (*model.Flow, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if f, ok := p.flows[id]; ok {
		return f, nil
	}
	return nil, fmt.Errorf("flow not found: %s", id)
}

func (p *LiveProvider) GetExpertEvents(minSeverity int) ([]*model.ExpertEvent, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	filtered := make([]*model.ExpertEvent, 0)
	for _, e := range p.events {
		if e.Severity.Order() >= minSeverity {
			filtered = append(filtered, e)
		}
	}
	return filtered, nil
}

func (p *LiveProvider) GetExpertEventCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.events)
}

func (p *LiveProvider) GetStats() *Stats {
	return p.stats
}

func (p *LiveProvider) GetOverview() (*query.Overview, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var totalBytes int64
	for _, pkt := range p.packets {
		totalBytes += int64(pkt.Length)
	}

	return &query.Overview{
		TotalPackets:  len(p.packets),
		TotalFlows:    len(p.flows),
		TotalBytes:    totalBytes,
		WarningEvents: len(p.events),
	}, nil
}

func (p *LiveProvider) ReceivePacket() <-chan *DisplayPacket {
	return p.packetChan
}

func (p *LiveProvider) Close() error {
	close(p.packetChan)
	return nil
}

// AddPacket adds a captured packet to the live provider.
func (p *LiveProvider) AddPacket(pkt *DisplayPacket) {
	p.mu.Lock()
	if len(p.packets) < MaxLivePackets {
		p.packets = append(p.packets, pkt)
	}
	p.mu.Unlock()

	// Update stats
	p.stats.Update(pkt)

	// Non-blocking send to channel
	select {
	case p.packetChan <- pkt:
	default:
		// Channel full, drop packet notification
	}
}

// AddCapturedPacket converts and adds a captured packet.
func (p *LiveProvider) AddCapturedPacket(pktInfo *capture.PacketInfo) {
	pkt := ConvertFromPacketInfo(pktInfo)
	p.AddPacket(pkt)

	// Update flow aggregation
	p.updateFlow(pkt)
}

// updateFlow updates flow aggregation for the packet.
func (p *LiveProvider) updateFlow(pkt *DisplayPacket) {
	if pkt.FlowID == "" {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	flowID := pkt.FlowID
	flow, exists := p.flows[flowID]
	if !exists {
		srcPort := 0
		dstPort := 0
		fmt.Sscanf(pkt.SrcPort, "%d", &srcPort)
		fmt.Sscanf(pkt.DstPort, "%d", &dstPort)
		
		flow = &model.Flow{
			ID:       flowID,
			SrcIP:    pkt.SrcIP,
			DstIP:    pkt.DstIP,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Protocol: pkt.Protocol,
			StartNS:  pkt.Timestamp.UnixNano(),
			State:    "active",
		}
		p.flows[flowID] = flow
	}

	flow.Packets++
	flow.Bytes += int64(pkt.Length)
	flow.EndNS = pkt.Timestamp.UnixNano()
}

// AddExpertEvent adds an expert event.
func (p *LiveProvider) AddExpertEvent(event *model.ExpertEvent) {
	p.mu.Lock()
	p.events = append(p.events, event)
	p.mu.Unlock()
}
