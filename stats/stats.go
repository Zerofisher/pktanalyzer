// Package stats provides network traffic statistics similar to tshark -z options
package stats

import (
	"fmt"
	"io"
	"github.com/Zerofisher/pktanalyzer/capture"
	"sort"
	"strings"
	"time"
)

// Manager collects and reports various traffic statistics
type Manager struct {
	endpoints     map[string]*Endpoint
	conversations map[string]*Conversation
	ioBuckets     []*IOBucket
	bucketSize    time.Duration
	startTime     time.Time
	totalPackets  int
	totalBytes    int64
}

// Endpoint represents traffic statistics for a single IP address
type Endpoint struct {
	Address   string
	TxPackets int
	RxPackets int
	TxBytes   int64
	RxBytes   int64
}

// Conversation represents traffic between two endpoints
type Conversation struct {
	AddrA       string
	PortA       string
	AddrB       string
	PortB       string
	Protocol    string
	PacketsAtoB int
	PacketsBtoA int
	BytesAtoB   int64
	BytesBtoA   int64
	StartTime   time.Time
	LastSeen    time.Time
}

// IOBucket represents packet/byte counts for a time interval
type IOBucket struct {
	Timestamp time.Time
	Packets   int
	Bytes     int64
}

// NewManager creates a new statistics manager
func NewManager() *Manager {
	return &Manager{
		endpoints:     make(map[string]*Endpoint),
		conversations: make(map[string]*Conversation),
		ioBuckets:     make([]*IOBucket, 0),
		bucketSize:    time.Second,
	}
}

// SetBucketSize sets the I/O stats time interval
func (m *Manager) SetBucketSize(d time.Duration) {
	m.bucketSize = d
}

// ProcessPacket updates statistics with a new packet
func (m *Manager) ProcessPacket(pkt *capture.PacketInfo) {
	if m.startTime.IsZero() {
		m.startTime = pkt.Timestamp
	}

	m.totalPackets++
	m.totalBytes += int64(pkt.Length)

	// Update endpoints
	m.updateEndpoints(pkt)

	// Update conversations
	m.updateConversations(pkt)

	// Update I/O buckets
	m.updateIOBuckets(pkt)
}

func (m *Manager) updateEndpoints(pkt *capture.PacketInfo) {
	if pkt.SrcIP == "" || pkt.DstIP == "" {
		return
	}

	// Source endpoint (transmitting)
	src, ok := m.endpoints[pkt.SrcIP]
	if !ok {
		src = &Endpoint{Address: pkt.SrcIP}
		m.endpoints[pkt.SrcIP] = src
	}
	src.TxPackets++
	src.TxBytes += int64(pkt.Length)

	// Destination endpoint (receiving)
	dst, ok := m.endpoints[pkt.DstIP]
	if !ok {
		dst = &Endpoint{Address: pkt.DstIP}
		m.endpoints[pkt.DstIP] = dst
	}
	dst.RxPackets++
	dst.RxBytes += int64(pkt.Length)
}

func (m *Manager) updateConversations(pkt *capture.PacketInfo) {
	if pkt.SrcIP == "" || pkt.DstIP == "" {
		return
	}

	// Determine protocol type
	proto := "IP"
	if isTCP(pkt.Protocol) {
		proto = "TCP"
	} else if isUDP(pkt.Protocol) {
		proto = "UDP"
	}

	// Create consistent conversation key (lower address first)
	var addrA, portA, addrB, portB string
	if pkt.SrcIP < pkt.DstIP || (pkt.SrcIP == pkt.DstIP && pkt.SrcPort < pkt.DstPort) {
		addrA, portA = pkt.SrcIP, pkt.SrcPort
		addrB, portB = pkt.DstIP, pkt.DstPort
	} else {
		addrA, portA = pkt.DstIP, pkt.DstPort
		addrB, portB = pkt.SrcIP, pkt.SrcPort
	}

	key := fmt.Sprintf("%s:%s-%s:%s-%s", addrA, portA, addrB, portB, proto)

	conv, ok := m.conversations[key]
	if !ok {
		conv = &Conversation{
			AddrA:     addrA,
			PortA:     portA,
			AddrB:     addrB,
			PortB:     portB,
			Protocol:  proto,
			StartTime: pkt.Timestamp,
		}
		m.conversations[key] = conv
	}

	// Update direction-specific counters
	if pkt.SrcIP == addrA && pkt.SrcPort == portA {
		conv.PacketsAtoB++
		conv.BytesAtoB += int64(pkt.Length)
	} else {
		conv.PacketsBtoA++
		conv.BytesBtoA += int64(pkt.Length)
	}
	conv.LastSeen = pkt.Timestamp
}

func (m *Manager) updateIOBuckets(pkt *capture.PacketInfo) {
	if m.bucketSize <= 0 {
		return
	}

	// Calculate bucket index
	elapsed := pkt.Timestamp.Sub(m.startTime)
	bucketIdx := int(elapsed / m.bucketSize)

	// Extend buckets slice if needed
	for len(m.ioBuckets) <= bucketIdx {
		t := m.startTime.Add(time.Duration(len(m.ioBuckets)) * m.bucketSize)
		m.ioBuckets = append(m.ioBuckets, &IOBucket{Timestamp: t})
	}

	m.ioBuckets[bucketIdx].Packets++
	m.ioBuckets[bucketIdx].Bytes += int64(pkt.Length)
}

// PrintEndpoints writes endpoint statistics to the writer
func (m *Manager) PrintEndpoints(w io.Writer, proto string) {
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintf(w, "%-6s Endpoints\n", strings.ToUpper(proto))
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintf(w, "%-40s %10s %12s %10s %12s\n", "Address", "Packets", "Bytes", "Tx Packets", "Tx Bytes")

	// Collect and sort endpoints
	var endpoints []*Endpoint
	for _, ep := range m.endpoints {
		endpoints = append(endpoints, ep)
	}
	sort.Slice(endpoints, func(i, j int) bool {
		totalI := endpoints[i].TxBytes + endpoints[i].RxBytes
		totalJ := endpoints[j].TxBytes + endpoints[j].RxBytes
		return totalI > totalJ
	})

	for _, ep := range endpoints {
		total := ep.TxPackets + ep.RxPackets
		totalBytes := ep.TxBytes + ep.RxBytes
		fmt.Fprintf(w, "%-40s %10d %12s %10d %12s\n",
			ep.Address,
			total,
			formatBytes(totalBytes),
			ep.TxPackets,
			formatBytes(ep.TxBytes),
		)
	}
	fmt.Fprintf(w, "================================================================================\n")
}

// PrintConversations writes conversation statistics to the writer
func (m *Manager) PrintConversations(w io.Writer, proto string) {
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintf(w, "%-6s Conversations\n", strings.ToUpper(proto))
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintf(w, "%-22s %-22s %8s %10s %8s %10s %10s\n",
		"Address A", "Address B", "Packets", "Bytes", "Packets", "Bytes", "Duration")
	fmt.Fprintf(w, "%-22s %-22s %8s %10s %8s %10s %10s\n",
		"", "", "A->B", "A->B", "B->A", "B->A", "")

	// Filter and collect conversations
	var convs []*Conversation
	for _, conv := range m.conversations {
		if proto == "ip" || proto == "" || strings.EqualFold(conv.Protocol, proto) {
			convs = append(convs, conv)
		}
	}

	// Sort by total bytes
	sort.Slice(convs, func(i, j int) bool {
		totalI := convs[i].BytesAtoB + convs[i].BytesBtoA
		totalJ := convs[j].BytesAtoB + convs[j].BytesBtoA
		return totalI > totalJ
	})

	for _, conv := range convs {
		addrA := conv.AddrA
		if conv.PortA != "" {
			addrA = fmt.Sprintf("%s:%s", conv.AddrA, conv.PortA)
		}
		addrB := conv.AddrB
		if conv.PortB != "" {
			addrB = fmt.Sprintf("%s:%s", conv.AddrB, conv.PortB)
		}

		duration := conv.LastSeen.Sub(conv.StartTime)

		fmt.Fprintf(w, "%-22s %-22s %8d %10s %8d %10s %10s\n",
			truncate(addrA, 22),
			truncate(addrB, 22),
			conv.PacketsAtoB,
			formatBytes(conv.BytesAtoB),
			conv.PacketsBtoA,
			formatBytes(conv.BytesBtoA),
			formatDuration(duration),
		)
	}
	fmt.Fprintf(w, "================================================================================\n")
}

// PrintIOStats writes I/O statistics to the writer
func (m *Manager) PrintIOStats(w io.Writer, interval float64) {
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintf(w, "IO Statistics (interval: %.1fs)\n", interval)
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintf(w, "%-20s %12s %15s %12s %15s\n",
		"Interval", "Packets", "Bytes", "Packets/s", "Bits/s")

	for i, bucket := range m.ioBuckets {
		start := float64(i) * interval
		end := start + interval
		pps := float64(bucket.Packets) / interval
		bps := float64(bucket.Bytes*8) / interval

		fmt.Fprintf(w, "%-20s %12d %15s %12.1f %15s\n",
			fmt.Sprintf("%.1f - %.1f", start, end),
			bucket.Packets,
			formatBytes(bucket.Bytes),
			pps,
			formatBits(int64(bps)),
		)
	}

	// Print totals
	fmt.Fprintln(w, strings.Repeat("-", 80))
	duration := time.Duration(len(m.ioBuckets)) * m.bucketSize
	avgPps := float64(m.totalPackets) / duration.Seconds()
	avgBps := float64(m.totalBytes*8) / duration.Seconds()

	fmt.Fprintf(w, "%-20s %12d %15s %12.1f %15s\n",
		"Total",
		m.totalPackets,
		formatBytes(m.totalBytes),
		avgPps,
		formatBits(int64(avgBps)),
	)
	fmt.Fprintln(w, "================================================================================")
}

// Helper functions

func isTCP(proto string) bool {
	switch proto {
	case "TCP", "HTTP", "HTTPS", "TLS":
		return true
	}
	return false
}

func isUDP(proto string) bool {
	switch proto {
	case "UDP", "DNS", "NBNS", "LLMNR", "MDNS", "SSDP", "DHCP", "NTP", "SNMP":
		return true
	}
	return false
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatBits(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d bps", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cbps", float64(b)/float64(div), "kMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	return fmt.Sprintf("%.1fh", d.Hours())
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
