package stats

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Zerofisher/pktanalyzer/internal/format"
	"github.com/Zerofisher/pktanalyzer/pkg/capture"
)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

// makePacket builds a minimal capture.PacketInfo suitable for stats tests.
func makePacket(srcIP, dstIP, srcPort, dstPort, proto string, length int, ts time.Time) *capture.PacketInfo {
	return &capture.PacketInfo{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  proto,
		Length:    length,
		Timestamp: ts,
	}
}

var baseTime = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// 1. TestNewManager
// ---------------------------------------------------------------------------

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.bucketSize != time.Second {
		t.Errorf("default bucketSize = %v, want %v", m.bucketSize, time.Second)
	}
	if len(m.endpoints) != 0 {
		t.Errorf("endpoints should be empty, got %d entries", len(m.endpoints))
	}
	if len(m.conversations) != 0 {
		t.Errorf("conversations should be empty, got %d entries", len(m.conversations))
	}
	if len(m.ioBuckets) != 0 {
		t.Errorf("ioBuckets should be empty, got %d entries", len(m.ioBuckets))
	}
	if m.totalPackets != 0 {
		t.Errorf("totalPackets = %d, want 0", m.totalPackets)
	}
	if m.totalBytes != 0 {
		t.Errorf("totalBytes = %d, want 0", m.totalBytes)
	}
	if !m.startTime.IsZero() {
		t.Errorf("startTime should be zero, got %v", m.startTime)
	}
}

// ---------------------------------------------------------------------------
// 2. TestProcessPacket_Endpoints
// ---------------------------------------------------------------------------

func TestProcessPacket_Endpoints(t *testing.T) {
	m := NewManager()
	pkt := makePacket("10.0.0.1", "10.0.0.2", "12345", "80", "TCP", 100, baseTime)
	m.ProcessPacket(pkt)

	if len(m.endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(m.endpoints))
	}

	src := m.endpoints["10.0.0.1"]
	if src == nil {
		t.Fatal("source endpoint missing")
	}
	if src.TxPackets != 1 {
		t.Errorf("src TxPackets = %d, want 1", src.TxPackets)
	}
	if src.TxBytes != 100 {
		t.Errorf("src TxBytes = %d, want 100", src.TxBytes)
	}
	if src.RxPackets != 0 {
		t.Errorf("src RxPackets = %d, want 0", src.RxPackets)
	}

	dst := m.endpoints["10.0.0.2"]
	if dst == nil {
		t.Fatal("destination endpoint missing")
	}
	if dst.RxPackets != 1 {
		t.Errorf("dst RxPackets = %d, want 1", dst.RxPackets)
	}
	if dst.RxBytes != 100 {
		t.Errorf("dst RxBytes = %d, want 100", dst.RxBytes)
	}
	if dst.TxPackets != 0 {
		t.Errorf("dst TxPackets = %d, want 0", dst.TxPackets)
	}
}

// ---------------------------------------------------------------------------
// 3. TestProcessPacket_Conversations
// ---------------------------------------------------------------------------

func TestProcessPacket_Conversations(t *testing.T) {
	m := NewManager()

	// Packet from lower IP to higher IP.
	pkt1 := makePacket("10.0.0.1", "10.0.0.2", "12345", "80", "TCP", 200, baseTime)
	m.ProcessPacket(pkt1)

	if len(m.conversations) != 1 {
		t.Fatalf("expected 1 conversation, got %d", len(m.conversations))
	}

	// Find the conversation.
	var conv *Conversation
	for _, c := range m.conversations {
		conv = c
	}

	if conv.AddrA != "10.0.0.1" || conv.AddrB != "10.0.0.2" {
		t.Errorf("conversation addresses = %s,%s; want 10.0.0.1,10.0.0.2", conv.AddrA, conv.AddrB)
	}
	if conv.Protocol != "TCP" {
		t.Errorf("protocol = %s, want TCP", conv.Protocol)
	}
	if conv.PacketsAtoB != 1 {
		t.Errorf("PacketsAtoB = %d, want 1", conv.PacketsAtoB)
	}
	if conv.BytesAtoB != 200 {
		t.Errorf("BytesAtoB = %d, want 200", conv.BytesAtoB)
	}

	// Reverse-direction packet should update BtoA counters.
	pkt2 := makePacket("10.0.0.2", "10.0.0.1", "80", "12345", "TCP", 300, baseTime.Add(time.Millisecond))
	m.ProcessPacket(pkt2)

	if len(m.conversations) != 1 {
		t.Fatalf("expected still 1 conversation, got %d", len(m.conversations))
	}
	if conv.PacketsBtoA != 1 {
		t.Errorf("PacketsBtoA = %d, want 1", conv.PacketsBtoA)
	}
	if conv.BytesBtoA != 300 {
		t.Errorf("BytesBtoA = %d, want 300", conv.BytesBtoA)
	}
}

// ---------------------------------------------------------------------------
// 4. TestProcessPacket_IOBuckets
// ---------------------------------------------------------------------------

func TestProcessPacket_IOBuckets(t *testing.T) {
	m := NewManager()
	m.SetBucketSize(time.Second)

	// First packet at T+0 -> bucket 0
	m.ProcessPacket(makePacket("10.0.0.1", "10.0.0.2", "1", "2", "TCP", 50, baseTime))
	// Second packet at T+0.5s -> still bucket 0
	m.ProcessPacket(makePacket("10.0.0.1", "10.0.0.2", "1", "2", "TCP", 60, baseTime.Add(500*time.Millisecond)))
	// Third packet at T+1.5s -> bucket 1
	m.ProcessPacket(makePacket("10.0.0.1", "10.0.0.2", "1", "2", "TCP", 70, baseTime.Add(1500*time.Millisecond)))

	if len(m.ioBuckets) != 2 {
		t.Fatalf("expected 2 IO buckets, got %d", len(m.ioBuckets))
	}

	b0 := m.ioBuckets[0]
	if b0.Packets != 2 {
		t.Errorf("bucket0 packets = %d, want 2", b0.Packets)
	}
	if b0.Bytes != 110 {
		t.Errorf("bucket0 bytes = %d, want 110", b0.Bytes)
	}

	b1 := m.ioBuckets[1]
	if b1.Packets != 1 {
		t.Errorf("bucket1 packets = %d, want 1", b1.Packets)
	}
	if b1.Bytes != 70 {
		t.Errorf("bucket1 bytes = %d, want 70", b1.Bytes)
	}
}

// ---------------------------------------------------------------------------
// 5. TestProcessPacket_Multiple
// ---------------------------------------------------------------------------

func TestProcessPacket_Multiple(t *testing.T) {
	m := NewManager()
	packets := []*capture.PacketInfo{
		makePacket("10.0.0.1", "10.0.0.2", "1000", "80", "TCP", 100, baseTime),
		makePacket("10.0.0.2", "10.0.0.1", "80", "1000", "TCP", 200, baseTime.Add(time.Millisecond)),
		makePacket("10.0.0.1", "10.0.0.3", "2000", "443", "TLS", 300, baseTime.Add(2*time.Millisecond)),
	}
	for _, p := range packets {
		m.ProcessPacket(p)
	}

	if m.totalPackets != 3 {
		t.Errorf("totalPackets = %d, want 3", m.totalPackets)
	}
	if m.totalBytes != 600 {
		t.Errorf("totalBytes = %d, want 600", m.totalBytes)
	}

	// 3 unique IPs: 10.0.0.1, 10.0.0.2, 10.0.0.3
	if len(m.endpoints) != 3 {
		t.Errorf("endpoints count = %d, want 3", len(m.endpoints))
	}

	ep1 := m.endpoints["10.0.0.1"]
	if ep1.TxPackets != 2 || ep1.RxPackets != 1 {
		t.Errorf("10.0.0.1 Tx=%d Rx=%d, want Tx=2 Rx=1", ep1.TxPackets, ep1.RxPackets)
	}
	if ep1.TxBytes != 400 || ep1.RxBytes != 200 {
		t.Errorf("10.0.0.1 TxBytes=%d RxBytes=%d, want 400,200", ep1.TxBytes, ep1.RxBytes)
	}

	// 2 conversations: (10.0.0.1,10.0.0.2) and (10.0.0.1,10.0.0.3)
	if len(m.conversations) != 2 {
		t.Errorf("conversations count = %d, want 2", len(m.conversations))
	}

	// TLS should map to TCP protocol in conversations
	for _, conv := range m.conversations {
		if conv.AddrA == "10.0.0.1" && conv.AddrB == "10.0.0.3" {
			if conv.Protocol != "TCP" {
				t.Errorf("TLS conversation protocol = %s, want TCP", conv.Protocol)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 6. TestSetBucketSize
// ---------------------------------------------------------------------------

func TestSetBucketSize(t *testing.T) {
	m := NewManager()
	if m.bucketSize != time.Second {
		t.Fatalf("initial bucketSize = %v, want 1s", m.bucketSize)
	}

	m.SetBucketSize(5 * time.Second)
	if m.bucketSize != 5*time.Second {
		t.Errorf("after SetBucketSize(5s), bucketSize = %v", m.bucketSize)
	}

	// Process packets spread over 5 seconds -- should land in single bucket.
	m.ProcessPacket(makePacket("10.0.0.1", "10.0.0.2", "1", "2", "TCP", 10, baseTime))
	m.ProcessPacket(makePacket("10.0.0.1", "10.0.0.2", "1", "2", "TCP", 20, baseTime.Add(4*time.Second)))

	if len(m.ioBuckets) != 1 {
		t.Errorf("expected 1 bucket for 5s window, got %d", len(m.ioBuckets))
	}
	if m.ioBuckets[0].Packets != 2 {
		t.Errorf("bucket packets = %d, want 2", m.ioBuckets[0].Packets)
	}
}

// ---------------------------------------------------------------------------
// 7. TestPrintEndpoints
// ---------------------------------------------------------------------------

func TestPrintEndpoints(t *testing.T) {
	m := NewManager()
	m.ProcessPacket(makePacket("192.168.1.1", "192.168.1.2", "5000", "80", "TCP", 500, baseTime))
	m.ProcessPacket(makePacket("192.168.1.2", "192.168.1.1", "80", "5000", "TCP", 1200, baseTime.Add(time.Millisecond)))

	var buf bytes.Buffer
	m.PrintEndpoints(&buf, "ip")
	out := buf.String()

	if !strings.Contains(out, "192.168.1.1") {
		t.Error("output missing 192.168.1.1")
	}
	if !strings.Contains(out, "192.168.1.2") {
		t.Error("output missing 192.168.1.2")
	}
	if !strings.Contains(out, "Endpoints") {
		t.Error("output missing header 'Endpoints'")
	}
	if !strings.Contains(out, "Address") {
		t.Error("output missing column header 'Address'")
	}
}

// ---------------------------------------------------------------------------
// 8. TestPrintConversations
// ---------------------------------------------------------------------------

func TestPrintConversations(t *testing.T) {
	m := NewManager()
	m.ProcessPacket(makePacket("10.1.1.1", "10.1.1.2", "3000", "443", "TCP", 1500, baseTime))
	m.ProcessPacket(makePacket("10.1.1.2", "10.1.1.1", "443", "3000", "TCP", 800, baseTime.Add(100*time.Millisecond)))

	var buf bytes.Buffer
	m.PrintConversations(&buf, "tcp")
	out := buf.String()

	if !strings.Contains(out, "Conversations") {
		t.Error("output missing header 'Conversations'")
	}
	if !strings.Contains(out, "10.1.1.1") {
		t.Error("output missing address 10.1.1.1")
	}
	if !strings.Contains(out, "10.1.1.2") {
		t.Error("output missing address 10.1.1.2")
	}
	// Duration should appear (100ms).
	if !strings.Contains(out, "ms") {
		t.Error("output missing duration in ms")
	}
}

// ---------------------------------------------------------------------------
// 9. TestPrintIOStats
// ---------------------------------------------------------------------------

func TestPrintIOStats(t *testing.T) {
	m := NewManager()
	m.ProcessPacket(makePacket("10.0.0.1", "10.0.0.2", "1", "2", "TCP", 1000, baseTime))
	m.ProcessPacket(makePacket("10.0.0.1", "10.0.0.2", "1", "2", "TCP", 2000, baseTime.Add(1500*time.Millisecond)))

	var buf bytes.Buffer
	m.PrintIOStats(&buf, 1.0)
	out := buf.String()

	if !strings.Contains(out, "IO Statistics") {
		t.Error("output missing header 'IO Statistics'")
	}
	if !strings.Contains(out, "Packets") {
		t.Error("output missing column 'Packets'")
	}
	if !strings.Contains(out, "Total") {
		t.Error("output missing 'Total' summary row")
	}
	// Two buckets should be present (0.0-1.0 and 1.0-2.0).
	if !strings.Contains(out, "0.0") {
		t.Error("output missing first interval start")
	}
}

// ---------------------------------------------------------------------------
// 10. TestProcessPacket_Empty
// ---------------------------------------------------------------------------

func TestProcessPacket_Empty(t *testing.T) {
	m := NewManager()

	// Packet with missing SrcIP -- endpoints and conversations should be skipped.
	pkt := makePacket("", "10.0.0.2", "", "80", "TCP", 50, baseTime)
	m.ProcessPacket(pkt)

	if len(m.endpoints) != 0 {
		t.Errorf("expected 0 endpoints for empty SrcIP, got %d", len(m.endpoints))
	}
	if len(m.conversations) != 0 {
		t.Errorf("expected 0 conversations for empty SrcIP, got %d", len(m.conversations))
	}

	// totalPackets and IO buckets should still update.
	if m.totalPackets != 1 {
		t.Errorf("totalPackets = %d, want 1", m.totalPackets)
	}

	// Packet with missing DstIP.
	pkt2 := makePacket("10.0.0.1", "", "12345", "", "UDP", 60, baseTime.Add(time.Millisecond))
	m.ProcessPacket(pkt2)

	if len(m.endpoints) != 0 {
		t.Errorf("expected 0 endpoints for empty DstIP, got %d", len(m.endpoints))
	}
	if m.totalPackets != 2 {
		t.Errorf("totalPackets = %d, want 2", m.totalPackets)
	}
}

// ---------------------------------------------------------------------------
// 11. TestConversation_ProtocolDetection
// ---------------------------------------------------------------------------

func TestConversation_ProtocolDetection(t *testing.T) {
	tests := []struct {
		protocol string
		wantConv string
	}{
		{"TCP", "TCP"},
		{"HTTP", "TCP"},
		{"HTTPS", "TCP"},
		{"TLS", "TCP"},
		{"UDP", "UDP"},
		{"DNS", "UDP"},
		{"NBNS", "UDP"},
		{"LLMNR", "UDP"},
		{"MDNS", "UDP"},
		{"SSDP", "UDP"},
		{"DHCP", "UDP"},
		{"NTP", "UDP"},
		{"SNMP", "UDP"},
		{"ICMP", "IP"},
		{"ICMPv6", "IP"},
		{"ARP", "IP"},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			m := NewManager()
			pkt := makePacket("10.0.0.1", "10.0.0.2", "100", "200", tt.protocol, 64, baseTime)
			m.ProcessPacket(pkt)

			var conv *Conversation
			for _, c := range m.conversations {
				conv = c
			}
			if conv == nil {
				t.Fatal("no conversation created")
			}
			if conv.Protocol != tt.wantConv {
				t.Errorf("protocol %s -> conversation protocol %s, want %s", tt.protocol, conv.Protocol, tt.wantConv)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 12. TestConversation_NormalizedKey
// ---------------------------------------------------------------------------

func TestConversation_NormalizedKey(t *testing.T) {
	m := NewManager()

	// Send from the "higher" IP first -- AddrA should still be the lower IP.
	pkt := makePacket("192.168.1.100", "10.0.0.1", "5000", "80", "TCP", 100, baseTime)
	m.ProcessPacket(pkt)

	var conv *Conversation
	for _, c := range m.conversations {
		conv = c
	}
	if conv == nil {
		t.Fatal("no conversation created")
	}
	if conv.AddrA != "10.0.0.1" {
		t.Errorf("AddrA = %s, want 10.0.0.1 (lower IP)", conv.AddrA)
	}
	if conv.AddrB != "192.168.1.100" {
		t.Errorf("AddrB = %s, want 192.168.1.100 (higher IP)", conv.AddrB)
	}
	// Since src (192.168.1.100) is AddrB, the packet should count as BtoA.
	if conv.PacketsBtoA != 1 {
		t.Errorf("PacketsBtoA = %d, want 1", conv.PacketsBtoA)
	}
	if conv.PacketsAtoB != 0 {
		t.Errorf("PacketsAtoB = %d, want 0", conv.PacketsAtoB)
	}
}

// ---------------------------------------------------------------------------
// 13. TestFormatBytes (via PrintEndpoints output)
// ---------------------------------------------------------------------------

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		got := format.FormatBytes(tt.input)
		if got != tt.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// 14. TestFormatBits
// ---------------------------------------------------------------------------

func TestFormatBits(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 bps"},
		{999, "999 bps"},
		{1000, "1.0 kbps"},
		{1500, "1.5 kbps"},
		{1000000, "1.0 Mbps"},
		{1000000000, "1.0 Gbps"},
	}

	for _, tt := range tests {
		got := format.FormatBits(tt.input)
		if got != tt.want {
			t.Errorf("FormatBits(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// 15. TestFormatDuration
// ---------------------------------------------------------------------------

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input time.Duration
		want  string
	}{
		{500 * time.Millisecond, "500ms"},
		{0, "0ms"},
		{time.Second, "1.00s"},
		{2500 * time.Millisecond, "2.50s"},
		{90 * time.Second, "1.5m"},
		{2 * time.Hour, "2.0h"},
	}

	for _, tt := range tests {
		got := formatDuration(tt.input)
		if got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// 16. TestPrintConversations_FilterByProto
// ---------------------------------------------------------------------------

func TestPrintConversations_FilterByProto(t *testing.T) {
	m := NewManager()
	m.ProcessPacket(makePacket("10.0.0.1", "10.0.0.2", "1000", "80", "TCP", 100, baseTime))
	m.ProcessPacket(makePacket("10.0.0.1", "10.0.0.3", "2000", "53", "DNS", 50, baseTime))

	// Filter to TCP only.
	var buf bytes.Buffer
	m.PrintConversations(&buf, "tcp")
	out := buf.String()

	if !strings.Contains(out, "10.0.0.2") {
		t.Error("TCP conversation should appear when filtering by tcp")
	}
	// DNS maps to UDP; the filter is "tcp", so it should not appear.
	if strings.Contains(out, "10.0.0.3") {
		t.Error("UDP conversation should not appear when filtering by tcp")
	}
}

// ---------------------------------------------------------------------------
// 17. TestIOBuckets_GapFilling
// ---------------------------------------------------------------------------

func TestIOBuckets_GapFilling(t *testing.T) {
	m := NewManager()
	m.SetBucketSize(time.Second)

	// Packet at T+0 and T+3s should create 4 buckets (0,1,2,3) with
	// buckets 1 and 2 being empty.
	m.ProcessPacket(makePacket("10.0.0.1", "10.0.0.2", "1", "2", "TCP", 10, baseTime))
	m.ProcessPacket(makePacket("10.0.0.1", "10.0.0.2", "1", "2", "TCP", 20, baseTime.Add(3*time.Second)))

	if len(m.ioBuckets) != 4 {
		t.Fatalf("expected 4 buckets with gap filling, got %d", len(m.ioBuckets))
	}

	if m.ioBuckets[0].Packets != 1 || m.ioBuckets[0].Bytes != 10 {
		t.Errorf("bucket[0] = {%d, %d}, want {1, 10}", m.ioBuckets[0].Packets, m.ioBuckets[0].Bytes)
	}
	if m.ioBuckets[1].Packets != 0 || m.ioBuckets[2].Packets != 0 {
		t.Error("gap buckets should have 0 packets")
	}
	if m.ioBuckets[3].Packets != 1 || m.ioBuckets[3].Bytes != 20 {
		t.Errorf("bucket[3] = {%d, %d}, want {1, 20}", m.ioBuckets[3].Packets, m.ioBuckets[3].Bytes)
	}
}

// ---------------------------------------------------------------------------
// 18. TestStartTime
// ---------------------------------------------------------------------------

func TestStartTime(t *testing.T) {
	m := NewManager()
	ts1 := baseTime.Add(10 * time.Second)
	ts2 := baseTime.Add(20 * time.Second)

	m.ProcessPacket(makePacket("10.0.0.1", "10.0.0.2", "1", "2", "TCP", 10, ts1))
	m.ProcessPacket(makePacket("10.0.0.1", "10.0.0.2", "1", "2", "TCP", 10, ts2))

	// startTime should be set to the first packet's timestamp and not change.
	if !m.startTime.Equal(ts1) {
		t.Errorf("startTime = %v, want %v", m.startTime, ts1)
	}
}

// ---------------------------------------------------------------------------
// BenchmarkProcessPacket
// ---------------------------------------------------------------------------

func BenchmarkProcessPacket(b *testing.B) {
	m := NewManager()
	pkt := makePacket("10.0.0.1", "10.0.0.2", "12345", "80", "TCP", 1500, baseTime)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Advance timestamp to avoid all packets landing in the same bucket.
		pkt.Timestamp = baseTime.Add(time.Duration(i) * time.Millisecond)
		m.ProcessPacket(pkt)
	}
}
