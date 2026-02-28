package export

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Zerofisher/pktanalyzer/capture"
)

// testTimestamp is a fixed timestamp used across all tests for deterministic output.
var testTimestamp = time.Date(2025, 6, 15, 10, 30, 45, 123456000, time.UTC)

// newTestPacket creates a PacketInfo suitable for testing with realistic field values.
func newTestPacket() *capture.PacketInfo {
	return &capture.PacketInfo{
		Number:    1,
		Timestamp: testTimestamp,
		SrcIP:     "192.168.1.1",
		DstIP:     "10.0.0.1",
		SrcPort:   "12345",
		DstPort:   "80",
		Protocol:  "TCP",
		Length:    100,
		Info:      "test info",
		RawData:   []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f},
		Layers: []capture.LayerInfo{
			{
				Name: "Ethernet II",
				Details: []string{
					"Source: aa:bb:cc:dd:ee:ff",
					"Destination: 11:22:33:44:55:66",
				},
			},
			{
				Name: "IPv4",
				Details: []string{
					"Source: 192.168.1.1",
					"Destination: 10.0.0.1",
					"TTL: 64",
				},
			},
			{
				Name: "TCP",
				Details: []string{
					"Source Port: 12345",
					"Destination Port: 80",
					"Flags: SYN",
				},
			},
		},
	}
}

func TestExporter_Text(t *testing.T) {
	var buf bytes.Buffer
	exp := NewExporter(&buf, FormatText)

	pkt := newTestPacket()
	if err := exp.ExportPacket(pkt); err != nil {
		t.Fatalf("ExportPacket returned error: %v", err)
	}

	output := buf.String()

	// The text format should contain tab-separated fields:
	// Number Time Src Dst Protocol Length Info
	if !strings.Contains(output, "1\t") {
		t.Error("output should contain frame number '1'")
	}
	if !strings.Contains(output, "10:30:45.123456") {
		t.Errorf("output should contain formatted timestamp, got: %s", output)
	}
	if !strings.Contains(output, "192.168.1.1:12345") {
		t.Errorf("output should contain source IP:port, got: %s", output)
	}
	if !strings.Contains(output, "10.0.0.1:80") {
		t.Errorf("output should contain destination IP:port, got: %s", output)
	}
	if !strings.Contains(output, "TCP") {
		t.Error("output should contain protocol 'TCP'")
	}
	if !strings.Contains(output, "100") {
		t.Error("output should contain length '100'")
	}
	if !strings.Contains(output, "test info") {
		t.Error("output should contain info 'test info'")
	}
}

func TestExporter_Text_WithDetail(t *testing.T) {
	var buf bytes.Buffer
	exp := NewExporter(&buf, FormatText)
	exp.SetShowDetail(true)

	pkt := newTestPacket()
	if err := exp.ExportPacket(pkt); err != nil {
		t.Fatalf("ExportPacket returned error: %v", err)
	}

	output := buf.String()

	// Detail mode should include layer information
	if !strings.Contains(output, "Frame 1:") {
		t.Errorf("detail output should contain 'Frame 1:', got: %s", output)
	}
	if !strings.Contains(output, "100 bytes on wire") {
		t.Errorf("detail output should contain byte count, got: %s", output)
	}
	if !strings.Contains(output, "Arrival Time:") {
		t.Error("detail output should contain 'Arrival Time:'")
	}
	if !strings.Contains(output, "Ethernet II:") {
		t.Error("detail output should contain 'Ethernet II:' layer")
	}
	if !strings.Contains(output, "IPv4:") {
		t.Error("detail output should contain 'IPv4:' layer")
	}
	if !strings.Contains(output, "TCP:") {
		t.Error("detail output should contain 'TCP:' layer")
	}
	if !strings.Contains(output, "Source Port: 12345") {
		t.Error("detail output should contain TCP detail 'Source Port: 12345'")
	}
	if !strings.Contains(output, "TTL: 64") {
		t.Error("detail output should contain IPv4 detail 'TTL: 64'")
	}
}

func TestExporter_Text_WithHex(t *testing.T) {
	var buf bytes.Buffer
	exp := NewExporter(&buf, FormatText)
	exp.SetShowHex(true)

	pkt := newTestPacket()
	if err := exp.ExportPacket(pkt); err != nil {
		t.Fatalf("ExportPacket returned error: %v", err)
	}

	output := buf.String()

	// Hex dump should contain offset, hex bytes, and ASCII representation
	if !strings.Contains(output, "Hex dump of packet 1") {
		t.Errorf("hex output should contain header, got: %s", output)
	}
	if !strings.Contains(output, "5 bytes") {
		t.Errorf("hex output should show byte count, got: %s", output)
	}
	// RawData is "Hello" -> 48 65 6c 6c 6f
	if !strings.Contains(output, "48 65 6c 6c 6f") {
		t.Errorf("hex output should contain hex bytes for 'Hello', got: %s", output)
	}
	// ASCII column should show "Hello"
	if !strings.Contains(output, "Hello") {
		t.Errorf("hex output should contain ASCII representation 'Hello', got: %s", output)
	}
	// Should contain offset prefix
	if !strings.Contains(output, "00000000") {
		t.Error("hex output should contain offset '00000000'")
	}
}

func TestExporter_JSON(t *testing.T) {
	var buf bytes.Buffer
	exp := NewExporter(&buf, FormatJSON)

	if err := exp.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	pkt := newTestPacket()
	if err := exp.ExportPacket(pkt); err != nil {
		t.Fatalf("ExportPacket returned error: %v", err)
	}

	if err := exp.Finish(); err != nil {
		t.Fatalf("Finish returned error: %v", err)
	}

	output := buf.String()

	// The output should be a valid JSON array
	if !strings.HasPrefix(strings.TrimSpace(output), "[") {
		t.Errorf("JSON output should start with '[', got: %s", output)
	}
	if !strings.HasSuffix(strings.TrimSpace(output), "]") {
		t.Errorf("JSON output should end with ']', got: %s", output)
	}

	// Parse the JSON array to validate structure
	var packets []PacketJSON
	if err := json.Unmarshal([]byte(output), &packets); err != nil {
		t.Fatalf("JSON output is not valid: %v\nOutput: %s", err, output)
	}

	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}

	p := packets[0]
	if p.FrameNumber != 1 {
		t.Errorf("frame.number = %d, want 1", p.FrameNumber)
	}
	if p.Protocol != "TCP" {
		t.Errorf("protocol = %q, want %q", p.Protocol, "TCP")
	}
	if p.Info != "test info" {
		t.Errorf("info = %q, want %q", p.Info, "test info")
	}
	if p.IPSrc != "192.168.1.1" {
		t.Errorf("ip.src = %q, want %q", p.IPSrc, "192.168.1.1")
	}
	if p.IPDst != "10.0.0.1" {
		t.Errorf("ip.dst = %q, want %q", p.IPDst, "10.0.0.1")
	}
	if p.FrameLen != 100 {
		t.Errorf("frame.len = %d, want 100", p.FrameLen)
	}
	// TCP-specific fields should be populated
	if p.TCPSrcPort == nil || *p.TCPSrcPort != 12345 {
		t.Errorf("tcp.srcport should be 12345, got %v", p.TCPSrcPort)
	}
	if p.TCPDstPort == nil || *p.TCPDstPort != 80 {
		t.Errorf("tcp.dstport should be 80, got %v", p.TCPDstPort)
	}
	// Layers should be present
	if len(p.Layers) != 3 {
		t.Errorf("expected 3 layers, got %d", len(p.Layers))
	}
}

func TestExporter_JSON_Multiple(t *testing.T) {
	var buf bytes.Buffer
	exp := NewExporter(&buf, FormatJSON)

	if err := exp.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	// Export first packet
	pkt1 := newTestPacket()
	pkt1.Number = 1
	if err := exp.ExportPacket(pkt1); err != nil {
		t.Fatalf("ExportPacket(1) returned error: %v", err)
	}

	// Export second packet
	pkt2 := newTestPacket()
	pkt2.Number = 2
	pkt2.SrcIP = "10.0.0.2"
	pkt2.DstIP = "10.0.0.3"
	pkt2.Info = "second packet"
	if err := exp.ExportPacket(pkt2); err != nil {
		t.Fatalf("ExportPacket(2) returned error: %v", err)
	}

	// Export third packet
	pkt3 := newTestPacket()
	pkt3.Number = 3
	pkt3.Protocol = "HTTP"
	pkt3.Info = "GET / HTTP/1.1"
	if err := exp.ExportPacket(pkt3); err != nil {
		t.Fatalf("ExportPacket(3) returned error: %v", err)
	}

	if err := exp.Finish(); err != nil {
		t.Fatalf("Finish returned error: %v", err)
	}

	output := buf.String()

	// Should be valid JSON with 3 elements
	var packets []PacketJSON
	if err := json.Unmarshal([]byte(output), &packets); err != nil {
		t.Fatalf("JSON output is not valid: %v\nOutput: %s", err, output)
	}

	if len(packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(packets))
	}

	// Verify comma separation exists between objects (not after last)
	if !strings.Contains(output, "},") {
		t.Error("multiple JSON packets should be comma-separated")
	}

	// Verify each packet
	if packets[0].FrameNumber != 1 {
		t.Errorf("first packet number = %d, want 1", packets[0].FrameNumber)
	}
	if packets[1].FrameNumber != 2 {
		t.Errorf("second packet number = %d, want 2", packets[1].FrameNumber)
	}
	if packets[1].IPSrc != "10.0.0.2" {
		t.Errorf("second packet ip.src = %q, want %q", packets[1].IPSrc, "10.0.0.2")
	}
	if packets[2].FrameNumber != 3 {
		t.Errorf("third packet number = %d, want 3", packets[2].FrameNumber)
	}
	if packets[2].Info != "GET / HTTP/1.1" {
		t.Errorf("third packet info = %q, want %q", packets[2].Info, "GET / HTTP/1.1")
	}
}

func TestExporter_Fields(t *testing.T) {
	var buf bytes.Buffer
	exp := NewExporter(&buf, FormatFields)
	exp.SetFields([]string{"ip.src", "ip.dst", "frame.number"})

	pkt := newTestPacket()
	if err := exp.ExportPacket(pkt); err != nil {
		t.Fatalf("ExportPacket returned error: %v", err)
	}

	output := buf.String()

	// Fields format is tab-separated values
	if !strings.Contains(output, "192.168.1.1") {
		t.Errorf("fields output should contain source IP, got: %s", output)
	}
	if !strings.Contains(output, "10.0.0.1") {
		t.Errorf("fields output should contain destination IP, got: %s", output)
	}
	if !strings.Contains(output, "1") {
		t.Errorf("fields output should contain frame number, got: %s", output)
	}

	// Verify tab separation: the line should have exactly 2 tabs (3 fields)
	line := strings.TrimSpace(output)
	parts := strings.Split(line, "\t")
	if len(parts) != 3 {
		t.Errorf("expected 3 tab-separated fields, got %d: %q", len(parts), line)
	}
	if parts[0] != "192.168.1.1" {
		t.Errorf("first field = %q, want %q", parts[0], "192.168.1.1")
	}
	if parts[1] != "10.0.0.1" {
		t.Errorf("second field = %q, want %q", parts[1], "10.0.0.1")
	}
	if parts[2] != "1" {
		t.Errorf("third field = %q, want %q", parts[2], "1")
	}
}

func TestExporter_MaxCount(t *testing.T) {
	var buf bytes.Buffer
	exp := NewExporter(&buf, FormatText)
	exp.SetMaxCount(2)

	// Export 5 packets; only the first 2 should produce output
	for i := 1; i <= 5; i++ {
		pkt := newTestPacket()
		pkt.Number = i
		if err := exp.ExportPacket(pkt); err != nil {
			t.Fatalf("ExportPacket(%d) returned error: %v", i, err)
		}
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines of output with maxCount=2, got %d lines:\n%s", len(lines), output)
	}
}

func TestShouldStop(t *testing.T) {
	tests := []struct {
		name     string
		maxCount int
		exported int
		want     bool
	}{
		{
			name:     "unlimited, zero exported",
			maxCount: 0,
			exported: 0,
			want:     false,
		},
		{
			name:     "unlimited, many exported",
			maxCount: 0,
			exported: 100,
			want:     false,
		},
		{
			name:     "limit 5, 3 exported",
			maxCount: 5,
			exported: 3,
			want:     false,
		},
		{
			name:     "limit 5, 5 exported",
			maxCount: 5,
			exported: 5,
			want:     true,
		},
		{
			name:     "limit 5, 7 exported",
			maxCount: 5,
			exported: 7,
			want:     true,
		},
		{
			name:     "limit 1, 0 exported",
			maxCount: 1,
			exported: 0,
			want:     false,
		},
		{
			name:     "limit 1, 1 exported",
			maxCount: 1,
			exported: 1,
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			exp := NewExporter(&buf, FormatText)
			exp.SetMaxCount(tt.maxCount)

			// Simulate exporting packets to increment the internal counter
			for i := 0; i < tt.exported; i++ {
				pkt := newTestPacket()
				pkt.Number = i + 1
				_ = exp.ExportPacket(pkt)
			}

			got := exp.ShouldStop()
			if got != tt.want {
				t.Errorf("ShouldStop() = %v, want %v (maxCount=%d, exported=%d)",
					got, tt.want, tt.maxCount, tt.exported)
			}
		})
	}
}

func TestExporter_Start_Finish_JSON(t *testing.T) {
	var buf bytes.Buffer
	exp := NewExporter(&buf, FormatJSON)

	if err := exp.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	if err := exp.Finish(); err != nil {
		t.Fatalf("Finish returned error: %v", err)
	}

	output := buf.String()

	// Should produce an empty JSON array
	if !strings.Contains(output, "[") {
		t.Errorf("JSON Start should write '[', got: %q", output)
	}
	if !strings.Contains(output, "]") {
		t.Errorf("JSON Finish should write ']', got: %q", output)
	}

	// Validate it produces valid JSON (empty array)
	trimmed := strings.TrimSpace(output)
	// The output is "[\n]\n" which should parse as valid JSON
	if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
		t.Errorf("expected JSON array brackets, got: %q", trimmed)
	}
}

func TestExporter_Start_Finish_Text(t *testing.T) {
	var buf bytes.Buffer
	exp := NewExporter(&buf, FormatText)

	if err := exp.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	if err := exp.Finish(); err != nil {
		t.Fatalf("Finish returned error: %v", err)
	}

	output := buf.String()

	// Text format Start/Finish should be no-ops, producing no output
	if output != "" {
		t.Errorf("text format Start/Finish should produce no output, got: %q", output)
	}
}
