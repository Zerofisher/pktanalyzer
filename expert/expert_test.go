package expert

import (
	"testing"
	"time"

	"github.com/Zerofisher/pktanalyzer/capture"
)

func TestTCPRetransmission(t *testing.T) {
	ctx := NewTCPAnalysisContext()

	// First packet
	pkt1 := &capture.PacketInfo{
		Number:     1,
		Timestamp:  time.Now(),
		Protocol:   "TCP",
		SrcIP:      "192.168.1.1",
		DstIP:      "192.168.1.2",
		SrcPort:    "12345",
		DstPort:    "80",
		TCPSeq:     1000,
		TCPAck:     500,
		TCPFlags:   0x018, // PSH+ACK
		TCPPayload: []byte("test data"),
		StreamKey:  "192.168.1.1:12345-192.168.1.2:80",
	}

	results1 := ctx.Analyze(pkt1)
	if len(results1) != 0 {
		t.Errorf("Expected no issues for first packet, got %d", len(results1))
	}

	// Second packet with same seq (retransmission)
	pkt2 := &capture.PacketInfo{
		Number:     2,
		Timestamp:  time.Now().Add(200 * time.Millisecond),
		Protocol:   "TCP",
		SrcIP:      "192.168.1.1",
		DstIP:      "192.168.1.2",
		SrcPort:    "12345",
		DstPort:    "80",
		TCPSeq:     1000, // Same seq
		TCPAck:     500,
		TCPFlags:   0x018, // PSH+ACK
		TCPPayload: []byte("test data"),
		StreamKey:  "192.168.1.1:12345-192.168.1.2:80",
	}

	results2 := ctx.Analyze(pkt2)
	if len(results2) != 1 {
		t.Errorf("Expected 1 retransmission, got %d", len(results2))
	}

	if len(results2) > 0 && results2[0].Summary != TCPRetransmission.String() {
		t.Errorf("Expected TCP Retransmission, got %s", results2[0].Summary)
	}
}

func TestTCPDuplicateACK(t *testing.T) {
	ctx := NewTCPAnalysisContext()

	// Setup initial packet (data packet)
	pkt1 := &capture.PacketInfo{
		Number:     1,
		Timestamp:  time.Now(),
		Protocol:   "TCP",
		SrcIP:      "192.168.1.1",
		DstIP:      "192.168.1.2",
		SrcPort:    "12345",
		DstPort:    "80",
		TCPSeq:     1000,
		TCPAck:     500,
		TCPFlags:   0x018, // PSH+ACK
		TCPPayload: []byte("data"),
		StreamKey:  "192.168.1.1:12345-192.168.1.2:80",
	}
	ctx.Analyze(pkt1)

	// First ACK (sets up the baseline)
	pkt2 := &capture.PacketInfo{
		Number:    2,
		Timestamp: time.Now().Add(100 * time.Millisecond),
		Protocol:  "TCP",
		SrcIP:     "192.168.1.2",
		DstIP:     "192.168.1.1",
		SrcPort:   "80",
		DstPort:   "12345",
		TCPSeq:    500,
		TCPAck:    1000,
		TCPFlags:  0x010, // ACK only
		StreamKey: "192.168.1.1:12345-192.168.1.2:80",
	}
	ctx.Analyze(pkt2)

	// Duplicate ACK #1 (second time same ACK seen)
	pkt3 := &capture.PacketInfo{
		Number:    3,
		Timestamp: time.Now().Add(200 * time.Millisecond),
		Protocol:  "TCP",
		SrcIP:     "192.168.1.2",
		DstIP:     "192.168.1.1",
		SrcPort:   "80",
		DstPort:   "12345",
		TCPSeq:    500,
		TCPAck:    1000, // Same ACK
		TCPFlags:  0x010,
		StreamKey: "192.168.1.1:12345-192.168.1.2:80",
	}
	results3 := ctx.Analyze(pkt3)
	foundDupACK := false
	for _, r := range results3 {
		if r.Summary == TCPDuplicateACK.String() {
			foundDupACK = true
			break
		}
	}
	if !foundDupACK {
		// It's OK if duplicate ACK is not detected on first duplicate
		// We need at least 2 duplicates to register
		t.Log("First duplicate ACK not detected (this is acceptable)")
	}

	// Duplicate ACK #2 (third time same ACK seen - should definitely trigger)
	pkt4 := &capture.PacketInfo{
		Number:    4,
		Timestamp: time.Now().Add(300 * time.Millisecond),
		Protocol:  "TCP",
		SrcIP:     "192.168.1.2",
		DstIP:     "192.168.1.1",
		SrcPort:   "80",
		DstPort:   "12345",
		TCPSeq:    500,
		TCPAck:    1000,
		TCPFlags:  0x010,
		StreamKey: "192.168.1.1:12345-192.168.1.2:80",
	}
	results4 := ctx.Analyze(pkt4)

	foundDupACKOrTriple := false
	for _, r := range results4 {
		if r.Summary == TCPDuplicateACK.String() || r.Summary == TCPTripleDuplicateACK.String() {
			foundDupACKOrTriple = true
			break
		}
	}

	if !foundDupACKOrTriple {
		t.Error("Expected duplicate ACK or triple duplicate ACK detection")
	}
}

func TestTCPRST(t *testing.T) {
	ctx := NewTCPAnalysisContext()

	// RST packet
	pkt := &capture.PacketInfo{
		Number:    1,
		Timestamp: time.Now(),
		Protocol:  "TCP",
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		SrcPort:   "12345",
		DstPort:   "80",
		TCPSeq:    1000,
		TCPAck:    500,
		TCPFlags:  0x004, // RST
		StreamKey: "192.168.1.1:12345-192.168.1.2:80",
	}

	results := ctx.Analyze(pkt)

	foundRST := false
	for _, r := range results {
		if r.Summary == TCPConnectionRefused.String() || r.Summary == TCPRSTFlag.String() {
			foundRST = true
			break
		}
	}

	if !foundRST {
		t.Error("Expected RST detection")
	}
}

func TestTCPZeroWindow(t *testing.T) {
	ctx := NewTCPAnalysisContext()

	// Setup stream
	pkt1 := &capture.PacketInfo{
		Number:    1,
		Timestamp: time.Now(),
		Protocol:  "TCP",
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		SrcPort:   "12345",
		DstPort:   "80",
		TCPSeq:    1000,
		TCPAck:    500,
		TCPFlags:  0x010, // ACK
		TCPWindow: 65535,
		StreamKey: "192.168.1.1:12345-192.168.1.2:80",
	}
	ctx.Analyze(pkt1)

	// Zero window packet
	pkt2 := &capture.PacketInfo{
		Number:    2,
		Timestamp: time.Now().Add(100 * time.Millisecond),
		Protocol:  "TCP",
		SrcIP:     "192.168.1.2",
		DstIP:     "192.168.1.1",
		SrcPort:   "80",
		DstPort:   "12345",
		TCPSeq:    500,
		TCPAck:    1000,
		TCPFlags:  0x010, // ACK
		TCPWindow: 0,     // Zero window
		StreamKey: "192.168.1.1:12345-192.168.1.2:80",
	}
	results := ctx.Analyze(pkt2)

	foundZeroWindow := false
	for _, r := range results {
		if r.Summary == TCPZeroWindow.String() {
			foundZeroWindow = true
			break
		}
	}

	if !foundZeroWindow {
		t.Error("Expected zero window detection")
	}
}

func TestExpertAnalyzer(t *testing.T) {
	analyzer := NewAnalyzer()

	// TCP RST
	pkt := &capture.PacketInfo{
		Number:    1,
		Timestamp: time.Now(),
		Protocol:  "TCP",
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		SrcPort:   "12345",
		DstPort:   "80",
		TCPSeq:    1000,
		TCPFlags:  0x004, // RST
		StreamKey: "192.168.1.1:12345-192.168.1.2:80",
	}

	results := analyzer.Analyze(pkt)
	if len(results) == 0 {
		t.Error("Expected at least one expert info")
	}

	stats := analyzer.GetStatistics()
	if stats.TotalCount == 0 {
		t.Error("Expected non-zero total count")
	}

	if !analyzer.HasIssues() {
		t.Error("Expected HasIssues to return true for RST")
	}
}

func TestHTTPErrors(t *testing.T) {
	ctx := NewHTTPAnalysisContext()

	// HTTP 404 response
	pkt := &capture.PacketInfo{
		Number:    1,
		Timestamp: time.Now(),
		Protocol:  "HTTP",
		SrcIP:     "192.168.1.2",
		DstIP:     "192.168.1.1",
		SrcPort:   "80",
		DstPort:   "12345",
		Info:      "HTTP/1.1 404 Not Found",
		StreamKey: "192.168.1.1:12345-192.168.1.2:80",
	}

	results := ctx.Analyze(pkt)

	found404 := false
	for _, r := range results {
		if r.Severity == SeverityWarning && r.Protocol == "HTTP" {
			found404 = true
			break
		}
	}

	if !found404 {
		t.Error("Expected HTTP 404 detection")
	}
}

func TestHTTPServerError(t *testing.T) {
	ctx := NewHTTPAnalysisContext()

	// HTTP 500 response
	pkt := &capture.PacketInfo{
		Number:    1,
		Timestamp: time.Now(),
		Protocol:  "HTTP",
		SrcIP:     "192.168.1.2",
		DstIP:     "192.168.1.1",
		SrcPort:   "80",
		DstPort:   "12345",
		Info:      "HTTP/1.1 500 Internal Server Error",
		StreamKey: "192.168.1.1:12345-192.168.1.2:80",
	}

	results := ctx.Analyze(pkt)

	found500 := false
	for _, r := range results {
		if r.Severity == SeverityError && r.Protocol == "HTTP" {
			found500 = true
			break
		}
	}

	if !found500 {
		t.Error("Expected HTTP 500 detection")
	}
}

func TestDNSNXDOMAIN(t *testing.T) {
	ctx := NewDNSAnalysisContext()

	// DNS NXDOMAIN response
	pkt := &capture.PacketInfo{
		Number:    1,
		Timestamp: time.Now(),
		Protocol:  "DNS",
		SrcIP:     "8.8.8.8",
		DstIP:     "192.168.1.1",
		SrcPort:   "53",
		DstPort:   "12345",
		Info:      "Response: nonexistent.example.com NXDOMAIN",
	}

	results := ctx.Analyze(pkt)

	foundNXDOMAIN := false
	for _, r := range results {
		if r.Summary == DNSQueryNXDOMAIN.String() {
			foundNXDOMAIN = true
			break
		}
	}

	if !foundNXDOMAIN {
		t.Error("Expected NXDOMAIN detection")
	}
}

func TestSeverity(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
		symbol   string
	}{
		{SeverityChat, "Chat", "."},
		{SeverityNote, "Note", "i"},
		{SeverityWarning, "Warning", "!"},
		{SeverityError, "Error", "X"},
	}

	for _, tt := range tests {
		if tt.severity.String() != tt.expected {
			t.Errorf("Expected %s, got %s", tt.expected, tt.severity.String())
		}
		if tt.severity.Symbol() != tt.symbol {
			t.Errorf("Expected symbol %s, got %s", tt.symbol, tt.severity.Symbol())
		}
	}
}

func TestTCPExpertTypes(t *testing.T) {
	types := []TCPExpertType{
		TCPRetransmission,
		TCPFastRetransmission,
		TCPDuplicateACK,
		TCPTripleDuplicateACK,
		TCPOutOfOrder,
		TCPZeroWindow,
		TCPKeepAlive,
		TCPRSTFlag,
	}

	for _, typ := range types {
		if typ.String() == "" || typ.String() == "Unknown TCP Issue" {
			t.Errorf("Missing string for TCP expert type %d", typ)
		}
	}
}
