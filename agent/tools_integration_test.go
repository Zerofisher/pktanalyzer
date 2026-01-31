package agent

import (
	"strings"
	"testing"

	"github.com/Zerofisher/pktanalyzer/capture"
)

// TestGetStatisticsFirst tests that get_statistics provides good overview
func TestGetStatisticsFirst(t *testing.T) {
	exec, mock := NewToolExecutorWithMock()

	// Add diverse packets
	protocols := []string{"TCP", "TCP", "TCP", "DNS", "DNS", "HTTP", "HTTP", "ARP"}
	for i, proto := range protocols {
		mock.AddPacket(capture.PacketInfo{
			Number:   i + 1,
			Protocol: proto,
			SrcIP:    "192.168.1.100",
			DstIP:    "8.8.8.8",
			Length:   100,
		})
	}

	result, err := exec.ExecuteTool("get_statistics", map[string]interface{}{})
	if err != nil {
		t.Fatalf("get_statistics failed: %v", err)
	}

	// Verify it contains protocol distribution
	if !strings.Contains(result, "协议分布") {
		t.Error("get_statistics should contain protocol distribution")
	}
	if !strings.Contains(result, "TCP") {
		t.Error("get_statistics should show TCP")
	}
	if !strings.Contains(result, "DNS") {
		t.Error("get_statistics should show DNS")
	}
}

// TestLimitEnforcement tests that limit is properly clamped
func TestLimitEnforcement(t *testing.T) {
	exec, mock := NewToolExecutorWithMock()

	// Add 100 packets
	for i := 0; i < 100; i++ {
		mock.AddPacket(capture.PacketInfo{
			Number:   i + 1,
			Protocol: "TCP",
			SrcIP:    "192.168.1.100",
			DstIP:    "8.8.8.8",
			Length:   100,
		})
	}

	// Request 999 packets (should be clamped to MaxLimit)
	result, err := exec.ExecuteTool("get_packets", map[string]interface{}{
		"limit": float64(999),
	})
	if err != nil {
		t.Fatalf("get_packets failed: %v", err)
	}

	// Count lines (header + separator + data lines)
	lines := strings.Split(result, "\n")
	dataLines := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "  ") || (len(line) > 0 && line[0] >= '0' && line[0] <= '9') {
			dataLines++
		}
	}

	// Should not exceed MaxLimit
	if dataLines > MaxLimit+5 { // +5 for header lines
		t.Errorf("get_packets returned too many lines: %d (limit should be %d)", dataLines, MaxLimit)
	}
}

// TestEvidenceInOutput tests that Evidence is included in tool outputs
func TestEvidenceInOutput(t *testing.T) {
	exec, mock := NewToolExecutorWithMock()

	// Add DNS packets
	mock.AddPacket(capture.PacketInfo{Number: 1, Protocol: "DNS", SrcIP: "192.168.1.100", DstIP: "8.8.8.8", Info: "Query A google.com"})
	mock.AddPacket(capture.PacketInfo{Number: 2, Protocol: "DNS", SrcIP: "8.8.8.8", DstIP: "192.168.1.100", Info: "Response A google.com"})

	result, err := exec.ExecuteTool("find_dns_queries", map[string]interface{}{})
	if err != nil {
		t.Fatalf("find_dns_queries failed: %v", err)
	}

	if !strings.Contains(result, "Evidence:") {
		t.Error("find_dns_queries should include Evidence reference")
	}
	if !strings.Contains(result, "packets=") {
		t.Error("find_dns_queries Evidence should contain packets")
	}
}

// TestRawDataAuthorizationDenied tests that raw data triggers confirmation request without authorization
func TestRawDataAuthorizationDenied(t *testing.T) {
	exec, mock := NewToolExecutorWithMock()
	mock.AddPacket(capture.PacketInfo{
		Number:   1,
		Protocol: "TCP",
		SrcIP:    "192.168.1.100",
		DstIP:    "8.8.8.8",
		RawData:  []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
	})

	// Set user input without raw keyword
	exec.SetLastUserInput("分析这个数据包")

	result, err := exec.ExecuteTool("analyze_packet", map[string]interface{}{
		"packet_number": float64(1),
		"include_raw":   true,
	})
	if err != nil {
		t.Fatalf("analyze_packet failed: %v", err)
	}

	// Should return confirmation request (new behavior)
	if !strings.Contains(result, "[CONFIRMATION_REQUIRED]") {
		t.Error("Should return confirmation request when raw data is requested without authorization")
	}

	// Should have a pending confirmation
	if !exec.HasPendingConfirmation() {
		t.Error("Should have pending confirmation after requesting raw data")
	}

	// The pending confirmation should be for raw data
	pending := exec.GetPendingConfirmation()
	if pending == nil {
		t.Fatal("GetPendingConfirmation should return a request")
	}
	if pending.Type != AuthTypeRawData {
		t.Errorf("Pending confirmation type should be AuthTypeRawData, got %v", pending.Type)
	}
}

// TestRawDataAuthorizationGranted tests that raw data is shown with session authorization
func TestRawDataAuthorizationGranted(t *testing.T) {
	exec, mock := NewToolExecutorWithMock()
	mock.AddPacket(capture.PacketInfo{
		Number:   1,
		Protocol: "TCP",
		SrcIP:    "192.168.1.100",
		DstIP:    "8.8.8.8",
		RawData:  []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
	})

	// Grant session authorization BEFORE the request
	exec.GrantRawDataAuthorization(true)

	result, err := exec.ExecuteTool("analyze_packet", map[string]interface{}{
		"packet_number": float64(1),
		"include_raw":   true,
	})
	if err != nil {
		t.Fatalf("analyze_packet failed: %v", err)
	}

	// Should contain hex dump and sensitivity warning
	if !strings.Contains(result, "敏感") {
		t.Error("Raw data output should include sensitivity warning")
	}
	// Should NOT require confirmation since session is authorized
	if strings.Contains(result, "[CONFIRMATION_REQUIRED]") {
		t.Error("Should not require confirmation when session is authorized")
	}
}

// TestRawDataAfterSessionGrant tests that raw data is shown after session grant
func TestRawDataAfterSessionGrant(t *testing.T) {
	exec, mock := NewToolExecutorWithMock()
	mock.AddPacket(capture.PacketInfo{
		Number:   1,
		Protocol: "TCP",
		SrcIP:    "192.168.1.100",
		DstIP:    "8.8.8.8",
		RawData:  []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
	})

	// Set user input WITHOUT raw keyword
	exec.SetLastUserInput("分析这个数据包")

	// First call should trigger confirmation
	result, err := exec.ExecuteTool("analyze_packet", map[string]interface{}{
		"packet_number": float64(1),
		"include_raw":   true,
	})
	if err != nil {
		t.Fatalf("analyze_packet failed: %v", err)
	}
	if !strings.Contains(result, "[CONFIRMATION_REQUIRED]") {
		t.Error("First call should require confirmation")
	}

	// Grant authorization for session
	exec.GrantRawDataAuthorization(true)
	exec.ClearPendingAuthorization()

	// Second call should work because session is authorized
	result, err = exec.ExecuteTool("analyze_packet", map[string]interface{}{
		"packet_number": float64(1),
		"include_raw":   true,
	})
	if err != nil {
		t.Fatalf("analyze_packet after grant failed: %v", err)
	}

	// Should now contain raw data
	if strings.Contains(result, "[CONFIRMATION_REQUIRED]") {
		t.Error("After session grant, should not require confirmation")
	}
	if !strings.Contains(result, "敏感") {
		t.Error("After session grant, raw data should be shown with sensitivity warning")
	}
}

// TestRedactionEnabled tests that IP redaction works when enabled
func TestRedactionEnabled(t *testing.T) {
	exec, mock := NewToolExecutorWithMock()
	exec.SetRedactConfig(DefaultRedactConfig()) // Redaction enabled by default

	mock.AddPacket(capture.PacketInfo{
		Number:   1,
		Protocol: "TCP",
		SrcIP:    "8.8.8.8", // Public IP should be fully redacted
		DstIP:    "192.168.1.100",
		Length:   100,
	})

	result, err := exec.ExecuteTool("get_packets", map[string]interface{}{})
	if err != nil {
		t.Fatalf("get_packets failed: %v", err)
	}

	// Public IP should be redacted
	if strings.Contains(result, "8.8.8.8") {
		t.Error("Public IP should be redacted when redaction is enabled")
	}
	// Should contain redacted format
	if !strings.Contains(result, "IP[") {
		t.Error("Should contain redacted IP format")
	}
}

// TestRedactionDisabled tests that IPs are shown when redaction is disabled
func TestRedactionDisabled(t *testing.T) {
	exec, mock := NewToolExecutorWithMock()
	exec.SetRedactConfig(&RedactConfig{Enabled: false})

	mock.AddPacket(capture.PacketInfo{
		Number:   1,
		Protocol: "TCP",
		SrcIP:    "8.8.8.8",
		DstIP:    "192.168.1.100",
		Length:   100,
	})

	result, err := exec.ExecuteTool("get_packets", map[string]interface{}{})
	if err != nil {
		t.Fatalf("get_packets failed: %v", err)
	}

	// IP should be shown as-is
	if !strings.Contains(result, "8.8.8.8") {
		t.Error("IP should be shown when redaction is disabled")
	}
}

// TestAllowlistRejectsUnknownTool tests that unknown tools are rejected
func TestAllowlistRejectsUnknownTool(t *testing.T) {
	exec, _ := NewToolExecutorWithMock()

	_, err := exec.ExecuteTool("malicious_tool", map[string]interface{}{})
	if err == nil {
		t.Error("Unknown tool should be rejected")
	}
	if !strings.Contains(err.Error(), "未知工具") {
		t.Errorf("Error should mention unknown tool, got: %v", err)
	}
}

// TestDetectAnomaliesWithEvidence tests that anomaly detection includes evidence
func TestDetectAnomaliesWithEvidence(t *testing.T) {
	exec, mock := NewToolExecutorWithMock()

	// Add packets that simulate port scanning (many SYN to different ports)
	srcIP := "10.0.0.1"
	for i := 0; i < 15; i++ {
		mock.AddPacket(capture.PacketInfo{
			Number:   i + 1,
			Protocol: "TCP",
			SrcIP:    srcIP,
			DstIP:    "192.168.1.100",
			SrcPort:  "12345",
			DstPort:  string(rune('1')+rune(i)) + "000", // Different ports
			Info:     "[SYN] Seq=0",
		})
	}

	result, err := exec.ExecuteTool("detect_anomalies", map[string]interface{}{})
	if err != nil {
		t.Fatalf("detect_anomalies failed: %v", err)
	}

	// Should detect port scanning and include evidence
	if !strings.Contains(result, "端口扫描") {
		t.Error("Should detect port scanning")
	}
	if !strings.Contains(result, "证据包") {
		t.Error("Anomaly detection should include evidence packets")
	}
}

// TestStringParameterClamping tests that long strings are truncated
func TestStringParameterClamping(t *testing.T) {
	exec, mock := NewToolExecutorWithMock()
	mock.AddPacket(capture.PacketInfo{
		Number:   1,
		Protocol: "HTTP",
		SrcIP:    "192.168.1.100",
		DstIP:    "8.8.8.8",
		Info:     "GET /api/test",
	})

	// Create a very long filter string
	longString := strings.Repeat("a", 500)

	// This should not panic or cause issues
	_, err := exec.ExecuteTool("filter_packets", map[string]interface{}{
		"contains": longString,
	})
	if err != nil {
		t.Fatalf("filter_packets with long string failed: %v", err)
	}
}

// TestFindConnectionsWithEvidence tests connection finding with evidence
func TestFindConnectionsWithEvidence(t *testing.T) {
	exec, mock := NewToolExecutorWithMock()

	// Add TCP connection packets
	mock.AddPacket(capture.PacketInfo{Number: 1, Protocol: "TCP", SrcIP: "192.168.1.100", DstIP: "8.8.8.8", SrcPort: "54321", DstPort: "443", Info: "[SYN]"})
	mock.AddPacket(capture.PacketInfo{Number: 2, Protocol: "TCP", SrcIP: "8.8.8.8", DstIP: "192.168.1.100", SrcPort: "443", DstPort: "54321", Info: "[SYN, ACK]"})
	mock.AddPacket(capture.PacketInfo{Number: 3, Protocol: "TCP", SrcIP: "192.168.1.100", DstIP: "8.8.8.8", SrcPort: "54321", DstPort: "443", Info: "[ACK]"})

	result, err := exec.ExecuteTool("find_connections", map[string]interface{}{})
	if err != nil {
		t.Fatalf("find_connections failed: %v", err)
	}

	if !strings.Contains(result, "Evidence:") {
		t.Error("find_connections should include Evidence")
	}
	if !strings.Contains(result, "connections=") {
		t.Error("find_connections Evidence should contain connections")
	}
}
