package capture

import (
	"encoding/binary"
	"strings"
	"testing"
)

// --- Port name tests ---

func TestGetPortName(t *testing.T) {
	tests := []struct {
		port uint16
		want string
	}{
		{80, "http"},
		{443, "https"},
		{22, "ssh"},
		{53, "domain"},
		{5353, "mdns"},
		{12345, ""},
		{0, ""},
		{65535, ""},
	}
	for _, tt := range tests {
		got := GetPortName(tt.port)
		if got != tt.want {
			t.Errorf("GetPortName(%d) = %q, want %q", tt.port, got, tt.want)
		}
	}
}

func TestFormatPort(t *testing.T) {
	tests := []struct {
		port string
		want string
	}{
		{"80", "80(http)"},
		{"443", "443(https)"},
		{"22", "22(ssh)"},
		{"12345", "12345"},
		{"0", "0"},
		{"abc", "abc"},
	}
	for _, tt := range tests {
		got := FormatPort(tt.port)
		if got != tt.want {
			t.Errorf("FormatPort(%q) = %q, want %q", tt.port, got, tt.want)
		}
	}
}

// --- NBNS tests ---

func TestParseNBNS(t *testing.T) {
	t.Run("valid query", func(t *testing.T) {
		// Header (12) + nameLen (1) + encoded name (32) + null (1) + qtype (2) + pad (2)
		data := make([]byte, 50)
		binary.BigEndian.PutUint16(data[0:2], 0x1234)
		binary.BigEndian.PutUint16(data[2:4], 0x0000) // query
		binary.BigEndian.PutUint16(data[4:6], 0x0001) // 1 question
		data[12] = 32                                 // name length
		// NetBIOS A-P encoding of "TEST" + 12 trailing spaces
		copy(data[13:45], []byte("FEEFFDFECACACACACACACACACACACACA"))
		data[45] = 0                                    // null terminator
		binary.BigEndian.PutUint16(data[46:48], 0x0020) // NB

		msg, err := ParseNBNS(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.TransactionID != 0x1234 {
			t.Errorf("TransactionID = 0x%04x, want 0x1234", msg.TransactionID)
		}
		if msg.Questions != 1 {
			t.Errorf("Questions = %d, want 1", msg.Questions)
		}
		if !msg.IsQuery() {
			t.Error("expected query, got response")
		}
		if len(msg.Names) == 0 || msg.Names[0] != "TEST" {
			t.Errorf("Names = %v, want [TEST]", msg.Names)
		}
		if msg.QueryType != "NB" {
			t.Errorf("QueryType = %q, want %q", msg.QueryType, "NB")
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, err := ParseNBNS(make([]byte, 11))
		if err == nil {
			t.Error("expected error for short packet")
		}
	})

	t.Run("minimal 12 bytes", func(t *testing.T) {
		data := make([]byte, 12)
		binary.BigEndian.PutUint16(data[0:2], 0xABCD)
		msg, err := ParseNBNS(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.TransactionID != 0xABCD {
			t.Errorf("TransactionID = 0x%04x, want 0xABCD", msg.TransactionID)
		}
	})
}

func TestParseNBNS_GetInfo(t *testing.T) {
	t.Run("query", func(t *testing.T) {
		msg := &NBNSMessage{
			Flags:     0x0000,
			QueryType: "NB",
			Names:     []string{"WORKSTATION"},
		}
		got := msg.GetInfo()
		if !strings.Contains(got, "Name query") {
			t.Errorf("GetInfo() = %q, expected 'Name query'", got)
		}
		if !strings.Contains(got, "NB") {
			t.Errorf("GetInfo() = %q, expected NB type", got)
		}
		if !strings.Contains(got, "WORKSTATION") {
			t.Errorf("GetInfo() = %q, expected name WORKSTATION", got)
		}
	})

	t.Run("response", func(t *testing.T) {
		msg := &NBNSMessage{
			Flags:     0x8000,
			QueryType: "NB",
			Names:     []string{"SERVER"},
		}
		got := msg.GetInfo()
		if !strings.Contains(got, "Name response") {
			t.Errorf("GetInfo() = %q, expected 'Name response'", got)
		}
		if !strings.Contains(got, "SERVER") {
			t.Errorf("GetInfo() = %q, expected name SERVER", got)
		}
	})
}

// --- LLMNR tests ---

// buildLLMNRPacket constructs a minimal LLMNR packet with DNS-encoded name.
func buildLLMNRPacket(flags uint16, qtype uint16, name string) []byte {
	labels := strings.Split(name, ".")
	var encoded []byte
	for _, label := range labels {
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, []byte(label)...)
	}
	encoded = append(encoded, 0) // null terminator

	data := make([]byte, 12+len(encoded)+4)
	binary.BigEndian.PutUint16(data[0:2], 0x0001) // TransactionID
	binary.BigEndian.PutUint16(data[2:4], flags)
	binary.BigEndian.PutUint16(data[4:6], 0x0001) // 1 question
	copy(data[12:], encoded)
	offset := 12 + len(encoded)
	binary.BigEndian.PutUint16(data[offset:offset+2], qtype)
	binary.BigEndian.PutUint16(data[offset+2:offset+4], 0x0001) // class IN
	return data
}

func TestParseLLMNR(t *testing.T) {
	t.Run("valid query", func(t *testing.T) {
		data := buildLLMNRPacket(0x0000, 1, "myhost")

		msg, err := ParseLLMNR(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.QueryName != "myhost" {
			t.Errorf("QueryName = %q, want %q", msg.QueryName, "myhost")
		}
		if msg.QueryType != 1 {
			t.Errorf("QueryType = %d, want 1", msg.QueryType)
		}
		if msg.QueryClass != 1 {
			t.Errorf("QueryClass = %d, want 1", msg.QueryClass)
		}
		if !msg.IsQuery() {
			t.Error("expected query, got response")
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, err := ParseLLMNR(make([]byte, 11))
		if err == nil {
			t.Error("expected error for short packet")
		}
	})
}

func TestParseLLMNR_GetInfo(t *testing.T) {
	t.Run("query", func(t *testing.T) {
		msg := &LLMNRMessage{
			Flags:     0x0000,
			QueryType: 1,
			QueryName: "testhost",
		}
		got := msg.GetInfo()
		want := "Standard query A testhost"
		if got != want {
			t.Errorf("GetInfo() = %q, want %q", got, want)
		}
	})

	t.Run("response", func(t *testing.T) {
		msg := &LLMNRMessage{
			Flags:     0x8000,
			QueryType: 28,
			QueryName: "testhost",
		}
		got := msg.GetInfo()
		want := "Standard query response AAAA testhost"
		if got != want {
			t.Errorf("GetInfo() = %q, want %q", got, want)
		}
	})
}

// --- mDNS tests ---

func TestParseMDNS(t *testing.T) {
	t.Run("with query", func(t *testing.T) {
		// DNS-encode "_http._tcp.local"
		name := []byte{
			5, '_', 'h', 't', 't', 'p',
			4, '_', 't', 'c', 'p',
			5, 'l', 'o', 'c', 'a', 'l',
			0,
		}
		data := make([]byte, 12+len(name)+4)
		binary.BigEndian.PutUint16(data[2:4], 0x0000) // query
		binary.BigEndian.PutUint16(data[4:6], 0x0001) // 1 question
		copy(data[12:], name)
		offset := 12 + len(name)
		binary.BigEndian.PutUint16(data[offset:offset+2], 12)  // PTR
		binary.BigEndian.PutUint16(data[offset+2:offset+4], 1) // IN

		msg, err := ParseMDNS(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(msg.Queries) != 1 {
			t.Fatalf("expected 1 query, got %d", len(msg.Queries))
		}
		if msg.Queries[0].Name != "_http._tcp.local" {
			t.Errorf("query name = %q, want %q", msg.Queries[0].Name, "_http._tcp.local")
		}
		if msg.Queries[0].Type != 12 {
			t.Errorf("query type = %d, want 12 (PTR)", msg.Queries[0].Type)
		}
		if !msg.IsQuery() {
			t.Error("expected query, got response")
		}
		got := msg.GetInfo()
		want := "Standard query PTR _http._tcp.local"
		if got != want {
			t.Errorf("GetInfo() = %q, want %q", got, want)
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, err := ParseMDNS(make([]byte, 11))
		if err == nil {
			t.Error("expected error for short packet")
		}
	})

	t.Run("GetInfo response with answer", func(t *testing.T) {
		msg := &MDNSMessage{
			Flags: 0x8400,
			Answers: []MDNSAnswer{
				{Name: "myhost.local", Type: 1, Data: "192.168.1.100"},
			},
		}
		got := msg.GetInfo()
		want := "Standard query response A myhost.local 192.168.1.100"
		if got != want {
			t.Errorf("GetInfo() = %q, want %q", got, want)
		}
	})

	t.Run("GetInfo empty query", func(t *testing.T) {
		msg := &MDNSMessage{Flags: 0x0000}
		got := msg.GetInfo()
		if got != "Standard query" {
			t.Errorf("GetInfo() = %q, want %q", got, "Standard query")
		}
	})

	t.Run("GetInfo empty response", func(t *testing.T) {
		msg := &MDNSMessage{Flags: 0x8000}
		got := msg.GetInfo()
		if got != "Standard query response" {
			t.Errorf("GetInfo() = %q, want %q", got, "Standard query response")
		}
	})
}

// --- SSDP tests ---

func TestParseSSDP_Request(t *testing.T) {
	data := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n")

	msg, err := ParseSSDP(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.IsResponse {
		t.Error("expected request, got response")
	}
	if msg.Method != "M-SEARCH" {
		t.Errorf("Method = %q, want %q", msg.Method, "M-SEARCH")
	}
	if msg.URI != "*" {
		t.Errorf("URI = %q, want %q", msg.URI, "*")
	}
	if msg.HTTPVersion != "HTTP/1.1" {
		t.Errorf("HTTPVersion = %q, want %q", msg.HTTPVersion, "HTTP/1.1")
	}
	if msg.Headers["HOST"] != "239.255.255.250:1900" {
		t.Errorf("HOST header = %q, want %q", msg.Headers["HOST"], "239.255.255.250:1900")
	}
	if msg.Headers["ST"] != "ssdp:all" {
		t.Errorf("ST header = %q, want %q", msg.Headers["ST"], "ssdp:all")
	}

	got := msg.GetInfo()
	want := "M-SEARCH * HTTP/1.1"
	if got != want {
		t.Errorf("GetInfo() = %q, want %q", got, want)
	}
}

func TestParseSSDP_Response(t *testing.T) {
	data := []byte("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nLOCATION: http://192.168.1.1:80/desc.xml\r\n\r\n")

	msg, err := ParseSSDP(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !msg.IsResponse {
		t.Error("expected response, got request")
	}
	if msg.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", msg.StatusCode)
	}
	if msg.StatusText != "OK" {
		t.Errorf("StatusText = %q, want %q", msg.StatusText, "OK")
	}
	if msg.Headers["ST"] != "upnp:rootdevice" {
		t.Errorf("ST header = %q, want %q", msg.Headers["ST"], "upnp:rootdevice")
	}

	got := msg.GetInfo()
	want := "HTTP/1.1 200 OK"
	if got != want {
		t.Errorf("GetInfo() = %q, want %q", got, want)
	}
}

// --- SRVLOC tests ---

func TestParseSRVLOC(t *testing.T) {
	t.Run("version 2", func(t *testing.T) {
		data := make([]byte, 16)
		data[0] = 2                                 // Version
		data[1] = 1                                 // Service Request
		binary.BigEndian.PutUint16(data[2:4], 16)   // Length
		binary.BigEndian.PutUint16(data[5:7], 0)    // Flags
		binary.BigEndian.PutUint16(data[10:12], 42) // XID
		binary.BigEndian.PutUint16(data[12:14], 2)  // LangTagLen
		data[14] = 'e'
		data[15] = 'n'

		msg, err := ParseSRVLOC(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.Version != 2 {
			t.Errorf("Version = %d, want 2", msg.Version)
		}
		if msg.Function != 1 {
			t.Errorf("Function = %d, want 1", msg.Function)
		}
		if msg.XID != 42 {
			t.Errorf("XID = %d, want 42", msg.XID)
		}
		if msg.LangTag != "en" {
			t.Errorf("LangTag = %q, want %q", msg.LangTag, "en")
		}

		got := msg.GetInfo()
		want := "Service Request, V2 Transaction ID = 42"
		if got != want {
			t.Errorf("GetInfo() = %q, want %q", got, want)
		}
	})

	t.Run("version 1", func(t *testing.T) {
		data := make([]byte, 14)
		data[0] = 1                                // Version
		data[1] = 8                                // DA Advertisement
		binary.BigEndian.PutUint16(data[2:4], 14)  // Length
		binary.BigEndian.PutUint16(data[10:12], 7) // XID

		msg, err := ParseSRVLOC(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.Version != 1 {
			t.Errorf("Version = %d, want 1", msg.Version)
		}
		if msg.XID != 7 {
			t.Errorf("XID = %d, want 7", msg.XID)
		}

		got := msg.GetInfo()
		want := "DA Advertisement, V1 Transaction ID = 7"
		if got != want {
			t.Errorf("GetInfo() = %q, want %q", got, want)
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, err := ParseSRVLOC(make([]byte, 13))
		if err == nil {
			t.Error("expected error for short packet")
		}
	})
}

// --- WS-Discovery tests ---

func TestParseWSDiscovery(t *testing.T) {
	tests := []struct {
		name       string
		xml        string
		wantAction string
		wantProbe  bool
		wantMatch  bool
	}{
		{
			name:       "Probe",
			xml:        `<s:Envelope><s:Body><d:Probe></d:Probe></s:Body></s:Envelope>`,
			wantAction: "Probe",
			wantProbe:  true,
		},
		{
			name:       "ProbeMatches",
			xml:        `<s:Envelope><s:Body><d:ProbeMatches><d:ProbeMatch/></d:ProbeMatches></s:Body></s:Envelope>`,
			wantAction: "ProbeMatches",
			wantMatch:  true,
		},
		{
			name:       "Hello",
			xml:        `<s:Envelope><s:Body><d:Hello></d:Hello></s:Body></s:Envelope>`,
			wantAction: "Hello",
		},
		{
			name:       "Bye",
			xml:        `<s:Envelope><s:Body><d:Bye></d:Bye></s:Body></s:Envelope>`,
			wantAction: "Bye",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := ParseWSDiscovery([]byte(tt.xml))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if msg.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", msg.Action, tt.wantAction)
			}
			if msg.IsProbe != tt.wantProbe {
				t.Errorf("IsProbe = %v, want %v", msg.IsProbe, tt.wantProbe)
			}
			if msg.IsProbeMatch != tt.wantMatch {
				t.Errorf("IsProbeMatch = %v, want %v", msg.IsProbeMatch, tt.wantMatch)
			}
		})
	}

	t.Run("Probe with types GetInfo", func(t *testing.T) {
		xml := `<s:Envelope><s:Body><d:Probe><d:Types>wsdp:Device</d:Types></d:Probe></s:Body></s:Envelope>`
		msg, err := ParseWSDiscovery([]byte(xml))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.Types != "wsdp:Device" {
			t.Errorf("Types = %q, want %q", msg.Types, "wsdp:Device")
		}
		got := msg.GetInfo()
		want := "Probe (wsdp:Device)"
		if got != want {
			t.Errorf("GetInfo() = %q, want %q", got, want)
		}
	})

	t.Run("Hello GetInfo", func(t *testing.T) {
		msg := &WSDiscoveryMessage{Action: "Hello"}
		got := msg.GetInfo()
		if got != "Hello" {
			t.Errorf("GetInfo() = %q, want %q", got, "Hello")
		}
	})

	t.Run("empty action", func(t *testing.T) {
		msg, _ := ParseWSDiscovery([]byte("<s:Envelope><s:Body></s:Body></s:Envelope>"))
		got := msg.GetInfo()
		if got != "WS-Discovery" {
			t.Errorf("GetInfo() = %q, want %q", got, "WS-Discovery")
		}
	})
}

// --- DHCP tests ---

// buildDHCPPacket constructs a minimal valid DHCP packet with magic cookie and message type option.
func buildDHCPPacket(msgType uint8, xid uint32) []byte {
	data := make([]byte, 244)
	data[0] = 1 // Op: BOOTREQUEST
	data[1] = 1 // HType: Ethernet
	data[2] = 6 // HLen: 6
	binary.BigEndian.PutUint32(data[4:8], xid)
	// CHAddr (MAC: aa:bb:cc:dd:ee:ff)
	data[28] = 0xaa
	data[29] = 0xbb
	data[30] = 0xcc
	data[31] = 0xdd
	data[32] = 0xee
	data[33] = 0xff
	// Magic cookie
	data[236] = 99
	data[237] = 130
	data[238] = 83
	data[239] = 99
	// Option 53 (DHCP Message Type)
	data[240] = 53
	data[241] = 1
	data[242] = msgType
	// End option
	data[243] = 255
	return data
}

func TestParseDHCP(t *testing.T) {
	t.Run("valid Discover", func(t *testing.T) {
		data := buildDHCPPacket(1, 0x12345678)

		msg, err := ParseDHCP(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.Op != 1 {
			t.Errorf("Op = %d, want 1", msg.Op)
		}
		if msg.XID != 0x12345678 {
			t.Errorf("XID = 0x%08x, want 0x12345678", msg.XID)
		}
		if msg.MessageType != 1 {
			t.Errorf("MessageType = %d, want 1", msg.MessageType)
		}
		if msg.CHAddr != "aa:bb:cc:dd:ee:ff" {
			t.Errorf("CHAddr = %q, want %q", msg.CHAddr, "aa:bb:cc:dd:ee:ff")
		}
		if msg.CIAddr != "0.0.0.0" {
			t.Errorf("CIAddr = %q, want %q", msg.CIAddr, "0.0.0.0")
		}
		if opt, ok := msg.Options[53]; !ok || len(opt) != 1 || opt[0] != 1 {
			t.Errorf("Option 53 = %v, want [1]", opt)
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, err := ParseDHCP(make([]byte, 239))
		if err == nil {
			t.Error("expected error for short packet")
		}
	})

	t.Run("no magic cookie", func(t *testing.T) {
		data := make([]byte, 244)
		data[0] = 1
		data[1] = 1
		data[2] = 6
		// Magic cookie bytes left as zero - options will not be parsed
		msg, err := ParseDHCP(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.MessageType != 0 {
			t.Errorf("MessageType = %d, want 0 (no options parsed)", msg.MessageType)
		}
	})
}

func TestParseDHCP_GetInfo(t *testing.T) {
	tests := []struct {
		name        string
		messageType uint8
		xid         uint32
		want        string
	}{
		{"Discover", 1, 0x12345678, "DHCP Discover - Transaction ID 0x12345678"},
		{"Offer", 2, 0xAABBCCDD, "DHCP Offer - Transaction ID 0xaabbccdd"},
		{"Request", 3, 0x00000001, "DHCP Request - Transaction ID 0x00000001"},
		{"ACK", 5, 0xDEADBEEF, "DHCP ACK - Transaction ID 0xdeadbeef"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &DHCPMessage{
				MessageType: tt.messageType,
				XID:         tt.xid,
			}
			got := msg.GetInfo()
			if got != tt.want {
				t.Errorf("GetInfo() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- NTP tests ---

func TestParseNTP(t *testing.T) {
	t.Run("client mode", func(t *testing.T) {
		data := make([]byte, 48)
		// LI=0, VN=4, Mode=3 (Client): (0<<6)|(4<<3)|3 = 0x23
		data[0] = 0x23
		data[1] = 0 // Stratum unspecified

		msg, err := ParseNTP(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.LI != 0 {
			t.Errorf("LI = %d, want 0", msg.LI)
		}
		if msg.VN != 4 {
			t.Errorf("VN = %d, want 4", msg.VN)
		}
		if msg.Mode != 3 {
			t.Errorf("Mode = %d, want 3", msg.Mode)
		}
	})

	t.Run("server mode", func(t *testing.T) {
		data := make([]byte, 48)
		// LI=0, VN=4, Mode=4 (Server): (0<<6)|(4<<3)|4 = 0x24
		data[0] = 0x24
		data[1] = 2 // Stratum 2 (secondary reference)
		// RefID as IP address (stratum > 1)
		data[12] = 192
		data[13] = 168
		data[14] = 1
		data[15] = 1

		msg, err := ParseNTP(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.Mode != 4 {
			t.Errorf("Mode = %d, want 4", msg.Mode)
		}
		if msg.Stratum != 2 {
			t.Errorf("Stratum = %d, want 2", msg.Stratum)
		}
		if msg.RefID != "192.168.1.1" {
			t.Errorf("RefID = %q, want %q", msg.RefID, "192.168.1.1")
		}
	})

	t.Run("stratum 1 text RefID", func(t *testing.T) {
		data := make([]byte, 48)
		data[0] = 0x24 // server mode
		data[1] = 1    // Stratum 1
		copy(data[12:16], []byte("GPS\x00"))

		msg, err := ParseNTP(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.RefID != "GPS" {
			t.Errorf("RefID = %q, want %q", msg.RefID, "GPS")
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, err := ParseNTP(make([]byte, 47))
		if err == nil {
			t.Error("expected error for short packet")
		}
	})
}

func TestParseNTP_GetInfo(t *testing.T) {
	tests := []struct {
		name string
		vn   uint8
		mode uint8
		want string
	}{
		{"Client v4", 4, 3, "NTP Version 4, Client"},
		{"Server v4", 4, 4, "NTP Version 4, Server"},
		{"Broadcast v3", 3, 5, "NTP Version 3, Broadcast"},
		{"Symmetric Active", 4, 1, "NTP Version 4, Symmetric Active"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &NTPMessage{VN: tt.vn, Mode: tt.mode}
			got := msg.GetInfo()
			if got != tt.want {
				t.Errorf("GetInfo() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- SNMP tests ---

func TestParseSNMP(t *testing.T) {
	t.Run("valid GetRequest", func(t *testing.T) {
		data := []byte{
			0x30, 0x0E, // SEQUENCE, length 14
			0x02, 0x01, 0x00, // INTEGER, version 0 (SNMPv1)
			0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // OCTET STRING "public"
			0xA0, 0x00, // GetRequest PDU (0xA0 & 0x1F = 0)
		}

		msg, err := ParseSNMP(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.Version != 0 {
			t.Errorf("Version = %d, want 0", msg.Version)
		}
		if msg.Community != "public" {
			t.Errorf("Community = %q, want %q", msg.Community, "public")
		}
		if msg.PDUType != 0 {
			t.Errorf("PDUType = %d, want 0 (GetRequest)", msg.PDUType)
		}

		got := msg.GetInfo()
		want := "SNMPv1 GetRequest, community=public"
		if got != want {
			t.Errorf("GetInfo() = %q, want %q", got, want)
		}
	})

	t.Run("GetResponse", func(t *testing.T) {
		data := []byte{
			0x30, 0x0E,
			0x02, 0x01, 0x00,
			0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
			0xA2, 0x00, // GetResponse PDU (0xA2 & 0x1F = 2)
		}

		msg, err := ParseSNMP(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.PDUType != 2 {
			t.Errorf("PDUType = %d, want 2 (GetResponse)", msg.PDUType)
		}
		got := msg.GetInfo()
		if !strings.Contains(got, "GetResponse") {
			t.Errorf("GetInfo() = %q, expected GetResponse", got)
		}
	})

	t.Run("SNMPv2c", func(t *testing.T) {
		data := []byte{
			0x30, 0x0E,
			0x02, 0x01, 0x01, // version 1 (SNMPv2c)
			0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
			0xA0, 0x00,
		}

		msg, err := ParseSNMP(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.Version != 1 {
			t.Errorf("Version = %d, want 1", msg.Version)
		}
		got := msg.GetInfo()
		if !strings.Contains(got, "SNMPv2") {
			t.Errorf("GetInfo() = %q, expected SNMPv2", got)
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, err := ParseSNMP(make([]byte, 9))
		if err == nil {
			t.Error("expected error for short packet")
		}
	})

	t.Run("invalid sequence tag", func(t *testing.T) {
		data := make([]byte, 10)
		data[0] = 0x31 // not SEQUENCE (0x30)
		_, err := ParseSNMP(data)
		if err == nil {
			t.Error("expected error for invalid SNMP packet")
		}
	})
}

// --- IGMP tests ---

func TestParseIGMP(t *testing.T) {
	t.Run("membership query general", func(t *testing.T) {
		data := make([]byte, 8)
		data[0] = 0x11 // Membership Query
		data[1] = 100  // Max Response Time
		// Group address: 0.0.0.0 (all zeros)

		msg, err := ParseIGMP(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.Type != 0x11 {
			t.Errorf("Type = 0x%02x, want 0x11", msg.Type)
		}
		if msg.GroupAddress != "0.0.0.0" {
			t.Errorf("GroupAddress = %q, want %q", msg.GroupAddress, "0.0.0.0")
		}
		got := msg.GetInfo()
		want := "Membership Query, general"
		if got != want {
			t.Errorf("GetInfo() = %q, want %q", got, want)
		}
	})

	t.Run("membership query group-specific", func(t *testing.T) {
		data := make([]byte, 8)
		data[0] = 0x11
		data[4] = 224
		data[5] = 0
		data[6] = 0
		data[7] = 1

		msg, err := ParseIGMP(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.GroupAddress != "224.0.0.1" {
			t.Errorf("GroupAddress = %q, want %q", msg.GroupAddress, "224.0.0.1")
		}
		got := msg.GetInfo()
		want := "Membership Query, group 224.0.0.1"
		if got != want {
			t.Errorf("GetInfo() = %q, want %q", got, want)
		}
	})

	t.Run("membership report v2", func(t *testing.T) {
		data := make([]byte, 8)
		data[0] = 0x16 // Membership Report V2
		data[4] = 239
		data[5] = 1
		data[6] = 2
		data[7] = 3

		msg, err := ParseIGMP(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := msg.GetInfo()
		want := "Membership Report V2, group 239.1.2.3"
		if got != want {
			t.Errorf("GetInfo() = %q, want %q", got, want)
		}
	})

	t.Run("membership report v3", func(t *testing.T) {
		data := make([]byte, 8)
		data[0] = 0x22 // Membership Report V3

		msg, err := ParseIGMP(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := msg.GetInfo()
		if got != "Membership Report V3" {
			t.Errorf("GetInfo() = %q, want %q", got, "Membership Report V3")
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, err := ParseIGMP(make([]byte, 7))
		if err == nil {
			t.Error("expected error for short packet")
		}
	})
}

// --- DNS name parsing (tested indirectly via LLMNR/mDNS) ---

func TestParseDNSName(t *testing.T) {
	t.Run("multi-label name", func(t *testing.T) {
		data := buildLLMNRPacket(0x0000, 1, "host.example.com")
		msg, err := ParseLLMNR(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.QueryName != "host.example.com" {
			t.Errorf("QueryName = %q, want %q", msg.QueryName, "host.example.com")
		}
	})

	t.Run("single label", func(t *testing.T) {
		data := buildLLMNRPacket(0x0000, 1, "mypc")
		msg, err := ParseLLMNR(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.QueryName != "mypc" {
			t.Errorf("QueryName = %q, want %q", msg.QueryName, "mypc")
		}
	})

	t.Run("deeply nested labels via mDNS", func(t *testing.T) {
		name := []byte{
			8, '_', 'p', 'r', 'i', 'n', 't', 'e', 'r',
			4, '_', 's', 'u', 'b',
			5, '_', 'h', 't', 't', 'p',
			4, '_', 't', 'c', 'p',
			5, 'l', 'o', 'c', 'a', 'l',
			0,
		}
		data := make([]byte, 12+len(name)+4)
		binary.BigEndian.PutUint16(data[4:6], 1) // 1 question
		copy(data[12:], name)
		offset := 12 + len(name)
		binary.BigEndian.PutUint16(data[offset:offset+2], 12)  // PTR
		binary.BigEndian.PutUint16(data[offset+2:offset+4], 1) // IN

		msg, err := ParseMDNS(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "_printer._sub._http._tcp.local"
		if len(msg.Queries) == 0 || msg.Queries[0].Name != want {
			var got string
			if len(msg.Queries) > 0 {
				got = msg.Queries[0].Name
			}
			t.Errorf("query name = %q, want %q", got, want)
		}
	})
}

// --- DNS type name (tested indirectly via LLMNR GetInfo) ---

func TestGetDNSTypeName(t *testing.T) {
	tests := []struct {
		qtype    uint16
		wantType string
	}{
		{1, "A"},
		{28, "AAAA"},
		{12, "PTR"},
		{33, "SRV"},
		{255, "ANY"},
		{999, "TYPE999"},
	}
	for _, tt := range tests {
		t.Run(tt.wantType, func(t *testing.T) {
			msg := &LLMNRMessage{
				Flags:     0x0000,
				QueryType: tt.qtype,
				QueryName: "test",
			}
			got := msg.GetInfo()
			want := "Standard query " + tt.wantType + " test"
			if got != want {
				t.Errorf("GetInfo() = %q, want %q", got, want)
			}
		})
	}
}
