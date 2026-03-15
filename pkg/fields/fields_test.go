package fields

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Zerofisher/pktanalyzer/pkg/capture"
)

// helper: build a minimal PacketInfo for frame-level tests.
func newFramePacket(number, length int) *capture.PacketInfo {
	return &capture.PacketInfo{
		Number:    number,
		Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Length:    length,
		Layers: []capture.LayerInfo{
			{Name: "Ethernet II"},
			{Name: "IPv4"},
			{Name: "TCP"},
		},
	}
}

// helper: build a TCP packet with ports and flags.
func newTCPPacket() *capture.PacketInfo {
	return &capture.PacketInfo{
		Number:     1,
		Length:     100,
		Protocol:   "TCP",
		SrcIP:      "10.0.0.1",
		DstIP:      "10.0.0.2",
		SrcPort:    "12345",
		DstPort:    "443",
		TCPSeq:     1000,
		TCPAck:     2000,
		TCPFlags:   0x002, // SYN
		TCPPayload: []byte("hello"),
	}
}

// helper: build a UDP/DNS packet.
func newDNSPacket() *capture.PacketInfo {
	return &capture.PacketInfo{
		Number:   2,
		Length:   80,
		Protocol: "DNS",
		SrcIP:    "10.0.0.1",
		DstIP:    "8.8.8.8",
		SrcPort:  "54321",
		DstPort:  "53",
		Info:     "Query: example.com A",
	}
}

// helper: build an HTTP request packet.
func newHTTPRequestPacket() *capture.PacketInfo {
	return &capture.PacketInfo{
		Number:   3,
		Length:   200,
		Protocol: "HTTP",
		SrcIP:    "10.0.0.1",
		DstIP:    "93.184.216.34",
		SrcPort:  "50000",
		DstPort:  "80",
		Info:     "GET /path HTTP/1.1",
	}
}

// helper: build a TLS Client Hello packet with SNI.
func newTLSPacket() *capture.PacketInfo {
	return &capture.PacketInfo{
		Number:   4,
		Length:   300,
		Protocol: "TLS",
		SrcIP:    "10.0.0.1",
		DstIP:    "93.184.216.34",
		SrcPort:  "50001",
		DstPort:  "443",
		Info:     "Client Hello",
		SNI:      "www.example.com",
	}
}

// helper: build a plain UDP packet (not DNS, not any recognized app protocol).
func newUDPPacket() *capture.PacketInfo {
	return &capture.PacketInfo{
		Number:   5,
		Length:   64,
		Protocol: "UDP",
		SrcIP:    "10.0.0.1",
		DstIP:    "10.0.0.2",
		SrcPort:  "9999",
		DstPort:  "9998",
		Info:     "9999 -> 9998 Len=64",
	}
}

// ---------------------------------------------------------------------------
// 1. TestNewRegistry
// ---------------------------------------------------------------------------

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}

	// Spot-check a few standard fields that must be present.
	expected := []string{
		"frame.number", "frame.time", "frame.len", "frame.protocols",
		"eth.src", "eth.dst",
		"ip.src", "ip.dst", "ip.proto",
		"tcp.srcport", "tcp.dstport", "tcp.flags.syn",
		"udp.srcport", "udp.dstport",
		"dns.qry.name", "dns.qry.type",
		"http.request.method", "http.request.uri",
		"tls.sni", "tls.handshake",
		"frame.protocol",
	}
	for _, name := range expected {
		if r.Get(name) == nil {
			t.Errorf("standard field %q not registered", name)
		}
	}
}

// ---------------------------------------------------------------------------
// 2. TestRegistry_Get
// ---------------------------------------------------------------------------

func TestRegistry_Get(t *testing.T) {
	r := NewRegistry()

	t.Run("existing field", func(t *testing.T) {
		fd := r.Get("ip.src")
		if fd == nil {
			t.Fatal("Get(ip.src) returned nil")
		}
		if fd.Name != "ip.src" {
			t.Errorf("expected Name ip.src, got %s", fd.Name)
		}
		if fd.Description == "" {
			t.Error("expected non-empty Description")
		}
	})

	t.Run("non-existing field", func(t *testing.T) {
		fd := r.Get("nonexistent.field")
		if fd != nil {
			t.Errorf("expected nil for unknown field, got %+v", fd)
		}
	})
}

// ---------------------------------------------------------------------------
// 3. TestRegistry_List
// ---------------------------------------------------------------------------

func TestRegistry_List(t *testing.T) {
	r := NewRegistry()
	names := r.List()

	if len(names) == 0 {
		t.Fatal("List returned empty slice")
	}

	// All standard fields must appear in the list.
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}

	required := []string{
		"frame.number", "ip.src", "tcp.srcport",
		"udp.srcport", "dns.qry.name", "http.request.method",
		"tls.sni", "frame.protocol",
	}
	for _, req := range required {
		if !nameSet[req] {
			t.Errorf("field %q missing from List()", req)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. TestRegistry_ListByPrefix
// ---------------------------------------------------------------------------

func TestRegistry_ListByPrefix(t *testing.T) {
	r := NewRegistry()

	tcpFields := r.ListByPrefix("tcp.")
	if len(tcpFields) == 0 {
		t.Fatal("ListByPrefix(tcp.) returned empty slice")
	}

	sort.Strings(tcpFields)
	for _, name := range tcpFields {
		if !strings.HasPrefix(name, "tcp.") {
			t.Errorf("field %q does not have prefix tcp.", name)
		}
	}

	// We know at least these tcp fields exist.
	expectedTCP := map[string]bool{
		"tcp.srcport":   false,
		"tcp.dstport":   false,
		"tcp.port":      false,
		"tcp.seq":       false,
		"tcp.ack":       false,
		"tcp.flags":     false,
		"tcp.flags.syn": false,
		"tcp.flags.ack": false,
		"tcp.flags.fin": false,
		"tcp.flags.rst": false,
		"tcp.flags.psh": false,
		"tcp.len":       false,
		"tcp.stream":    false,
	}
	for _, name := range tcpFields {
		if _, ok := expectedTCP[name]; ok {
			expectedTCP[name] = true
		}
	}
	for name, found := range expectedTCP {
		if !found {
			t.Errorf("expected tcp field %q not in ListByPrefix result", name)
		}
	}

	// Prefix that matches nothing.
	empty := r.ListByPrefix("zzz.")
	if len(empty) != 0 {
		t.Errorf("expected empty result for prefix zzz., got %d", len(empty))
	}
}

// ---------------------------------------------------------------------------
// 5. TestRegistry_Extract_FrameFields
// ---------------------------------------------------------------------------

func TestRegistry_Extract_FrameFields(t *testing.T) {
	r := NewRegistry()
	pkt := newFramePacket(42, 1500)

	tests := []struct {
		field    string
		wantVal  any
		wantBool bool
	}{
		{"frame.number", 42, true},
		{"frame.len", 1500, true},
	}
	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			val, ok := r.Extract(tc.field, pkt)
			if ok != tc.wantBool {
				t.Fatalf("Extract(%s) ok=%v, want %v", tc.field, ok, tc.wantBool)
			}
			if val != tc.wantVal {
				t.Errorf("Extract(%s) = %v (%T), want %v (%T)", tc.field, val, val, tc.wantVal, tc.wantVal)
			}
		})
	}

	// frame.time should return a time.Time
	t.Run("frame.time", func(t *testing.T) {
		val, ok := r.Extract("frame.time", pkt)
		if !ok {
			t.Fatal("Extract(frame.time) returned false")
		}
		ts, isTime := val.(time.Time)
		if !isTime {
			t.Fatalf("expected time.Time, got %T", val)
		}
		if ts.Year() != 2025 {
			t.Errorf("expected year 2025, got %d", ts.Year())
		}
	})

	// frame.protocols should concatenate layer names.
	t.Run("frame.protocols", func(t *testing.T) {
		val, ok := r.Extract("frame.protocols", pkt)
		if !ok {
			t.Fatal("Extract(frame.protocols) returned false")
		}
		s, isStr := val.(string)
		if !isStr {
			t.Fatalf("expected string, got %T", val)
		}
		if !strings.Contains(s, "ethernet_ii") {
			t.Errorf("expected protocols string to contain ethernet_ii, got %q", s)
		}
		if !strings.Contains(s, "ipv4") {
			t.Errorf("expected protocols string to contain ipv4, got %q", s)
		}
		if !strings.Contains(s, "tcp") {
			t.Errorf("expected protocols string to contain tcp, got %q", s)
		}
	})
}

// ---------------------------------------------------------------------------
// 6. TestRegistry_Extract_IPFields
// ---------------------------------------------------------------------------

func TestRegistry_Extract_IPFields(t *testing.T) {
	r := NewRegistry()
	pkt := newTCPPacket()

	tests := []struct {
		field string
		want  string
	}{
		{"ip.src", "10.0.0.1"},
		{"ip.dst", "10.0.0.2"},
		{"ip.proto", "TCP"},
	}
	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			val, ok := r.Extract(tc.field, pkt)
			if !ok {
				t.Fatalf("Extract(%s) returned false", tc.field)
			}
			s, isStr := val.(string)
			if !isStr {
				t.Fatalf("expected string, got %T", val)
			}
			if s != tc.want {
				t.Errorf("Extract(%s) = %q, want %q", tc.field, s, tc.want)
			}
		})
	}

	// ip.addr returns "src,dst"
	t.Run("ip.addr", func(t *testing.T) {
		val, ok := r.Extract("ip.addr", pkt)
		if !ok {
			t.Fatal("Extract(ip.addr) returned false")
		}
		s := val.(string)
		if !strings.Contains(s, "10.0.0.1") || !strings.Contains(s, "10.0.0.2") {
			t.Errorf("ip.addr = %q, expected both src and dst IPs", s)
		}
	})
}

// ---------------------------------------------------------------------------
// 7. TestRegistry_Extract_TCPFields
// ---------------------------------------------------------------------------

func TestRegistry_Extract_TCPFields(t *testing.T) {
	r := NewRegistry()
	pkt := newTCPPacket()

	t.Run("tcp.srcport", func(t *testing.T) {
		val, ok := r.Extract("tcp.srcport", pkt)
		if !ok {
			t.Fatal("Extract(tcp.srcport) returned false")
		}
		port, isU16 := val.(uint16)
		if !isU16 {
			t.Fatalf("expected uint16, got %T", val)
		}
		if port != 12345 {
			t.Errorf("tcp.srcport = %d, want 12345", port)
		}
	})

	t.Run("tcp.dstport", func(t *testing.T) {
		val, ok := r.Extract("tcp.dstport", pkt)
		if !ok {
			t.Fatal("Extract(tcp.dstport) returned false")
		}
		port := val.(uint16)
		if port != 443 {
			t.Errorf("tcp.dstport = %d, want 443", port)
		}
	})

	t.Run("tcp.flags.syn", func(t *testing.T) {
		val, ok := r.Extract("tcp.flags.syn", pkt)
		if !ok {
			t.Fatal("Extract(tcp.flags.syn) returned false")
		}
		syn, isBool := val.(bool)
		if !isBool {
			t.Fatalf("expected bool, got %T", val)
		}
		if !syn {
			t.Error("expected SYN flag to be true")
		}
	})

	t.Run("tcp.flags.ack is false when only SYN set", func(t *testing.T) {
		val, ok := r.Extract("tcp.flags.ack", pkt)
		if !ok {
			t.Fatal("Extract(tcp.flags.ack) returned false")
		}
		ack := val.(bool)
		if ack {
			t.Error("expected ACK flag to be false (only SYN set)")
		}
	})

	t.Run("tcp.seq", func(t *testing.T) {
		val, ok := r.Extract("tcp.seq", pkt)
		if !ok {
			t.Fatal("Extract(tcp.seq) returned false")
		}
		seq, isU32 := val.(uint32)
		if !isU32 {
			t.Fatalf("expected uint32, got %T", val)
		}
		if seq != 1000 {
			t.Errorf("tcp.seq = %d, want 1000", seq)
		}
	})

	t.Run("tcp.len", func(t *testing.T) {
		val, ok := r.Extract("tcp.len", pkt)
		if !ok {
			t.Fatal("Extract(tcp.len) returned false")
		}
		length, isInt := val.(int)
		if !isInt {
			t.Fatalf("expected int, got %T", val)
		}
		if length != 5 { // len("hello")
			t.Errorf("tcp.len = %d, want 5", length)
		}
	})
}

// ---------------------------------------------------------------------------
// 8. TestRegistry_Extract_DNSFields
// ---------------------------------------------------------------------------

func TestRegistry_Extract_DNSFields(t *testing.T) {
	r := NewRegistry()
	pkt := newDNSPacket()

	t.Run("dns.qry.name", func(t *testing.T) {
		val, ok := r.Extract("dns.qry.name", pkt)
		if !ok {
			t.Fatal("Extract(dns.qry.name) returned false")
		}
		name, isStr := val.(string)
		if !isStr {
			t.Fatalf("expected string, got %T", val)
		}
		if name != "example.com" {
			t.Errorf("dns.qry.name = %q, want %q", name, "example.com")
		}
	})

	t.Run("dns.qry.type", func(t *testing.T) {
		val, ok := r.Extract("dns.qry.type", pkt)
		if !ok {
			t.Fatal("Extract(dns.qry.type) returned false")
		}
		qtype := val.(string)
		if qtype != "A" {
			t.Errorf("dns.qry.type = %q, want %q", qtype, "A")
		}
	})

	t.Run("dns.flags.response for query", func(t *testing.T) {
		val, ok := r.Extract("dns.flags.response", pkt)
		if !ok {
			t.Fatal("Extract(dns.flags.response) returned false")
		}
		isResp := val.(bool)
		if isResp {
			t.Error("expected dns.flags.response to be false for a query")
		}
	})

	t.Run("dns.flags.response for response", func(t *testing.T) {
		respPkt := &capture.PacketInfo{
			Protocol: "DNS",
			Info:     "Response: example.com -> 93.184.216.34",
		}
		val, ok := r.Extract("dns.flags.response", respPkt)
		if !ok {
			t.Fatal("Extract(dns.flags.response) returned false")
		}
		isResp := val.(bool)
		if !isResp {
			t.Error("expected dns.flags.response to be true for a response")
		}
	})

	t.Run("dns fields return nil for non-DNS", func(t *testing.T) {
		tcpPkt := newTCPPacket()
		val, ok := r.Extract("dns.qry.name", tcpPkt)
		if ok {
			t.Errorf("expected dns.qry.name to return false for TCP packet, got val=%v", val)
		}
	})
}

// ---------------------------------------------------------------------------
// 9. TestRegistry_Extract_HTTPFields
// ---------------------------------------------------------------------------

func TestRegistry_Extract_HTTPFields(t *testing.T) {
	r := NewRegistry()
	pkt := newHTTPRequestPacket()

	t.Run("http.request.method", func(t *testing.T) {
		val, ok := r.Extract("http.request.method", pkt)
		if !ok {
			t.Fatal("Extract(http.request.method) returned false")
		}
		method := val.(string)
		if method != "GET" {
			t.Errorf("http.request.method = %q, want %q", method, "GET")
		}
	})

	t.Run("http.request.uri", func(t *testing.T) {
		val, ok := r.Extract("http.request.uri", pkt)
		if !ok {
			t.Fatal("Extract(http.request.uri) returned false")
		}
		uri := val.(string)
		if uri != "/path" {
			t.Errorf("http.request.uri = %q, want %q", uri, "/path")
		}
	})

	t.Run("http.request is true for GET", func(t *testing.T) {
		val, ok := r.Extract("http.request", pkt)
		if !ok {
			t.Fatal("Extract(http.request) returned false")
		}
		isReq := val.(bool)
		if !isReq {
			t.Error("expected http.request to be true for GET request")
		}
	})

	t.Run("http.response for response packet", func(t *testing.T) {
		respPkt := &capture.PacketInfo{
			Protocol: "HTTP",
			Info:     "HTTP/1.1 200 OK",
		}
		val, ok := r.Extract("http.response", respPkt)
		if !ok {
			t.Fatal("Extract(http.response) returned false")
		}
		isResp := val.(bool)
		if !isResp {
			t.Error("expected http.response to be true for HTTP response")
		}
	})

	t.Run("http.response.code", func(t *testing.T) {
		respPkt := &capture.PacketInfo{
			Protocol: "HTTP",
			Info:     "HTTP/1.1 200 OK",
		}
		val, ok := r.Extract("http.response.code", respPkt)
		if !ok {
			t.Fatal("Extract(http.response.code) returned false")
		}
		code, isInt := val.(int)
		if !isInt {
			t.Fatalf("expected int, got %T", val)
		}
		if code != 200 {
			t.Errorf("http.response.code = %d, want 200", code)
		}
	})

	t.Run("http fields return nil for non-HTTP", func(t *testing.T) {
		tcpPkt := newTCPPacket()
		val, ok := r.Extract("http.request.method", tcpPkt)
		if ok {
			t.Errorf("expected http.request.method to return false for TCP packet, got val=%v", val)
		}
	})
}

// ---------------------------------------------------------------------------
// 10. TestRegistry_Extract_TLSFields
// ---------------------------------------------------------------------------

func TestRegistry_Extract_TLSFields(t *testing.T) {
	r := NewRegistry()
	pkt := newTLSPacket()

	t.Run("tls.sni", func(t *testing.T) {
		val, ok := r.Extract("tls.sni", pkt)
		if !ok {
			t.Fatal("Extract(tls.sni) returned false")
		}
		sni := val.(string)
		if sni != "www.example.com" {
			t.Errorf("tls.sni = %q, want %q", sni, "www.example.com")
		}
	})

	t.Run("tls.sni empty when no SNI", func(t *testing.T) {
		noSNI := &capture.PacketInfo{
			Protocol: "TLS",
			Info:     "Application Data",
			SNI:      "",
		}
		_, ok := r.Extract("tls.sni", noSNI)
		if ok {
			t.Error("expected tls.sni to return false when SNI is empty")
		}
	})

	t.Run("tls.handshake", func(t *testing.T) {
		val, ok := r.Extract("tls.handshake", pkt)
		if !ok {
			t.Fatal("Extract(tls.handshake) returned false")
		}
		isHS := val.(bool)
		if !isHS {
			t.Error("expected tls.handshake to be true for Client Hello")
		}
	})

	t.Run("tls.handshake.type", func(t *testing.T) {
		val, ok := r.Extract("tls.handshake.type", pkt)
		if !ok {
			t.Fatal("Extract(tls.handshake.type) returned false")
		}
		hsType := val.(string)
		if hsType != "Client Hello" {
			t.Errorf("tls.handshake.type = %q, want %q", hsType, "Client Hello")
		}
	})

	t.Run("tls fields return nil for non-TLS", func(t *testing.T) {
		tcpPkt := newTCPPacket()
		_, ok := r.Extract("tls.handshake", tcpPkt)
		// tls.handshake checks Protocol == "TLS"; TCP packet returns nil.
		// The extractor returns nil, so ok should be false.
		if ok {
			t.Error("expected tls.handshake to return false for TCP packet")
		}
	})
}

// ---------------------------------------------------------------------------
// 11. TestRegistry_ExtractString
// ---------------------------------------------------------------------------

func TestRegistry_ExtractString(t *testing.T) {
	r := NewRegistry()

	t.Run("string field (ip.src)", func(t *testing.T) {
		pkt := newTCPPacket()
		s := r.ExtractString("ip.src", pkt)
		if s != "10.0.0.1" {
			t.Errorf("ExtractString(ip.src) = %q, want %q", s, "10.0.0.1")
		}
	})

	t.Run("int field (frame.number)", func(t *testing.T) {
		pkt := newFramePacket(99, 500)
		s := r.ExtractString("frame.number", pkt)
		if s != "99" {
			t.Errorf("ExtractString(frame.number) = %q, want %q", s, "99")
		}
	})

	t.Run("uint16 field (tcp.srcport)", func(t *testing.T) {
		pkt := newTCPPacket()
		s := r.ExtractString("tcp.srcport", pkt)
		if s != "12345" {
			t.Errorf("ExtractString(tcp.srcport) = %q, want %q", s, "12345")
		}
	})

	t.Run("uint32 field (tcp.seq)", func(t *testing.T) {
		pkt := newTCPPacket()
		s := r.ExtractString("tcp.seq", pkt)
		if s != "1000" {
			t.Errorf("ExtractString(tcp.seq) = %q, want %q", s, "1000")
		}
	})

	t.Run("bool field true (tcp.flags.syn)", func(t *testing.T) {
		pkt := newTCPPacket()
		s := r.ExtractString("tcp.flags.syn", pkt)
		if s != "1" {
			t.Errorf("ExtractString(tcp.flags.syn) = %q, want %q", s, "1")
		}
	})

	t.Run("bool field false (tcp.flags.fin)", func(t *testing.T) {
		pkt := newTCPPacket()
		s := r.ExtractString("tcp.flags.fin", pkt)
		if s != "0" {
			t.Errorf("ExtractString(tcp.flags.fin) = %q, want %q", s, "0")
		}
	})

	t.Run("non-existing field returns empty", func(t *testing.T) {
		pkt := newTCPPacket()
		s := r.ExtractString("nonexistent", pkt)
		if s != "" {
			t.Errorf("ExtractString(nonexistent) = %q, want empty", s)
		}
	})

	t.Run("nil extractor result returns empty", func(t *testing.T) {
		// dns.qry.name on a TCP packet returns nil.
		pkt := newTCPPacket()
		s := r.ExtractString("dns.qry.name", pkt)
		if s != "" {
			t.Errorf("ExtractString(dns.qry.name) on TCP = %q, want empty", s)
		}
	})
}

// ---------------------------------------------------------------------------
// 12. TestRegistry_Register
// ---------------------------------------------------------------------------

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()

	custom := &FieldDef{
		Name:        "custom.field",
		Description: "A custom test field",
		Type:        TypeString,
		Extractor: func(p *capture.PacketInfo) any {
			return "custom_value"
		},
	}
	r.Register(custom)

	t.Run("custom field retrievable via Get", func(t *testing.T) {
		fd := r.Get("custom.field")
		if fd == nil {
			t.Fatal("custom.field not found after Register")
		}
		if fd.Description != "A custom test field" {
			t.Errorf("Description = %q, want %q", fd.Description, "A custom test field")
		}
	})

	t.Run("custom field in List", func(t *testing.T) {
		names := r.List()
		found := false
		for _, n := range names {
			if n == "custom.field" {
				found = true
				break
			}
		}
		if !found {
			t.Error("custom.field not found in List()")
		}
	})

	t.Run("custom field extraction works", func(t *testing.T) {
		pkt := newTCPPacket()
		val, ok := r.Extract("custom.field", pkt)
		if !ok {
			t.Fatal("Extract(custom.field) returned false")
		}
		if val != "custom_value" {
			t.Errorf("Extract(custom.field) = %v, want %q", val, "custom_value")
		}
	})

	t.Run("register overwrites existing field", func(t *testing.T) {
		override := &FieldDef{
			Name:        "custom.field",
			Description: "Overridden",
			Type:        TypeInt,
			Extractor: func(p *capture.PacketInfo) any {
				return 42
			},
		}
		r.Register(override)

		fd := r.Get("custom.field")
		if fd.Description != "Overridden" {
			t.Errorf("expected overridden description, got %q", fd.Description)
		}
		val, _ := r.Extract("custom.field", newTCPPacket())
		if val != 42 {
			t.Errorf("expected 42 after override, got %v", val)
		}
	})
}

// ---------------------------------------------------------------------------
// 13. TestRegistry_GetFieldInfo
// ---------------------------------------------------------------------------

func TestRegistry_GetFieldInfo(t *testing.T) {
	r := NewRegistry()

	t.Run("known field", func(t *testing.T) {
		info := r.GetFieldInfo("tcp.srcport")
		if info == "" {
			t.Fatal("GetFieldInfo(tcp.srcport) returned empty string")
		}
		if !strings.Contains(info, "tcp.srcport") {
			t.Errorf("expected info to contain field name, got %q", info)
		}
		if !strings.Contains(info, "uint16") {
			t.Errorf("expected info to contain type uint16, got %q", info)
		}
	})

	t.Run("field types in info", func(t *testing.T) {
		cases := []struct {
			name     string
			wantType string
		}{
			{"frame.number", "int"},
			{"ip.src", "string"},
			{"tcp.flags.syn", "bool"},
			{"tcp.seq", "uint32"},
			{"frame.time", "time"},
			{"frame.time_epoch", "float"},
		}
		for _, tc := range cases {
			info := r.GetFieldInfo(tc.name)
			if !strings.Contains(info, tc.wantType) {
				t.Errorf("GetFieldInfo(%s) = %q, expected to contain type %q", tc.name, info, tc.wantType)
			}
		}
	})

	t.Run("unknown field returns empty", func(t *testing.T) {
		info := r.GetFieldInfo("does.not.exist")
		if info != "" {
			t.Errorf("GetFieldInfo for unknown field returned %q, want empty", info)
		}
	})
}

// ---------------------------------------------------------------------------
// 14. TestRegistry_Extract_NonTCP
// ---------------------------------------------------------------------------

func TestRegistry_Extract_NonTCP(t *testing.T) {
	r := NewRegistry()
	pkt := newUDPPacket()

	tcpFields := []string{
		"tcp.srcport",
		"tcp.dstport",
		"tcp.port",
	}

	for _, field := range tcpFields {
		t.Run(field+" returns nil for UDP", func(t *testing.T) {
			val, ok := r.Extract(field, pkt)
			if ok {
				t.Errorf("Extract(%s) on UDP packet should return false, got val=%v", field, val)
			}
		})
	}

	// tcp.seq and tcp.ack return nil when zero and Protocol != "TCP".
	t.Run("tcp.seq nil for UDP with zero seq", func(t *testing.T) {
		val, ok := r.Extract("tcp.seq", pkt)
		if ok {
			t.Errorf("Extract(tcp.seq) on UDP packet should return false, got val=%v", val)
		}
	})

	t.Run("tcp.ack nil for UDP with zero ack", func(t *testing.T) {
		val, ok := r.Extract("tcp.ack", pkt)
		if ok {
			t.Errorf("Extract(tcp.ack) on UDP packet should return false, got val=%v", val)
		}
	})

	// Verify that TLS-related handshake fields also return nil for UDP.
	t.Run("tls.handshake nil for UDP", func(t *testing.T) {
		_, ok := r.Extract("tls.handshake", pkt)
		if ok {
			t.Error("Extract(tls.handshake) on UDP packet should return false")
		}
	})

	// But UDP fields SHOULD work for a UDP packet.
	t.Run("udp.srcport works for UDP", func(t *testing.T) {
		val, ok := r.Extract("udp.srcport", pkt)
		if !ok {
			t.Fatal("Extract(udp.srcport) on UDP packet returned false")
		}
		port := val.(uint16)
		if port != 9999 {
			t.Errorf("udp.srcport = %d, want 9999", port)
		}
	})

	// Ensure DNS-protocol UDP packets report udp.srcport too.
	t.Run("udp.srcport works for DNS", func(t *testing.T) {
		dnsPkt := newDNSPacket()
		val, ok := r.Extract("udp.srcport", dnsPkt)
		if !ok {
			t.Fatal("Extract(udp.srcport) on DNS packet returned false")
		}
		port := val.(uint16)
		if port != 54321 {
			t.Errorf("udp.srcport on DNS = %d, want 54321", port)
		}
	})
}
