package filter

import (
	"strings"
	"testing"
	"time"

	"github.com/Zerofisher/pktanalyzer/pkg/capture"
)

// ---------------------------------------------------------------------------
// Helper: build a PacketInfo with sensible defaults.
// ---------------------------------------------------------------------------

func newPacketInfo(opts ...func(*capture.PacketInfo)) *capture.PacketInfo {
	pkt := &capture.PacketInfo{
		Number:    1,
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Length:    64,
		SrcMAC:    "aa:bb:cc:dd:ee:ff",
		DstMAC:    "11:22:33:44:55:66",
		EtherType: "IPv4",
		SrcIP:     "192.168.1.1",
		DstIP:     "10.0.0.1",
		Protocol:  "TCP",
		SrcPort:   "12345",
		DstPort:   "80",
		Info:      "",
	}
	for _, fn := range opts {
		fn(pkt)
	}
	return pkt
}

func withProtocol(proto string) func(*capture.PacketInfo) {
	return func(p *capture.PacketInfo) { p.Protocol = proto }
}

func withSrcIP(ip string) func(*capture.PacketInfo) {
	return func(p *capture.PacketInfo) { p.SrcIP = ip }
}

func withDstIP(ip string) func(*capture.PacketInfo) {
	return func(p *capture.PacketInfo) { p.DstIP = ip }
}

func withPorts(src, dst string) func(*capture.PacketInfo) {
	return func(p *capture.PacketInfo) {
		p.SrcPort = src
		p.DstPort = dst
	}
}

func withTCPFlags(flags uint16) func(*capture.PacketInfo) {
	return func(p *capture.PacketInfo) { p.TCPFlags = flags }
}

func withInfo(info string) func(*capture.PacketInfo) {
	return func(p *capture.PacketInfo) { p.Info = info }
}

func withSNI(sni string) func(*capture.PacketInfo) {
	return func(p *capture.PacketInfo) { p.SNI = sni }
}

func withLength(n int) func(*capture.PacketInfo) {
	return func(p *capture.PacketInfo) { p.Length = n }
}

func withStreamKey(key string) func(*capture.PacketInfo) {
	return func(p *capture.PacketInfo) { p.StreamKey = key }
}

// ---------------------------------------------------------------------------
// 1. TestCompile_SimpleProtocol
// ---------------------------------------------------------------------------

func TestCompile_SimpleProtocol(t *testing.T) {
	t.Parallel()

	protocols := []string{"tcp", "udp", "dns", "http", "arp", "tls", "icmp"}
	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			fn, err := Compile(proto)
			if err != nil {
				t.Fatalf("Compile(%q) returned error: %v", proto, err)
			}
			if fn == nil {
				t.Fatalf("Compile(%q) returned nil function", proto)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. TestCompile_FieldComparison
// ---------------------------------------------------------------------------

func TestCompile_FieldComparison(t *testing.T) {
	t.Parallel()

	filters := []string{
		`ip.src == "192.168.1.1"`,
		`ip.dst == "10.0.0.1"`,
		`frame.len > 100`,
		`tcp.srcport == 80`,
	}
	for _, f := range filters {
		t.Run(f, func(t *testing.T) {
			fn, err := Compile(f)
			if err != nil {
				t.Fatalf("Compile(%q) returned error: %v", f, err)
			}
			if fn == nil {
				t.Fatalf("Compile(%q) returned nil function", f)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. TestCompile_LogicalOperators
// ---------------------------------------------------------------------------

func TestCompile_LogicalOperators(t *testing.T) {
	t.Parallel()

	filters := []string{
		"tcp and not dns",
		"tcp or udp",
		"not arp",
		"tcp and ip.src == \"192.168.1.1\"",
	}
	for _, f := range filters {
		t.Run(f, func(t *testing.T) {
			fn, err := Compile(f)
			if err != nil {
				t.Fatalf("Compile(%q) returned error: %v", f, err)
			}
			if fn == nil {
				t.Fatalf("Compile(%q) returned nil function", f)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 4. TestCompile_InvalidSyntax
// ---------------------------------------------------------------------------

func TestCompile_InvalidSyntax(t *testing.T) {
	t.Parallel()

	invalid := []string{
		"tcp ===",
		"(((",
		"unknown_field +++ 42",
	}
	for _, f := range invalid {
		t.Run(f, func(t *testing.T) {
			_, err := Compile(f)
			if err == nil {
				t.Fatalf("Compile(%q) expected error, got nil", f)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 5. TestFilter_Protocol - table-driven
// ---------------------------------------------------------------------------

func TestFilter_Protocol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		filter string
		pkt    *capture.PacketInfo
		want   bool
	}{
		{
			name:   "tcp matches TCP packet",
			filter: "tcp",
			pkt:    newPacketInfo(withProtocol("TCP")),
			want:   true,
		},
		{
			name:   "tcp does not match UDP packet",
			filter: "tcp",
			pkt:    newPacketInfo(withProtocol("UDP")),
			want:   false,
		},
		{
			name:   "udp matches UDP packet",
			filter: "udp",
			pkt:    newPacketInfo(withProtocol("UDP")),
			want:   true,
		},
		{
			name:   "udp does not match TCP packet",
			filter: "udp",
			pkt:    newPacketInfo(withProtocol("TCP")),
			want:   false,
		},
		{
			name:   "tcp matches HTTP packet (HTTP runs on TCP)",
			filter: "tcp",
			pkt:    newPacketInfo(withProtocol("HTTP")),
			want:   true,
		},
		{
			name:   "tcp matches TLS packet",
			filter: "tcp",
			pkt:    newPacketInfo(withProtocol("TLS")),
			want:   true,
		},
		{
			name:   "tcp matches HTTPS packet",
			filter: "tcp",
			pkt:    newPacketInfo(withProtocol("HTTPS")),
			want:   true,
		},
		{
			name:   "udp matches DNS packet (DNS runs on UDP)",
			filter: "udp",
			pkt:    newPacketInfo(withProtocol("DNS")),
			want:   true,
		},
		{
			name:   "arp matches ARP packet",
			filter: "arp",
			pkt:    newPacketInfo(withProtocol("ARP")),
			want:   true,
		},
		{
			name:   "arp does not match TCP packet",
			filter: "arp",
			pkt:    newPacketInfo(withProtocol("TCP")),
			want:   false,
		},
		{
			name:   "icmp matches ICMP packet",
			filter: "icmp",
			pkt:    newPacketInfo(withProtocol("ICMP")),
			want:   true,
		},
		{
			name:   "icmp matches ICMPv6 packet",
			filter: "icmp",
			pkt:    newPacketInfo(withProtocol("ICMPv6")),
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := Compile(tt.filter)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.filter, err)
			}
			got := fn(tt.pkt)
			if got != tt.want {
				t.Errorf("filter %q on protocol %q = %v, want %v",
					tt.filter, tt.pkt.Protocol, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 6. TestFilter_Port - "tcp.port == 80" matches src or dst
// ---------------------------------------------------------------------------

func TestFilter_Port(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		filter  string
		srcPort string
		dstPort string
		proto   string
		want    bool
	}{
		{
			name:    "tcp.port matches dst 80",
			filter:  "tcp.port == 80",
			srcPort: "12345",
			dstPort: "80",
			proto:   "TCP",
			want:    true,
		},
		{
			name:    "tcp.port matches src 80",
			filter:  "tcp.port == 80",
			srcPort: "80",
			dstPort: "12345",
			proto:   "TCP",
			want:    true,
		},
		{
			name:    "tcp.port no match",
			filter:  "tcp.port == 80",
			srcPort: "443",
			dstPort: "12345",
			proto:   "TCP",
			want:    false,
		},
		{
			name:    "tcp.srcport exact match",
			filter:  "tcp.srcport == 443",
			srcPort: "443",
			dstPort: "12345",
			proto:   "TCP",
			want:    true,
		},
		{
			name:    "tcp.dstport exact match",
			filter:  "tcp.dstport == 443",
			srcPort: "12345",
			dstPort: "443",
			proto:   "TCP",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := Compile(tt.filter)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.filter, err)
			}
			pkt := newPacketInfo(
				withProtocol(tt.proto),
				withPorts(tt.srcPort, tt.dstPort),
			)
			got := fn(pkt)
			if got != tt.want {
				t.Errorf("filter %q (src=%s, dst=%s) = %v, want %v",
					tt.filter, tt.srcPort, tt.dstPort, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 7. TestFilter_IPAddress
// ---------------------------------------------------------------------------

func TestFilter_IPAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		filter string
		pkt    *capture.PacketInfo
		want   bool
	}{
		{
			name:   "ip.src matches",
			filter: `ip.src == "192.168.1.1"`,
			pkt:    newPacketInfo(withSrcIP("192.168.1.1")),
			want:   true,
		},
		{
			name:   "ip.src does not match",
			filter: `ip.src == "192.168.1.2"`,
			pkt:    newPacketInfo(withSrcIP("192.168.1.1")),
			want:   false,
		},
		{
			name:   "ip.dst matches",
			filter: `ip.dst == "10.0.0.1"`,
			pkt:    newPacketInfo(withDstIP("10.0.0.1")),
			want:   true,
		},
		{
			name:   "ip.dst does not match",
			filter: `ip.dst == "10.0.0.2"`,
			pkt:    newPacketInfo(withDstIP("10.0.0.1")),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := Compile(tt.filter)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.filter, err)
			}
			got := fn(tt.pkt)
			if got != tt.want {
				t.Errorf("filter %q = %v, want %v", tt.filter, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 8. TestFilter_TCPFlags
// ---------------------------------------------------------------------------

func TestFilter_TCPFlags(t *testing.T) {
	t.Parallel()

	const (
		flagFIN = 0x001
		flagSYN = 0x002
		flagRST = 0x004
		flagPSH = 0x008
		flagACK = 0x010
	)

	tests := []struct {
		name   string
		filter string
		flags  uint16
		want   bool
	}{
		{
			name:   "syn flag set",
			filter: "tcp.flags.syn",
			flags:  flagSYN,
			want:   true,
		},
		{
			name:   "syn flag not set",
			filter: "tcp.flags.syn",
			flags:  flagACK,
			want:   false,
		},
		{
			name:   "ack flag set",
			filter: "tcp.flags.ack",
			flags:  flagACK,
			want:   true,
		},
		{
			name:   "ack flag not set",
			filter: "tcp.flags.ack",
			flags:  flagSYN,
			want:   false,
		},
		{
			name:   "syn+ack both set, filter syn",
			filter: "tcp.flags.syn",
			flags:  flagSYN | flagACK,
			want:   true,
		},
		{
			name:   "syn+ack both set, filter ack",
			filter: "tcp.flags.ack",
			flags:  flagSYN | flagACK,
			want:   true,
		},
		{
			name:   "fin flag set",
			filter: "tcp.flags.fin",
			flags:  flagFIN,
			want:   true,
		},
		{
			name:   "rst flag set",
			filter: "tcp.flags.rst",
			flags:  flagRST,
			want:   true,
		},
		{
			name:   "psh flag set",
			filter: "tcp.flags.psh",
			flags:  flagPSH,
			want:   true,
		},
		{
			name:   "psh flag not set on pure SYN",
			filter: "tcp.flags.psh",
			flags:  flagSYN,
			want:   false,
		},
		{
			name:   "combined: syn and not ack",
			filter: "tcp.flags.syn and not tcp.flags.ack",
			flags:  flagSYN,
			want:   true,
		},
		{
			name:   "combined: syn and not ack fails on SYN+ACK",
			filter: "tcp.flags.syn and not tcp.flags.ack",
			flags:  flagSYN | flagACK,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := Compile(tt.filter)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.filter, err)
			}
			pkt := newPacketInfo(
				withProtocol("TCP"),
				withTCPFlags(tt.flags),
			)
			got := fn(pkt)
			if got != tt.want {
				t.Errorf("filter %q flags=0x%03x = %v, want %v",
					tt.filter, tt.flags, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 9. TestFilter_DNS
// ---------------------------------------------------------------------------

func TestFilter_DNS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		filter string
		pkt    *capture.PacketInfo
		want   bool
	}{
		{
			name:   "dns matches DNS protocol",
			filter: "dns",
			pkt:    newPacketInfo(withProtocol("DNS"), withPorts("53", "12345")),
			want:   true,
		},
		{
			name:   "dns does not match TCP",
			filter: "dns",
			pkt:    newPacketInfo(withProtocol("TCP")),
			want:   false,
		},
		{
			name:   "dns does not match plain UDP",
			filter: "dns",
			pkt:    newPacketInfo(withProtocol("UDP")),
			want:   false,
		},
		{
			name:   "udp matches DNS (DNS runs over UDP)",
			filter: "udp",
			pkt:    newPacketInfo(withProtocol("DNS"), withPorts("53", "12345")),
			want:   true,
		},
		{
			name:   "dns query info contains Query",
			filter: "dns",
			pkt: newPacketInfo(
				withProtocol("DNS"),
				withPorts("53", "12345"),
				withInfo("Query: example.com A"),
			),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := Compile(tt.filter)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.filter, err)
			}
			got := fn(tt.pkt)
			if got != tt.want {
				t.Errorf("filter %q protocol=%s = %v, want %v",
					tt.filter, tt.pkt.Protocol, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 10. TestFilter_HTTP
// ---------------------------------------------------------------------------

func TestFilter_HTTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		filter string
		pkt    *capture.PacketInfo
		want   bool
	}{
		{
			name:   "http matches HTTP protocol",
			filter: "http",
			pkt:    newPacketInfo(withProtocol("HTTP"), withPorts("12345", "80")),
			want:   true,
		},
		{
			name:   "http matches HTTPS protocol",
			filter: "http",
			pkt:    newPacketInfo(withProtocol("HTTPS"), withPorts("12345", "443")),
			want:   true,
		},
		{
			name:   "http does not match plain TCP",
			filter: "http",
			pkt:    newPacketInfo(withProtocol("TCP")),
			want:   false,
		},
		{
			name:   "http.request detects GET",
			filter: "http.request",
			pkt: newPacketInfo(
				withProtocol("HTTP"),
				withPorts("12345", "80"),
				withInfo("GET /index.html HTTP/1.1"),
			),
			want: true,
		},
		{
			name:   "http.request detects POST",
			filter: "http.request",
			pkt: newPacketInfo(
				withProtocol("HTTP"),
				withPorts("12345", "80"),
				withInfo("POST /api/data HTTP/1.1"),
			),
			want: true,
		},
		{
			name:   "http.request false for response",
			filter: "http.request",
			pkt: newPacketInfo(
				withProtocol("HTTP"),
				withPorts("80", "12345"),
				withInfo("HTTP/1.1 200 OK"),
			),
			want: false,
		},
		{
			name:   "http.response detects HTTP response",
			filter: "http.response",
			pkt: newPacketInfo(
				withProtocol("HTTP"),
				withPorts("80", "12345"),
				withInfo("HTTP/1.1 200 OK"),
			),
			want: true,
		},
		{
			name:   "http.response false for request",
			filter: "http.response",
			pkt: newPacketInfo(
				withProtocol("HTTP"),
				withPorts("12345", "80"),
				withInfo("GET /index.html HTTP/1.1"),
			),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := Compile(tt.filter)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.filter, err)
			}
			got := fn(tt.pkt)
			if got != tt.want {
				t.Errorf("filter %q protocol=%s info=%q = %v, want %v",
					tt.filter, tt.pkt.Protocol, tt.pkt.Info, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 11. TestFilter_TLS
// ---------------------------------------------------------------------------

func TestFilter_TLS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		filter string
		pkt    *capture.PacketInfo
		want   bool
	}{
		{
			name:   "tls matches TLS protocol",
			filter: "tls",
			pkt:    newPacketInfo(withProtocol("TLS"), withPorts("12345", "443")),
			want:   true,
		},
		{
			name:   "tls does not match plain TCP",
			filter: "tls",
			pkt:    newPacketInfo(withProtocol("TCP")),
			want:   false,
		},
		{
			name:   "tls.handshake detects Client Hello",
			filter: "tls.handshake",
			pkt: newPacketInfo(
				withProtocol("TLS"),
				withPorts("12345", "443"),
				withInfo("Client Hello (SNI: example.com)"),
			),
			want: true,
		},
		{
			name:   "tls.handshake detects Server Hello",
			filter: "tls.handshake",
			pkt: newPacketInfo(
				withProtocol("TLS"),
				withPorts("443", "12345"),
				withInfo("Server Hello"),
			),
			want: true, // "Server Hello" contains "Hello" so handshake is true
		},
		{
			name:   "tls.handshake detects Certificate",
			filter: "tls.handshake",
			pkt: newPacketInfo(
				withProtocol("TLS"),
				withPorts("443", "12345"),
				withInfo("Certificate"),
			),
			want: true,
		},
		{
			name:   "tls.handshake false for Application Data",
			filter: "tls.handshake",
			pkt: newPacketInfo(
				withProtocol("TLS"),
				withPorts("443", "12345"),
				withInfo("Application Data [128 bytes]"),
			),
			want: false,
		},
		{
			name:   "tls.sni matches SNI field",
			filter: `tls.sni == "example.com"`,
			pkt: newPacketInfo(
				withProtocol("TLS"),
				withPorts("12345", "443"),
				withInfo("Client Hello (SNI: example.com)"),
				withSNI("example.com"),
			),
			want: true,
		},
		{
			name:   "tls.sni does not match different SNI",
			filter: `tls.sni == "other.com"`,
			pkt: newPacketInfo(
				withProtocol("TLS"),
				withPorts("12345", "443"),
				withInfo("Client Hello (SNI: example.com)"),
				withSNI("example.com"),
			),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := Compile(tt.filter)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.filter, err)
			}
			got := fn(tt.pkt)
			if got != tt.want {
				t.Errorf("filter %q protocol=%s info=%q sni=%q = %v, want %v",
					tt.filter, tt.pkt.Protocol, tt.pkt.Info, tt.pkt.SNI, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestFilter_FrameLen - frame.len field comparisons
// ---------------------------------------------------------------------------

func TestFilter_FrameLen(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		filter string
		length int
		want   bool
	}{
		{
			name:   "frame.len > 100 true for 200",
			filter: "frame.len > 100",
			length: 200,
			want:   true,
		},
		{
			name:   "frame.len > 100 false for 50",
			filter: "frame.len > 100",
			length: 50,
			want:   false,
		},
		{
			name:   "frame.len == 64 matches",
			filter: "frame.len == 64",
			length: 64,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := Compile(tt.filter)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.filter, err)
			}
			pkt := newPacketInfo(withLength(tt.length))
			got := fn(pkt)
			if got != tt.want {
				t.Errorf("filter %q length=%d = %v, want %v",
					tt.filter, tt.length, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestFilter_LogicalCombinations - compound filters
// ---------------------------------------------------------------------------

func TestFilter_LogicalCombinations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		filter string
		pkt    *capture.PacketInfo
		want   bool
	}{
		{
			name:   "tcp and not dns - TCP packet passes",
			filter: "tcp and not dns",
			pkt:    newPacketInfo(withProtocol("TCP")),
			want:   true,
		},
		{
			name:   "tcp and not dns - DNS packet fails",
			filter: "tcp and not dns",
			pkt:    newPacketInfo(withProtocol("DNS")),
			want:   false,
		},
		{
			name:   "tcp or udp - TCP passes",
			filter: "tcp or udp",
			pkt:    newPacketInfo(withProtocol("TCP")),
			want:   true,
		},
		{
			name:   "tcp or udp - UDP passes",
			filter: "tcp or udp",
			pkt:    newPacketInfo(withProtocol("UDP")),
			want:   true,
		},
		{
			name:   "tcp or udp - ARP fails",
			filter: "tcp or udp",
			pkt:    newPacketInfo(withProtocol("ARP")),
			want:   false,
		},
		{
			name:   "not arp - TCP passes",
			filter: "not arp",
			pkt:    newPacketInfo(withProtocol("TCP")),
			want:   true,
		},
		{
			name:   "not arp - ARP fails",
			filter: "not arp",
			pkt:    newPacketInfo(withProtocol("ARP")),
			want:   false,
		},
		{
			name:   "ip and port filter combined",
			filter: `tcp and ip.src == "192.168.1.1"`,
			pkt: newPacketInfo(
				withProtocol("TCP"),
				withSrcIP("192.168.1.1"),
			),
			want: true,
		},
		{
			name:   "ip and port filter combined - wrong IP",
			filter: `tcp and ip.src == "192.168.1.2"`,
			pkt: newPacketInfo(
				withProtocol("TCP"),
				withSrcIP("192.168.1.1"),
			),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := Compile(tt.filter)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.filter, err)
			}
			got := fn(tt.pkt)
			if got != tt.want {
				t.Errorf("filter %q = %v, want %v", tt.filter, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestPreprocessFilter - verify the preprocessing step directly
// ---------------------------------------------------------------------------

func TestPreprocessFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string // substring that must appear in the output
	}{
		{
			name:  "standalone tcp becomes is_tcp",
			input: "tcp",
			want:  "is_tcp",
		},
		{
			name:  "tcp.port is not replaced",
			input: "tcp.port == 80",
			want:  "tcp.srcport",
		},
		{
			name:  "standalone dns becomes is_dns",
			input: "dns",
			want:  "is_dns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := preprocessFilter(tt.input)
			if !strings.Contains(got, tt.want) {
				t.Errorf("preprocessFilter(%q) = %q, want to contain %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestPacketToEnv - verify environment construction
// ---------------------------------------------------------------------------

func TestPacketToEnv(t *testing.T) {
	t.Parallel()

	pkt := newPacketInfo(
		withProtocol("TCP"),
		withSrcIP("10.0.0.1"),
		withDstIP("10.0.0.2"),
		withPorts("443", "54321"),
		withTCPFlags(0x002|0x010), // SYN+ACK
		withLength(128),
		withStreamKey("10.0.0.1:443-10.0.0.2:54321"),
	)

	env := packetToEnv(pkt)

	if !env.IsTCP {
		t.Error("expected IsTCP to be true")
	}
	if env.IsUDP {
		t.Error("expected IsUDP to be false")
	}
	if env.IP.Src != "10.0.0.1" {
		t.Errorf("IP.Src = %q, want %q", env.IP.Src, "10.0.0.1")
	}
	if env.IP.Dst != "10.0.0.2" {
		t.Errorf("IP.Dst = %q, want %q", env.IP.Dst, "10.0.0.2")
	}
	if env.TCP.SrcPort != 443 {
		t.Errorf("TCP.SrcPort = %d, want 443", env.TCP.SrcPort)
	}
	if env.TCP.DstPort != 54321 {
		t.Errorf("TCP.DstPort = %d, want 54321", env.TCP.DstPort)
	}
	if !env.TCP.Flags.Syn {
		t.Error("expected TCP.Flags.Syn to be true")
	}
	if !env.TCP.Flags.Ack {
		t.Error("expected TCP.Flags.Ack to be true")
	}
	if env.TCP.Flags.Fin {
		t.Error("expected TCP.Flags.Fin to be false")
	}
	if env.Frame.Len != 128 {
		t.Errorf("Frame.Len = %d, want 128", env.Frame.Len)
	}
	if env.TCP.Stream != "10.0.0.1:443-10.0.0.2:54321" {
		t.Errorf("TCP.Stream = %q, want %q", env.TCP.Stream, "10.0.0.1:443-10.0.0.2:54321")
	}
}

// ---------------------------------------------------------------------------
// TestPacketToEnv_ProtocolFlags - protocol flag mapping coverage
// ---------------------------------------------------------------------------

func TestPacketToEnv_ProtocolFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		protocol string
		isTCP    bool
		isUDP    bool
		isDNS    bool
		isHTTP   bool
		isTLS    bool
		isICMP   bool
		isARP    bool
	}{
		{"TCP", true, false, false, false, false, false, false},
		{"HTTP", true, false, false, true, false, false, false},
		{"HTTPS", true, false, false, true, false, false, false},
		{"TLS", true, false, false, false, true, false, false},
		{"UDP", false, true, false, false, false, false, false},
		{"DNS", false, true, true, false, false, false, false},
		{"NBNS", false, true, false, false, false, false, false},
		{"LLMNR", false, true, false, false, false, false, false},
		{"MDNS", false, true, false, false, false, false, false},
		{"SSDP", false, true, false, false, false, false, false},
		{"DHCP", false, true, false, false, false, false, false},
		{"NTP", false, true, false, false, false, false, false},
		{"SNMP", false, true, false, false, false, false, false},
		{"ICMP", false, false, false, false, false, true, false},
		{"ICMPv6", false, false, false, false, false, true, false},
		{"ARP", false, false, false, false, false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			pkt := newPacketInfo(withProtocol(tt.protocol))
			env := packetToEnv(pkt)

			if env.IsTCP != tt.isTCP {
				t.Errorf("IsTCP = %v, want %v", env.IsTCP, tt.isTCP)
			}
			if env.IsUDP != tt.isUDP {
				t.Errorf("IsUDP = %v, want %v", env.IsUDP, tt.isUDP)
			}
			if env.IsDNS != tt.isDNS {
				t.Errorf("IsDNS = %v, want %v", env.IsDNS, tt.isDNS)
			}
			if env.IsHTTP != tt.isHTTP {
				t.Errorf("IsHTTP = %v, want %v", env.IsHTTP, tt.isHTTP)
			}
			if env.IsTLS != tt.isTLS {
				t.Errorf("IsTLS = %v, want %v", env.IsTLS, tt.isTLS)
			}
			if env.IsICMP != tt.isICMP {
				t.Errorf("IsICMP = %v, want %v", env.IsICMP, tt.isICMP)
			}
			if env.IsARP != tt.isARP {
				t.Errorf("IsARP = %v, want %v", env.IsARP, tt.isARP)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 12. BenchmarkCompile
// ---------------------------------------------------------------------------

func BenchmarkCompile(b *testing.B) {
	filters := []struct {
		name string
		expr string
	}{
		{"simple_protocol", "tcp"},
		{"field_comparison", `ip.src == "192.168.1.1"`},
		{"port_filter", "tcp.port == 80"},
		{"logical_compound", `tcp and ip.src == "10.0.0.1" and not dns`},
	}

	for _, f := range filters {
		b.Run(f.name, func(b *testing.B) {
			for b.Loop() {
				_, err := Compile(f.expr)
				if err != nil {
					b.Fatalf("Compile(%q): %v", f.expr, err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 13. BenchmarkFilter_Simple
// ---------------------------------------------------------------------------

func BenchmarkFilter_Simple(b *testing.B) {
	fn, err := Compile("tcp")
	if err != nil {
		b.Fatalf("Compile: %v", err)
	}

	pkt := newPacketInfo(withProtocol("TCP"))

	b.ResetTimer()
	for b.Loop() {
		fn(pkt)
	}
}

// ---------------------------------------------------------------------------
// 14. BenchmarkFilter_Complex
// ---------------------------------------------------------------------------

func BenchmarkFilter_Complex(b *testing.B) {
	fn, err := Compile(`tcp and ip.src == "192.168.1.1" and tcp.port == 80 and not dns`)
	if err != nil {
		b.Fatalf("Compile: %v", err)
	}

	pkt := newPacketInfo(
		withProtocol("TCP"),
		withSrcIP("192.168.1.1"),
		withPorts("12345", "80"),
	)

	b.ResetTimer()
	for b.Loop() {
		fn(pkt)
	}
}
