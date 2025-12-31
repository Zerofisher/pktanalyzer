// Package filter provides display filter functionality using expr-lang/expr
package filter

import (
	"fmt"
	"github.com/Zerofisher/pktanalyzer/capture"
	"strconv"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// PacketEnv is the environment for expression evaluation
// It maps Wireshark-like field names to packet data
type PacketEnv struct {
	// Frame fields
	Frame struct {
		Number    int     `expr:"number"`
		Len       int     `expr:"len"`
		TimeEpoch float64 `expr:"time_epoch"`
		Protocols string  `expr:"protocols"`
		Protocol  string  `expr:"protocol"`
	} `expr:"frame"`

	// Ethernet fields
	Eth struct {
		Src  string `expr:"src"`
		Dst  string `expr:"dst"`
		Type string `expr:"type"`
	} `expr:"eth"`

	// IP fields
	IP struct {
		Src   string `expr:"src"`
		Dst   string `expr:"dst"`
		Proto string `expr:"proto"`
		Addr  string `expr:"addr"` // matches either src or dst
	} `expr:"ip"`

	// TCP fields
	TCP struct {
		SrcPort uint16 `expr:"srcport"`
		DstPort uint16 `expr:"dstport"`
		Port    uint16 `expr:"port"` // matches either src or dst
		Seq     uint32 `expr:"seq"`
		Ack     uint32 `expr:"ack"`
		Flags   struct {
			Syn bool `expr:"syn"`
			Ack bool `expr:"ack"`
			Fin bool `expr:"fin"`
			Rst bool `expr:"rst"`
			Psh bool `expr:"psh"`
		} `expr:"flags"`
		Len    int    `expr:"len"`
		Stream string `expr:"stream"`
	} `expr:"tcp"`

	// UDP fields
	UDP struct {
		SrcPort uint16 `expr:"srcport"`
		DstPort uint16 `expr:"dstport"`
		Port    uint16 `expr:"port"` // matches either src or dst
	} `expr:"udp"`

	// DNS fields
	DNS struct {
		Qry struct {
			Name string `expr:"name"`
			Type string `expr:"type"`
		} `expr:"qry"`
		Flags struct {
			Response bool `expr:"response"`
		} `expr:"flags"`
	} `expr:"dns"`

	// HTTP fields
	HTTP struct {
		Request  bool   `expr:"request"`
		Response bool   `expr:"response"`
		Method   string `expr:"method"`
		URI      string `expr:"uri"`
		Status   int    `expr:"status"`
	} `expr:"http"`

	// TLS fields
	TLS struct {
		Handshake     bool   `expr:"handshake"`
		HandshakeType string `expr:"handshake_type"`
		SNI           string `expr:"sni"`
	} `expr:"tls"`

	// Protocol flags (for simple protocol filtering like "tcp", "udp", "dns")
	IsTCP  bool `expr:"is_tcp"`
	IsUDP  bool `expr:"is_udp"`
	IsDNS  bool `expr:"is_dns"`
	IsHTTP bool `expr:"is_http"`
	IsTLS  bool `expr:"is_tls"`
	IsICMP bool `expr:"is_icmp"`
	IsARP  bool `expr:"is_arp"`
}

// CompiledFilter holds a compiled filter expression
type CompiledFilter struct {
	program *vm.Program
}

// Compile compiles a display filter expression
func Compile(filterStr string) (func(*capture.PacketInfo) bool, error) {
	// Preprocess the filter to handle Wireshark-style syntax
	processed := preprocessFilter(filterStr)

	// Compile the expression
	program, err := expr.Compile(processed, expr.Env(PacketEnv{}), expr.AsBool())
	if err != nil {
		return nil, fmt.Errorf("failed to compile filter '%s': %w", filterStr, err)
	}

	// Return a function that evaluates the filter
	return func(pkt *capture.PacketInfo) bool {
		env := packetToEnv(pkt)
		result, err := expr.Run(program, env)
		if err != nil {
			return false
		}
		if b, ok := result.(bool); ok {
			return b
		}
		return false
	}, nil
}

// preprocessFilter converts Wireshark-style filter syntax to expr syntax
func preprocessFilter(filter string) string {
	// Handle simple protocol names first (must be done before other replacements)
	// Convert standalone "tcp", "udp", "dns" etc. to is_tcp, is_udp, is_dns
	protocolMap := map[string]string{
		"tcp":  "is_tcp",
		"udp":  "is_udp",
		"dns":  "is_dns",
		"http": "is_http",
		"tls":  "is_tls",
		"icmp": "is_icmp",
		"arp":  "is_arp",
	}

	// Replace standalone protocol names (not part of field names like tcp.port)
	words := tokenizeFilter(filter)
	for i, word := range words {
		lowerWord := strings.ToLower(word)
		if replacement, ok := protocolMap[lowerWord]; ok {
			// Check if this is a standalone protocol name (not followed by .)
			if i+1 >= len(words) || words[i+1] != "." {
				// Check if previous word is not a .
				if i == 0 || words[i-1] != "." {
					words[i] = replacement
				}
			}
		}
	}
	filter = strings.Join(words, "")

	// Handle "tcp.port == X" style - check both src and dst
	filter = strings.ReplaceAll(filter, "tcp.port ==", "(tcp.srcport == uint16(")
	filter = strings.ReplaceAll(filter, "udp.port ==", "(udp.srcport == uint16(")

	// Fix the closing for port comparisons
	if strings.Contains(filter, "(tcp.srcport == uint16(") {
		filter = fixPortComparison(filter, "tcp")
	}
	if strings.Contains(filter, "(udp.srcport == uint16(") {
		filter = fixPortComparison(filter, "udp")
	}

	// Handle "in {x, y, z}" syntax - convert to "in [x, y, z]"
	filter = strings.ReplaceAll(filter, "{", "[")
	filter = strings.ReplaceAll(filter, "}", "]")

	return filter
}

// tokenizeFilter breaks a filter string into tokens while preserving structure
func tokenizeFilter(filter string) []string {
	var tokens []string
	var current strings.Builder

	for _, ch := range filter {
		switch ch {
		case ' ', '\t', '\n':
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			tokens = append(tokens, string(ch))
		case '.', '(', ')', '[', ']', '{', '}', ',', '!':
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			tokens = append(tokens, string(ch))
		case '=', '>', '<', '&', '|':
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			current.WriteRune(ch)
		default:
			// Check if current is an operator and we're starting a new token
			if current.Len() > 0 {
				s := current.String()
				if s == "==" || s == "!=" || s == ">=" || s == "<=" || s == ">" || s == "<" ||
					s == "&&" || s == "||" || s == "=" {
					tokens = append(tokens, s)
					current.Reset()
				}
			}
			current.WriteRune(ch)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

func fixPortComparison(filter string, proto string) string {
	// This is a simplified fix - a proper implementation would parse the expression
	// For now, we'll just handle simple cases like "tcp.port == 80"
	prefix := fmt.Sprintf("(%s.srcport == uint16(", proto)
	idx := strings.Index(filter, prefix)
	if idx == -1 {
		return filter
	}

	// Find the value after the prefix
	start := idx + len(prefix)
	end := start
	for end < len(filter) && (filter[end] >= '0' && filter[end] <= '9') {
		end++
	}

	if end > start {
		value := filter[start:end]
		// Replace with proper OR expression
		oldExpr := prefix + value
		newExpr := fmt.Sprintf("(%s.srcport == %s or %s.dstport == %s", proto, value, proto, value)
		filter = strings.Replace(filter, oldExpr, newExpr, 1)
	}

	return filter
}

// packetToEnv converts a PacketInfo to a PacketEnv for expression evaluation
func packetToEnv(pkt *capture.PacketInfo) PacketEnv {
	env := PacketEnv{}

	// Frame fields
	env.Frame.Number = pkt.Number
	env.Frame.Len = pkt.Length
	env.Frame.TimeEpoch = float64(pkt.Timestamp.UnixNano()) / 1e9
	env.Frame.Protocol = pkt.Protocol

	// Build protocols string
	var protocols []string
	for _, layer := range pkt.Layers {
		protocols = append(protocols, strings.ToLower(strings.ReplaceAll(layer.Name, " ", "_")))
	}
	env.Frame.Protocols = strings.Join(protocols, ":")

	// Ethernet fields
	env.Eth.Src = pkt.SrcMAC
	env.Eth.Dst = pkt.DstMAC
	env.Eth.Type = pkt.EtherType

	// IP fields
	env.IP.Src = pkt.SrcIP
	env.IP.Dst = pkt.DstIP
	env.IP.Proto = pkt.Protocol
	env.IP.Addr = pkt.SrcIP // For matching, we'll check both in filter

	// Protocol-specific fields
	switch pkt.Protocol {
	case "TCP", "HTTP", "HTTPS", "TLS":
		env.IsTCP = true
		env.TCP.SrcPort = parsePort16(pkt.SrcPort)
		env.TCP.DstPort = parsePort16(pkt.DstPort)
		env.TCP.Port = env.TCP.SrcPort // Will check both in filter
		env.TCP.Seq = pkt.TCPSeq
		env.TCP.Ack = pkt.TCPAck
		env.TCP.Flags.Syn = pkt.TCPFlags&0x002 != 0
		env.TCP.Flags.Ack = pkt.TCPFlags&0x010 != 0
		env.TCP.Flags.Fin = pkt.TCPFlags&0x001 != 0
		env.TCP.Flags.Rst = pkt.TCPFlags&0x004 != 0
		env.TCP.Flags.Psh = pkt.TCPFlags&0x008 != 0
		env.TCP.Len = len(pkt.TCPPayload)
		env.TCP.Stream = pkt.StreamKey

		if pkt.Protocol == "HTTP" || pkt.Protocol == "HTTPS" {
			env.IsHTTP = true
			env.HTTP.Request = strings.Contains(pkt.Info, "GET ") || strings.Contains(pkt.Info, "POST ") ||
				strings.Contains(pkt.Info, "PUT ") || strings.Contains(pkt.Info, "DELETE ")
			env.HTTP.Response = strings.HasPrefix(pkt.Info, "HTTP/") || strings.Contains(pkt.Info, "[Decrypted] HTTP/")

			// Extract method
			for _, m := range []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"} {
				if strings.Contains(pkt.Info, m+" ") {
					env.HTTP.Method = m
					break
				}
			}

			// Extract URI
			parts := strings.SplitN(pkt.Info, " ", 3)
			if len(parts) >= 2 {
				env.HTTP.URI = parts[1]
			}

			// Extract status code
			if env.HTTP.Response {
				info := strings.TrimPrefix(pkt.Info, "[Decrypted] ")
				parts := strings.SplitN(info, " ", 3)
				if len(parts) >= 2 {
					code, _ := strconv.Atoi(parts[1])
					env.HTTP.Status = code
				}
			}
		}

		if pkt.Protocol == "TLS" {
			env.IsTLS = true
			env.TLS.Handshake = strings.Contains(pkt.Info, "Hello") || strings.Contains(pkt.Info, "Certificate")
			env.TLS.HandshakeType = pkt.Info
			env.TLS.SNI = pkt.SNI
		}

	case "UDP", "DNS", "NBNS", "LLMNR", "MDNS", "SSDP", "DHCP", "NTP", "SNMP":
		env.IsUDP = true
		env.UDP.SrcPort = parsePort16(pkt.SrcPort)
		env.UDP.DstPort = parsePort16(pkt.DstPort)
		env.UDP.Port = env.UDP.SrcPort

		if pkt.Protocol == "DNS" {
			env.IsDNS = true
			env.DNS.Flags.Response = strings.HasPrefix(pkt.Info, "Response")

			// Extract query name and type
			if strings.HasPrefix(pkt.Info, "Query: ") {
				parts := strings.SplitN(pkt.Info[7:], " ", 2)
				if len(parts) > 0 {
					env.DNS.Qry.Name = parts[0]
				}
				if len(parts) > 1 {
					env.DNS.Qry.Type = parts[1]
				}
			}
		}

	case "ICMP", "ICMPv6":
		env.IsICMP = true

	case "ARP":
		env.IsARP = true
	}

	return env
}

func parsePort16(s string) uint16 {
	v, _ := strconv.ParseUint(s, 10, 16)
	return uint16(v)
}
