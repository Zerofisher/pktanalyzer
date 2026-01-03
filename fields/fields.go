// Package fields provides protocol field definitions and extraction
package fields

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Zerofisher/pktanalyzer/capture"
)

// FieldType represents the type of a field
type FieldType int

const (
	TypeString FieldType = iota
	TypeInt
	TypeUint16
	TypeUint32
	TypeBool
	TypeBytes
	TypeFloat
	TypeTime
)

// FieldDef defines a protocol field
type FieldDef struct {
	Name        string                        // Field name (e.g., "tcp.port")
	Description string                        // Human-readable description
	Type        FieldType                     // Value type
	Extractor   func(*capture.PacketInfo) any // Field value extractor
}

// Registry holds all registered fields
type Registry struct {
	fields map[string]*FieldDef
}

// NewRegistry creates a new field registry with standard fields
func NewRegistry() *Registry {
	r := &Registry{
		fields: make(map[string]*FieldDef),
	}
	r.registerStandardFields()
	return r
}

// Get returns a field definition by name
func (r *Registry) Get(name string) *FieldDef {
	return r.fields[name]
}

// List returns all registered field names
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.fields))
	for name := range r.fields {
		names = append(names, name)
	}
	return names
}

// ListByPrefix returns field names matching a prefix
func (r *Registry) ListByPrefix(prefix string) []string {
	var names []string
	for name := range r.fields {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names
}

// Extract extracts a field value from a packet
func (r *Registry) Extract(name string, pkt *capture.PacketInfo) (any, bool) {
	field := r.fields[name]
	if field == nil {
		return nil, false
	}
	value := field.Extractor(pkt)
	return value, value != nil
}

// ExtractString extracts a field value as string
func (r *Registry) ExtractString(name string, pkt *capture.PacketInfo) string {
	value, ok := r.Extract(name, pkt)
	if !ok || value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case uint16:
		return strconv.FormatUint(uint64(v), 10)
	case uint32:
		return strconv.FormatUint(uint64(v), 10)
	case bool:
		if v {
			return "1"
		}
		return "0"
	case []byte:
		return fmt.Sprintf("%x", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// Register adds a new field to the registry
func (r *Registry) Register(field *FieldDef) {
	r.fields[field.Name] = field
}

// registerStandardFields registers all standard protocol fields
func (r *Registry) registerStandardFields() {
	// Frame fields
	r.Register(&FieldDef{
		Name:        "frame.number",
		Description: "Frame number",
		Type:        TypeInt,
		Extractor:   func(p *capture.PacketInfo) any { return p.Number },
	})
	r.Register(&FieldDef{
		Name:        "frame.time",
		Description: "Frame timestamp",
		Type:        TypeTime,
		Extractor:   func(p *capture.PacketInfo) any { return p.Timestamp },
	})
	r.Register(&FieldDef{
		Name:        "frame.time_epoch",
		Description: "Frame timestamp (Unix epoch)",
		Type:        TypeFloat,
		Extractor:   func(p *capture.PacketInfo) any { return float64(p.Timestamp.UnixNano()) / 1e9 },
	})
	r.Register(&FieldDef{
		Name:        "frame.len",
		Description: "Frame length",
		Type:        TypeInt,
		Extractor:   func(p *capture.PacketInfo) any { return p.Length },
	})
	r.Register(&FieldDef{
		Name:        "frame.protocols",
		Description: "Protocols in frame",
		Type:        TypeString,
		Extractor: func(p *capture.PacketInfo) any {
			var protos []string
			for _, layer := range p.Layers {
				protos = append(protos, strings.ToLower(strings.ReplaceAll(layer.Name, " ", "_")))
			}
			return strings.Join(protos, ":")
		},
	})

	// Ethernet fields
	r.Register(&FieldDef{
		Name:        "eth.src",
		Description: "Source MAC address",
		Type:        TypeString,
		Extractor:   func(p *capture.PacketInfo) any { return p.SrcMAC },
	})
	r.Register(&FieldDef{
		Name:        "eth.dst",
		Description: "Destination MAC address",
		Type:        TypeString,
		Extractor:   func(p *capture.PacketInfo) any { return p.DstMAC },
	})
	r.Register(&FieldDef{
		Name:        "eth.type",
		Description: "Ethernet type",
		Type:        TypeString,
		Extractor:   func(p *capture.PacketInfo) any { return p.EtherType },
	})

	// IP fields
	r.Register(&FieldDef{
		Name:        "ip.src",
		Description: "Source IP address",
		Type:        TypeString,
		Extractor:   func(p *capture.PacketInfo) any { return p.SrcIP },
	})
	r.Register(&FieldDef{
		Name:        "ip.dst",
		Description: "Destination IP address",
		Type:        TypeString,
		Extractor:   func(p *capture.PacketInfo) any { return p.DstIP },
	})
	r.Register(&FieldDef{
		Name:        "ip.proto",
		Description: "IP protocol",
		Type:        TypeString,
		Extractor:   func(p *capture.PacketInfo) any { return p.Protocol },
	})
	r.Register(&FieldDef{
		Name:        "ip.addr",
		Description: "Source or destination IP address",
		Type:        TypeString,
		Extractor: func(p *capture.PacketInfo) any {
			// Returns both addresses for filtering purposes
			return p.SrcIP + "," + p.DstIP
		},
	})

	// TCP fields
	r.Register(&FieldDef{
		Name:        "tcp.srcport",
		Description: "TCP source port",
		Type:        TypeUint16,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol != "TCP" && !strings.HasPrefix(p.Protocol, "HTTP") && p.Protocol != "TLS" {
				return nil
			}
			port, _ := strconv.ParseUint(p.SrcPort, 10, 16)
			return uint16(port)
		},
	})
	r.Register(&FieldDef{
		Name:        "tcp.dstport",
		Description: "TCP destination port",
		Type:        TypeUint16,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol != "TCP" && !strings.HasPrefix(p.Protocol, "HTTP") && p.Protocol != "TLS" {
				return nil
			}
			port, _ := strconv.ParseUint(p.DstPort, 10, 16)
			return uint16(port)
		},
	})
	r.Register(&FieldDef{
		Name:        "tcp.port",
		Description: "TCP source or destination port",
		Type:        TypeString,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol != "TCP" && !strings.HasPrefix(p.Protocol, "HTTP") && p.Protocol != "TLS" {
				return nil
			}
			return p.SrcPort + "," + p.DstPort
		},
	})
	r.Register(&FieldDef{
		Name:        "tcp.seq",
		Description: "TCP sequence number",
		Type:        TypeUint32,
		Extractor: func(p *capture.PacketInfo) any {
			if p.TCPSeq == 0 && p.Protocol != "TCP" {
				return nil
			}
			return p.TCPSeq
		},
	})
	r.Register(&FieldDef{
		Name:        "tcp.ack",
		Description: "TCP acknowledgment number",
		Type:        TypeUint32,
		Extractor: func(p *capture.PacketInfo) any {
			if p.TCPAck == 0 && p.Protocol != "TCP" {
				return nil
			}
			return p.TCPAck
		},
	})
	r.Register(&FieldDef{
		Name:        "tcp.flags",
		Description: "TCP flags",
		Type:        TypeUint16,
		Extractor:   func(p *capture.PacketInfo) any { return p.TCPFlags },
	})
	r.Register(&FieldDef{
		Name:        "tcp.flags.syn",
		Description: "TCP SYN flag",
		Type:        TypeBool,
		Extractor:   func(p *capture.PacketInfo) any { return p.TCPFlags&0x002 != 0 },
	})
	r.Register(&FieldDef{
		Name:        "tcp.flags.ack",
		Description: "TCP ACK flag",
		Type:        TypeBool,
		Extractor:   func(p *capture.PacketInfo) any { return p.TCPFlags&0x010 != 0 },
	})
	r.Register(&FieldDef{
		Name:        "tcp.flags.fin",
		Description: "TCP FIN flag",
		Type:        TypeBool,
		Extractor:   func(p *capture.PacketInfo) any { return p.TCPFlags&0x001 != 0 },
	})
	r.Register(&FieldDef{
		Name:        "tcp.flags.rst",
		Description: "TCP RST flag",
		Type:        TypeBool,
		Extractor:   func(p *capture.PacketInfo) any { return p.TCPFlags&0x004 != 0 },
	})
	r.Register(&FieldDef{
		Name:        "tcp.flags.psh",
		Description: "TCP PSH flag",
		Type:        TypeBool,
		Extractor:   func(p *capture.PacketInfo) any { return p.TCPFlags&0x008 != 0 },
	})
	r.Register(&FieldDef{
		Name:        "tcp.len",
		Description: "TCP payload length",
		Type:        TypeInt,
		Extractor:   func(p *capture.PacketInfo) any { return len(p.TCPPayload) },
	})
	r.Register(&FieldDef{
		Name:        "tcp.stream",
		Description: "TCP stream index",
		Type:        TypeString,
		Extractor:   func(p *capture.PacketInfo) any { return p.StreamKey },
	})

	// UDP fields
	r.Register(&FieldDef{
		Name:        "udp.srcport",
		Description: "UDP source port",
		Type:        TypeUint16,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol == "UDP" || p.Protocol == "DNS" || p.Protocol == "NBNS" ||
				p.Protocol == "LLMNR" || p.Protocol == "MDNS" || p.Protocol == "SSDP" ||
				p.Protocol == "DHCP" || p.Protocol == "NTP" || p.Protocol == "SNMP" {
				port, _ := strconv.ParseUint(p.SrcPort, 10, 16)
				return uint16(port)
			}
			return nil
		},
	})
	r.Register(&FieldDef{
		Name:        "udp.dstport",
		Description: "UDP destination port",
		Type:        TypeUint16,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol == "UDP" || p.Protocol == "DNS" || p.Protocol == "NBNS" ||
				p.Protocol == "LLMNR" || p.Protocol == "MDNS" || p.Protocol == "SSDP" ||
				p.Protocol == "DHCP" || p.Protocol == "NTP" || p.Protocol == "SNMP" {
				port, _ := strconv.ParseUint(p.DstPort, 10, 16)
				return uint16(port)
			}
			return nil
		},
	})
	r.Register(&FieldDef{
		Name:        "udp.port",
		Description: "UDP source or destination port",
		Type:        TypeString,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol == "UDP" || p.Protocol == "DNS" || p.Protocol == "NBNS" ||
				p.Protocol == "LLMNR" || p.Protocol == "MDNS" || p.Protocol == "SSDP" ||
				p.Protocol == "DHCP" || p.Protocol == "NTP" || p.Protocol == "SNMP" {
				return p.SrcPort + "," + p.DstPort
			}
			return nil
		},
	})

	// DNS fields
	r.Register(&FieldDef{
		Name:        "dns.qry.name",
		Description: "DNS query name",
		Type:        TypeString,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol != "DNS" {
				return nil
			}
			// Extract from Info field: "Query: example.com A"
			if strings.HasPrefix(p.Info, "Query: ") {
				parts := strings.SplitN(p.Info[7:], " ", 2)
				if len(parts) > 0 {
					return parts[0]
				}
			}
			return nil
		},
	})
	r.Register(&FieldDef{
		Name:        "dns.qry.type",
		Description: "DNS query type",
		Type:        TypeString,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol != "DNS" {
				return nil
			}
			// Extract from Info field: "Query: example.com A"
			if strings.HasPrefix(p.Info, "Query: ") {
				parts := strings.SplitN(p.Info[7:], " ", 2)
				if len(parts) > 1 {
					return parts[1]
				}
			}
			return nil
		},
	})
	r.Register(&FieldDef{
		Name:        "dns.flags.response",
		Description: "DNS response flag",
		Type:        TypeBool,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol != "DNS" {
				return nil
			}
			return strings.HasPrefix(p.Info, "Response")
		},
	})

	// HTTP fields
	r.Register(&FieldDef{
		Name:        "http.request",
		Description: "HTTP request",
		Type:        TypeBool,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol != "HTTP" && p.Protocol != "HTTPS" {
				return nil
			}
			return strings.Contains(p.Info, "GET ") || strings.Contains(p.Info, "POST ") ||
				strings.Contains(p.Info, "PUT ") || strings.Contains(p.Info, "DELETE ") ||
				strings.Contains(p.Info, "HEAD ") || strings.Contains(p.Info, "OPTIONS ")
		},
	})
	r.Register(&FieldDef{
		Name:        "http.response",
		Description: "HTTP response",
		Type:        TypeBool,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol != "HTTP" && p.Protocol != "HTTPS" {
				return nil
			}
			return strings.HasPrefix(p.Info, "HTTP/") || strings.Contains(p.Info, "HTTP/1.")
		},
	})
	r.Register(&FieldDef{
		Name:        "http.request.method",
		Description: "HTTP request method",
		Type:        TypeString,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol != "HTTP" && p.Protocol != "HTTPS" {
				return nil
			}
			methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
			for _, m := range methods {
				if strings.Contains(p.Info, m+" ") {
					return m
				}
			}
			return nil
		},
	})
	r.Register(&FieldDef{
		Name:        "http.request.uri",
		Description: "HTTP request URI",
		Type:        TypeString,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol != "HTTP" && p.Protocol != "HTTPS" {
				return nil
			}
			// Parse from Info: "GET /path HTTP/1.1"
			parts := strings.SplitN(p.Info, " ", 3)
			if len(parts) >= 2 {
				return parts[1]
			}
			return nil
		},
	})
	r.Register(&FieldDef{
		Name:        "http.response.code",
		Description: "HTTP response status code",
		Type:        TypeInt,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol != "HTTP" && p.Protocol != "HTTPS" {
				return nil
			}
			// Parse from Info: "HTTP/1.1 200 OK"
			if strings.HasPrefix(p.Info, "HTTP/") || strings.Contains(p.Info, "[Decrypted] HTTP/") {
				info := strings.TrimPrefix(p.Info, "[Decrypted] ")
				parts := strings.SplitN(info, " ", 3)
				if len(parts) >= 2 {
					code, err := strconv.Atoi(parts[1])
					if err == nil {
						return code
					}
				}
			}
			return nil
		},
	})

	// TLS fields
	r.Register(&FieldDef{
		Name:        "tls.handshake",
		Description: "TLS handshake message",
		Type:        TypeBool,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol != "TLS" {
				return nil
			}
			return strings.Contains(p.Info, "Hello") || strings.Contains(p.Info, "Certificate") ||
				strings.Contains(p.Info, "Key Exchange") || strings.Contains(p.Info, "Finished")
		},
	})
	r.Register(&FieldDef{
		Name:        "tls.handshake.type",
		Description: "TLS handshake type",
		Type:        TypeString,
		Extractor: func(p *capture.PacketInfo) any {
			if p.Protocol != "TLS" {
				return nil
			}
			return p.Info
		},
	})
	r.Register(&FieldDef{
		Name:        "tls.sni",
		Description: "TLS Server Name Indication",
		Type:        TypeString,
		Extractor: func(p *capture.PacketInfo) any {
			if p.SNI == "" {
				return nil
			}
			return p.SNI
		},
	})

	// Protocol field (matches any protocol name)
	r.Register(&FieldDef{
		Name:        "frame.protocol",
		Description: "Highest layer protocol",
		Type:        TypeString,
		Extractor:   func(p *capture.PacketInfo) any { return p.Protocol },
	})
}

// GetFieldInfo returns a formatted string describing a field
func (r *Registry) GetFieldInfo(name string) string {
	field := r.fields[name]
	if field == nil {
		return ""
	}
	return fmt.Sprintf("%s\t%s\t%s", field.Name, getTypeName(field.Type), field.Description)
}

func getTypeName(t FieldType) string {
	switch t {
	case TypeString:
		return "string"
	case TypeInt:
		return "int"
	case TypeUint16:
		return "uint16"
	case TypeUint32:
		return "uint32"
	case TypeBool:
		return "bool"
	case TypeBytes:
		return "bytes"
	case TypeFloat:
		return "float"
	case TypeTime:
		return "time"
	default:
		return "unknown"
	}
}
