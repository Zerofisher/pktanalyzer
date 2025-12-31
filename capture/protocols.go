package capture

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// Well-known port names
var portNames = map[uint16]string{
	20:    "ftp-data",
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "domain",
	67:    "bootps",
	68:    "bootpc",
	69:    "tftp",
	80:    "http",
	110:   "pop3",
	123:   "ntp",
	137:   "netbios-ns",
	138:   "netbios-dgm",
	139:   "netbios-ssn",
	143:   "imap",
	161:   "snmp",
	162:   "snmptrap",
	389:   "ldap",
	427:   "svrloc",
	443:   "https",
	445:   "microsoft-ds",
	465:   "smtps",
	500:   "isakmp",
	514:   "syslog",
	515:   "printer",
	520:   "rip",
	546:   "dhcpv6-client",
	547:   "dhcpv6-server",
	554:   "rtsp",
	587:   "submission",
	636:   "ldaps",
	993:   "imaps",
	995:   "pop3s",
	1080:  "socks",
	1194:  "openvpn",
	1433:  "ms-sql-s",
	1434:  "ms-sql-m",
	1521:  "oracle",
	1701:  "l2tp",
	1723:  "pptp",
	1812:  "radius",
	1813:  "radius-acct",
	1900:  "ssdp",
	2049:  "nfs",
	3268:  "msft-gc",
	3269:  "msft-gc-ssl",
	3306:  "mysql",
	3389:  "ms-wbt-server",
	3702:  "ws-discovery",
	4500:  "ipsec-nat-t",
	5060:  "sip",
	5061:  "sips",
	5222:  "xmpp-client",
	5223:  "xmpp-client-ssl",
	5269:  "xmpp-server",
	5353:  "mdns",
	5355:  "llmnr",
	5432:  "postgresql",
	5900:  "vnc",
	6379:  "redis",
	8080:  "http-proxy",
	8443:  "https-alt",
	9000:  "cslistener",
	27017: "mongodb",
}

// GetPortName returns a human-readable port name
func GetPortName(port uint16) string {
	if name, ok := portNames[port]; ok {
		return name
	}
	return ""
}

// FormatPort returns port with optional name
func FormatPort(port string) string {
	var p uint16
	fmt.Sscanf(port, "%d", &p)
	if name := GetPortName(p); name != "" {
		return fmt.Sprintf("%s(%s)", port, name)
	}
	return port
}

// NBNS (NetBIOS Name Service) parser - Port 137
type NBNSMessage struct {
	TransactionID uint16
	Flags         uint16
	Questions     uint16
	AnswerRRs     uint16
	AuthorityRRs  uint16
	AdditionalRRs uint16
	Names         []string
	QueryType     string
}

func ParseNBNS(data []byte) (*NBNSMessage, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("NBNS packet too short")
	}

	msg := &NBNSMessage{
		TransactionID: binary.BigEndian.Uint16(data[0:2]),
		Flags:         binary.BigEndian.Uint16(data[2:4]),
		Questions:     binary.BigEndian.Uint16(data[4:6]),
		AnswerRRs:     binary.BigEndian.Uint16(data[6:8]),
		AuthorityRRs:  binary.BigEndian.Uint16(data[8:10]),
		AdditionalRRs: binary.BigEndian.Uint16(data[10:12]),
	}

	// Decode NetBIOS name
	offset := 12
	if len(data) > offset+1 {
		nameLen := int(data[offset])
		if nameLen > 0 && len(data) > offset+1+nameLen {
			encodedName := data[offset+1 : offset+1+nameLen]
			msg.Names = append(msg.Names, decodeNetBIOSName(encodedName))
			offset += 1 + nameLen + 1 // length + name + null terminator
		}
	}

	// Determine query type
	if len(data) > offset+2 {
		qtype := binary.BigEndian.Uint16(data[offset : offset+2])
		switch qtype {
		case 0x0020:
			msg.QueryType = "NB"
		case 0x0021:
			msg.QueryType = "NBSTAT"
		default:
			msg.QueryType = fmt.Sprintf("0x%04x", qtype)
		}
	}

	return msg, nil
}

func decodeNetBIOSName(encoded []byte) string {
	if len(encoded) < 32 {
		return string(encoded)
	}

	// NetBIOS name encoding: each byte becomes two bytes (A-P encoding)
	var decoded bytes.Buffer
	for i := 0; i < 32 && i < len(encoded); i += 2 {
		if i+1 >= len(encoded) {
			break
		}
		high := encoded[i] - 'A'
		low := encoded[i+1] - 'A'
		ch := (high << 4) | low
		if ch >= 0x20 && ch < 0x7F {
			decoded.WriteByte(ch)
		}
	}
	return strings.TrimRight(decoded.String(), " ")
}

func (m *NBNSMessage) IsQuery() bool {
	return (m.Flags & 0x8000) == 0
}

func (m *NBNSMessage) GetInfo() string {
	nameStr := ""
	if len(m.Names) > 0 {
		nameStr = m.Names[0]
	}

	if m.IsQuery() {
		return fmt.Sprintf("Name query %s %s<%02x>", m.QueryType, nameStr, 0)
	}
	return fmt.Sprintf("Name response %s %s", m.QueryType, nameStr)
}

// LLMNR (Link-Local Multicast Name Resolution) parser - Port 5355
type LLMNRMessage struct {
	TransactionID uint16
	Flags         uint16
	Questions     uint16
	AnswerRRs     uint16
	AuthorityRRs  uint16
	AdditionalRRs uint16
	QueryName     string
	QueryType     uint16
	QueryClass    uint16
}

func ParseLLMNR(data []byte) (*LLMNRMessage, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("LLMNR packet too short")
	}

	msg := &LLMNRMessage{
		TransactionID: binary.BigEndian.Uint16(data[0:2]),
		Flags:         binary.BigEndian.Uint16(data[2:4]),
		Questions:     binary.BigEndian.Uint16(data[4:6]),
		AnswerRRs:     binary.BigEndian.Uint16(data[6:8]),
		AuthorityRRs:  binary.BigEndian.Uint16(data[8:10]),
		AdditionalRRs: binary.BigEndian.Uint16(data[10:12]),
	}

	// Parse query name (DNS-style encoding)
	offset := 12
	name, newOffset := parseDNSName(data, offset)
	msg.QueryName = name
	offset = newOffset

	if len(data) >= offset+4 {
		msg.QueryType = binary.BigEndian.Uint16(data[offset : offset+2])
		msg.QueryClass = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	}

	return msg, nil
}

func (m *LLMNRMessage) IsQuery() bool {
	return (m.Flags & 0x8000) == 0
}

func (m *LLMNRMessage) GetInfo() string {
	typeStr := getDNSTypeName(m.QueryType)
	if m.IsQuery() {
		return fmt.Sprintf("Standard query %s %s", typeStr, m.QueryName)
	}
	return fmt.Sprintf("Standard query response %s %s", typeStr, m.QueryName)
}

// mDNS (Multicast DNS) parser - Port 5353
type MDNSMessage struct {
	TransactionID uint16
	Flags         uint16
	Questions     uint16
	AnswerRRs     uint16
	AuthorityRRs  uint16
	AdditionalRRs uint16
	Queries       []MDNSQuery
	Answers       []MDNSAnswer
}

type MDNSQuery struct {
	Name  string
	Type  uint16
	Class uint16
}

type MDNSAnswer struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string
}

func ParseMDNS(data []byte) (*MDNSMessage, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("mDNS packet too short")
	}

	msg := &MDNSMessage{
		TransactionID: binary.BigEndian.Uint16(data[0:2]),
		Flags:         binary.BigEndian.Uint16(data[2:4]),
		Questions:     binary.BigEndian.Uint16(data[4:6]),
		AnswerRRs:     binary.BigEndian.Uint16(data[6:8]),
		AuthorityRRs:  binary.BigEndian.Uint16(data[8:10]),
		AdditionalRRs: binary.BigEndian.Uint16(data[10:12]),
	}

	offset := 12

	// Parse questions
	for i := 0; i < int(msg.Questions) && offset < len(data); i++ {
		name, newOffset := parseDNSName(data, offset)
		offset = newOffset
		if len(data) >= offset+4 {
			query := MDNSQuery{
				Name:  name,
				Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
				Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
			}
			msg.Queries = append(msg.Queries, query)
			offset += 4
		}
	}

	// Parse answers (simplified)
	for i := 0; i < int(msg.AnswerRRs) && offset < len(data); i++ {
		name, newOffset := parseDNSName(data, offset)
		offset = newOffset
		if len(data) >= offset+10 {
			answer := MDNSAnswer{
				Name:  name,
				Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
				Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
				TTL:   binary.BigEndian.Uint32(data[offset+4 : offset+8]),
			}
			rdlen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
			offset += 10

			if len(data) >= offset+int(rdlen) {
				answer.Data = parseMDNSRData(data, offset, int(rdlen), answer.Type)
				offset += int(rdlen)
			}
			msg.Answers = append(msg.Answers, answer)
		}
	}

	return msg, nil
}

func parseMDNSRData(data []byte, offset, length int, qtype uint16) string {
	if offset+length > len(data) {
		return ""
	}

	rdata := data[offset : offset+length]

	switch qtype {
	case 1: // A record
		if len(rdata) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3])
		}
	case 28: // AAAA record
		if len(rdata) == 16 {
			return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
				binary.BigEndian.Uint16(rdata[0:2]),
				binary.BigEndian.Uint16(rdata[2:4]),
				binary.BigEndian.Uint16(rdata[4:6]),
				binary.BigEndian.Uint16(rdata[6:8]),
				binary.BigEndian.Uint16(rdata[8:10]),
				binary.BigEndian.Uint16(rdata[10:12]),
				binary.BigEndian.Uint16(rdata[12:14]),
				binary.BigEndian.Uint16(rdata[14:16]))
		}
	case 12: // PTR record
		name, _ := parseDNSName(data, offset)
		return name
	case 16: // TXT record
		return string(rdata)
	case 33: // SRV record
		if len(rdata) >= 6 {
			name, _ := parseDNSName(data, offset+6)
			return fmt.Sprintf("priority=%d weight=%d port=%d target=%s",
				binary.BigEndian.Uint16(rdata[0:2]),
				binary.BigEndian.Uint16(rdata[2:4]),
				binary.BigEndian.Uint16(rdata[4:6]),
				name)
		}
	}

	return fmt.Sprintf("[%d bytes]", len(rdata))
}

func (m *MDNSMessage) IsQuery() bool {
	return (m.Flags & 0x8000) == 0
}

func (m *MDNSMessage) GetInfo() string {
	if m.IsQuery() {
		if len(m.Queries) > 0 {
			return fmt.Sprintf("Standard query %s %s", getDNSTypeName(m.Queries[0].Type), m.Queries[0].Name)
		}
		return "Standard query"
	}

	if len(m.Answers) > 0 {
		return fmt.Sprintf("Standard query response %s %s %s",
			getDNSTypeName(m.Answers[0].Type), m.Answers[0].Name, m.Answers[0].Data)
	}
	return "Standard query response"
}

// SSDP (Simple Service Discovery Protocol) parser - Port 1900
type SSDPMessage struct {
	Method      string
	URI         string
	HTTPVersion string
	Headers     map[string]string
	IsResponse  bool
	StatusCode  int
	StatusText  string
}

func ParseSSDP(data []byte) (*SSDPMessage, error) {
	lines := strings.Split(string(data), "\r\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("empty SSDP message")
	}

	msg := &SSDPMessage{
		Headers: make(map[string]string),
	}

	// Parse first line
	firstLine := lines[0]
	if strings.HasPrefix(firstLine, "HTTP/") {
		// Response
		msg.IsResponse = true
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 2 {
			msg.HTTPVersion = parts[0]
			fmt.Sscanf(parts[1], "%d", &msg.StatusCode)
			if len(parts) >= 3 {
				msg.StatusText = parts[2]
			}
		}
	} else {
		// Request
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 3 {
			msg.Method = parts[0]
			msg.URI = parts[1]
			msg.HTTPVersion = parts[2]
		}
	}

	// Parse headers
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			msg.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return msg, nil
}

func (m *SSDPMessage) GetInfo() string {
	if m.IsResponse {
		return fmt.Sprintf("%s %d %s", m.HTTPVersion, m.StatusCode, m.StatusText)
	}
	return fmt.Sprintf("%s * %s", m.Method, m.HTTPVersion)
}

// SRVLOC (Service Location Protocol) parser - Port 427
type SRVLOCMessage struct {
	Version     uint8
	Function    uint8
	Length      uint16
	Flags       uint16
	ExtOffset   uint32
	XID         uint16
	LangTagLen  uint16
	LangTag     string
	ServiceType string
}

var srvlocFunctions = map[uint8]string{
	1:  "Service Request",
	2:  "Service Reply",
	3:  "Service Registration",
	4:  "Service Deregister",
	5:  "Service Acknowledge",
	6:  "Attribute Request",
	7:  "Attribute Reply",
	8:  "DA Advertisement",
	9:  "Service Type Request",
	10: "Service Type Reply",
	11: "SA Advertisement",
}

func ParseSRVLOC(data []byte) (*SRVLOCMessage, error) {
	if len(data) < 14 {
		return nil, fmt.Errorf("SRVLOC packet too short")
	}

	msg := &SRVLOCMessage{
		Version:  data[0],
		Function: data[1],
		Length:   binary.BigEndian.Uint16(data[2:4]),
	}

	if msg.Version == 2 && len(data) >= 16 {
		// SLPv2
		msg.Flags = binary.BigEndian.Uint16(data[5:7])
		msg.ExtOffset = uint32(data[7])<<16 | uint32(data[8])<<8 | uint32(data[9])
		msg.XID = binary.BigEndian.Uint16(data[10:12])
		msg.LangTagLen = binary.BigEndian.Uint16(data[12:14])
		if len(data) >= 14+int(msg.LangTagLen) {
			msg.LangTag = string(data[14 : 14+msg.LangTagLen])
		}
	} else if msg.Version == 1 && len(data) >= 12 {
		// SLPv1
		msg.Flags = binary.BigEndian.Uint16(data[4:6])
		msg.XID = binary.BigEndian.Uint16(data[10:12])
	}

	return msg, nil
}

func (m *SRVLOCMessage) GetInfo() string {
	funcName := "Unknown"
	if name, ok := srvlocFunctions[m.Function]; ok {
		funcName = name
	}
	return fmt.Sprintf("%s, V%d Transaction ID = %d", funcName, m.Version, m.XID)
}

// WS-Discovery parser - Port 3702
type WSDiscoveryMessage struct {
	Action      string
	MessageID   string
	To          string
	Types       string
	IsProbe     bool
	IsProbeMatch bool
}

func ParseWSDiscovery(data []byte) (*WSDiscoveryMessage, error) {
	content := string(data)
	msg := &WSDiscoveryMessage{}

	// Simple XML parsing for key elements
	if strings.Contains(content, "Probe>") {
		msg.IsProbe = true
		msg.Action = "Probe"
	} else if strings.Contains(content, "ProbeMatches>") {
		msg.IsProbeMatch = true
		msg.Action = "ProbeMatches"
	} else if strings.Contains(content, "Hello>") {
		msg.Action = "Hello"
	} else if strings.Contains(content, "Bye>") {
		msg.Action = "Bye"
	} else if strings.Contains(content, "Resolve>") {
		msg.Action = "Resolve"
	} else if strings.Contains(content, "ResolveMatches>") {
		msg.Action = "ResolveMatches"
	}

	// Extract types if present
	if idx := strings.Index(content, "<d:Types>"); idx != -1 {
		end := strings.Index(content[idx:], "</d:Types>")
		if end != -1 {
			msg.Types = content[idx+9 : idx+end]
		}
	}

	return msg, nil
}

func (m *WSDiscoveryMessage) GetInfo() string {
	if m.Action != "" {
		if m.Types != "" {
			return fmt.Sprintf("%s (%s)", m.Action, m.Types)
		}
		return m.Action
	}
	return "WS-Discovery"
}

// Helper functions
func parseDNSName(data []byte, offset int) (string, int) {
	var parts []string
	jumped := false
	jumpOffset := 0

	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}

		// Check for compression pointer
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				break
			}
			pointer := int(length&0x3F)<<8 | int(data[offset+1])
			if !jumped {
				jumpOffset = offset + 2
			}
			jumped = true
			offset = pointer
			continue
		}

		offset++
		if offset+length > len(data) {
			break
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}

	if jumped {
		offset = jumpOffset
	}

	return strings.Join(parts, "."), offset
}

func getDNSTypeName(t uint16) string {
	types := map[uint16]string{
		1:   "A",
		2:   "NS",
		5:   "CNAME",
		6:   "SOA",
		12:  "PTR",
		15:  "MX",
		16:  "TXT",
		28:  "AAAA",
		33:  "SRV",
		35:  "NAPTR",
		41:  "OPT",
		43:  "DS",
		46:  "RRSIG",
		47:  "NSEC",
		48:  "DNSKEY",
		50:  "NSEC3",
		51:  "NSEC3PARAM",
		52:  "TLSA",
		99:  "SPF",
		252: "AXFR",
		255: "ANY",
		256: "URI",
		257: "CAA",
	}
	if name, ok := types[t]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", t)
}

// IGMPv3 parser
type IGMPMessage struct {
	Type            uint8
	MaxRespTime     uint8
	Checksum        uint16
	GroupAddress    string
	NumSources      uint16
	SourceAddresses []string
}

func ParseIGMP(data []byte) (*IGMPMessage, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("IGMP packet too short")
	}

	msg := &IGMPMessage{
		Type:        data[0],
		MaxRespTime: data[1],
		Checksum:    binary.BigEndian.Uint16(data[2:4]),
	}

	if len(data) >= 8 {
		msg.GroupAddress = fmt.Sprintf("%d.%d.%d.%d", data[4], data[5], data[6], data[7])
	}

	return msg, nil
}

func (m *IGMPMessage) GetInfo() string {
	switch m.Type {
	case 0x11:
		if m.GroupAddress == "0.0.0.0" {
			return "Membership Query, general"
		}
		return fmt.Sprintf("Membership Query, group %s", m.GroupAddress)
	case 0x12:
		return fmt.Sprintf("Membership Report V1, group %s", m.GroupAddress)
	case 0x16:
		return fmt.Sprintf("Membership Report V2, group %s", m.GroupAddress)
	case 0x17:
		return fmt.Sprintf("Leave Group, group %s", m.GroupAddress)
	case 0x22:
		return "Membership Report V3"
	default:
		return fmt.Sprintf("Unknown IGMP type %d", m.Type)
	}
}

// DHCP/BOOTP parser
type DHCPMessage struct {
	Op        uint8
	HType     uint8
	HLen      uint8
	Hops      uint8
	XID       uint32
	Secs      uint16
	Flags     uint16
	CIAddr    string
	YIAddr    string
	SIAddr    string
	GIAddr    string
	CHAddr    string
	Options   map[uint8][]byte
	MessageType uint8
}

func ParseDHCP(data []byte) (*DHCPMessage, error) {
	if len(data) < 240 {
		return nil, fmt.Errorf("DHCP packet too short")
	}

	msg := &DHCPMessage{
		Op:      data[0],
		HType:   data[1],
		HLen:    data[2],
		Hops:    data[3],
		XID:     binary.BigEndian.Uint32(data[4:8]),
		Secs:    binary.BigEndian.Uint16(data[8:10]),
		Flags:   binary.BigEndian.Uint16(data[10:12]),
		CIAddr:  fmt.Sprintf("%d.%d.%d.%d", data[12], data[13], data[14], data[15]),
		YIAddr:  fmt.Sprintf("%d.%d.%d.%d", data[16], data[17], data[18], data[19]),
		SIAddr:  fmt.Sprintf("%d.%d.%d.%d", data[20], data[21], data[22], data[23]),
		GIAddr:  fmt.Sprintf("%d.%d.%d.%d", data[24], data[25], data[26], data[27]),
		Options: make(map[uint8][]byte),
	}

	// Parse hardware address
	if msg.HLen <= 16 {
		hwAddr := make([]string, msg.HLen)
		for i := uint8(0); i < msg.HLen; i++ {
			hwAddr[i] = fmt.Sprintf("%02x", data[28+i])
		}
		msg.CHAddr = strings.Join(hwAddr, ":")
	}

	// Parse options (after magic cookie at offset 236)
	if len(data) > 240 && data[236] == 99 && data[237] == 130 && data[238] == 83 && data[239] == 99 {
		offset := 240
		for offset < len(data) {
			if data[offset] == 255 { // End option
				break
			}
			if data[offset] == 0 { // Padding
				offset++
				continue
			}
			if offset+1 >= len(data) {
				break
			}
			optType := data[offset]
			optLen := int(data[offset+1])
			offset += 2
			if offset+optLen > len(data) {
				break
			}
			msg.Options[optType] = data[offset : offset+optLen]
			if optType == 53 && optLen > 0 { // Message type
				msg.MessageType = data[offset]
			}
			offset += optLen
		}
	}

	return msg, nil
}

func (m *DHCPMessage) GetInfo() string {
	msgTypes := map[uint8]string{
		1: "Discover",
		2: "Offer",
		3: "Request",
		4: "Decline",
		5: "ACK",
		6: "NAK",
		7: "Release",
		8: "Inform",
	}

	msgType := "Unknown"
	if name, ok := msgTypes[m.MessageType]; ok {
		msgType = name
	}

	return fmt.Sprintf("DHCP %s - Transaction ID 0x%08x", msgType, m.XID)
}

// NTP parser
type NTPMessage struct {
	LI          uint8
	VN          uint8
	Mode        uint8
	Stratum     uint8
	Poll        int8
	Precision   int8
	RootDelay   uint32
	RootDisp    uint32
	RefID       string
}

func ParseNTP(data []byte) (*NTPMessage, error) {
	if len(data) < 48 {
		return nil, fmt.Errorf("NTP packet too short")
	}

	msg := &NTPMessage{
		LI:        (data[0] >> 6) & 0x3,
		VN:        (data[0] >> 3) & 0x7,
		Mode:      data[0] & 0x7,
		Stratum:   data[1],
		Poll:      int8(data[2]),
		Precision: int8(data[3]),
		RootDelay: binary.BigEndian.Uint32(data[4:8]),
		RootDisp:  binary.BigEndian.Uint32(data[8:12]),
	}

	// Reference ID
	if msg.Stratum <= 1 {
		msg.RefID = string(bytes.TrimRight(data[12:16], "\x00"))
	} else {
		msg.RefID = fmt.Sprintf("%d.%d.%d.%d", data[12], data[13], data[14], data[15])
	}

	return msg, nil
}

func (m *NTPMessage) GetInfo() string {
	modes := map[uint8]string{
		0: "Reserved",
		1: "Symmetric Active",
		2: "Symmetric Passive",
		3: "Client",
		4: "Server",
		5: "Broadcast",
		6: "Control",
		7: "Private",
	}

	mode := "Unknown"
	if name, ok := modes[m.Mode]; ok {
		mode = name
	}

	return fmt.Sprintf("NTP Version %d, %s", m.VN, mode)
}

// SNMP parser (basic)
type SNMPMessage struct {
	Version   int
	Community string
	PDUType   uint8
	RequestID uint32
}

func ParseSNMP(data []byte) (*SNMPMessage, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("SNMP packet too short")
	}

	msg := &SNMPMessage{}

	// Basic ASN.1 BER parsing
	if data[0] != 0x30 { // SEQUENCE
		return nil, fmt.Errorf("not a valid SNMP packet")
	}

	offset := 2
	if data[1] > 0x80 {
		lenBytes := int(data[1] & 0x7F)
		offset = 2 + lenBytes
	}

	// Version
	if offset+2 < len(data) && data[offset] == 0x02 { // INTEGER
		vLen := int(data[offset+1])
		if offset+2+vLen <= len(data) {
			msg.Version = int(data[offset+2])
		}
		offset += 2 + vLen
	}

	// Community string
	if offset+2 < len(data) && data[offset] == 0x04 { // OCTET STRING
		cLen := int(data[offset+1])
		if offset+2+cLen <= len(data) {
			msg.Community = string(data[offset+2 : offset+2+cLen])
		}
		offset += 2 + cLen
	}

	// PDU type
	if offset < len(data) {
		msg.PDUType = data[offset] & 0x1F
	}

	return msg, nil
}

func (m *SNMPMessage) GetInfo() string {
	pduTypes := map[uint8]string{
		0: "GetRequest",
		1: "GetNextRequest",
		2: "GetResponse",
		3: "SetRequest",
		4: "Trap",
		5: "GetBulkRequest",
		6: "InformRequest",
		7: "SNMPv2-Trap",
		8: "Report",
	}

	pduType := "Unknown"
	if name, ok := pduTypes[m.PDUType]; ok {
		pduType = name
	}

	return fmt.Sprintf("SNMPv%d %s, community=%s", m.Version+1, pduType, m.Community)
}
