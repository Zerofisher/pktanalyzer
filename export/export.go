// Package export provides packet export functionality in various formats
package export

import (
	"encoding/json"
	"fmt"
	"io"
	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/fields"
	"strings"
)

// OutputFormat represents the output format type
type OutputFormat string

const (
	FormatText   OutputFormat = "text"
	FormatJSON   OutputFormat = "json"
	FormatFields OutputFormat = "fields"
)

// Exporter handles packet export
type Exporter struct {
	format       OutputFormat
	writer       io.Writer
	registry     *fields.Registry
	fields       []string // for -e field extraction
	showDetail   bool     // -V verbose
	showHex      bool     // -x hex dump
	count        int      // packets exported
	maxCount     int      // -c limit (0 = unlimited)
	firstPacket  bool     // track first packet for JSON array
}

// NewExporter creates a new exporter
func NewExporter(w io.Writer, format OutputFormat) *Exporter {
	return &Exporter{
		format:      format,
		writer:      w,
		registry:    fields.NewRegistry(),
		firstPacket: true,
	}
}

// SetFields sets the fields to extract (for -T fields -e)
func (e *Exporter) SetFields(fieldNames []string) {
	e.fields = fieldNames
}

// SetMaxCount sets the maximum packet count
func (e *Exporter) SetMaxCount(n int) {
	e.maxCount = n
}

// SetShowDetail enables verbose output
func (e *Exporter) SetShowDetail(v bool) {
	e.showDetail = v
}

// SetShowHex enables hex dump output
func (e *Exporter) SetShowHex(v bool) {
	e.showHex = v
}

// ShouldStop returns true if we've reached the packet limit
func (e *Exporter) ShouldStop() bool {
	return e.maxCount > 0 && e.count >= e.maxCount
}

// ExportPacket exports a single packet
func (e *Exporter) ExportPacket(pkt *capture.PacketInfo) error {
	if e.ShouldStop() {
		return nil
	}

	var err error
	switch e.format {
	case FormatText:
		err = e.exportText(pkt)
	case FormatJSON:
		err = e.exportJSON(pkt)
	case FormatFields:
		err = e.exportFields(pkt)
	default:
		err = e.exportText(pkt)
	}

	if err == nil {
		e.count++
	}
	return err
}

// Start writes any header needed for the format
func (e *Exporter) Start() error {
	if e.format == FormatJSON {
		_, err := fmt.Fprintln(e.writer, "[")
		return err
	}
	return nil
}

// Finish writes any footer needed for the format
func (e *Exporter) Finish() error {
	if e.format == FormatJSON {
		_, err := fmt.Fprintln(e.writer, "]")
		return err
	}
	return nil
}

// exportText exports packet in text format (one line summary)
func (e *Exporter) exportText(pkt *capture.PacketInfo) error {
	// Format: No. Time Source Destination Protocol Length Info
	timeStr := pkt.Timestamp.Format("15:04:05.000000")

	src := pkt.SrcIP
	if pkt.SrcPort != "" {
		src = fmt.Sprintf("%s:%s", pkt.SrcIP, pkt.SrcPort)
	}

	dst := pkt.DstIP
	if pkt.DstPort != "" {
		dst = fmt.Sprintf("%s:%s", pkt.DstIP, pkt.DstPort)
	}

	line := fmt.Sprintf("%d\t%s\t%s\t%s\t%s\t%d\t%s",
		pkt.Number,
		timeStr,
		src,
		dst,
		pkt.Protocol,
		pkt.Length,
		pkt.Info,
	)

	_, err := fmt.Fprintln(e.writer, line)
	if err != nil {
		return err
	}

	// Show detail if requested
	if e.showDetail {
		if err := e.exportDetail(pkt); err != nil {
			return err
		}
	}

	// Show hex if requested
	if e.showHex {
		if err := e.exportHexDump(pkt); err != nil {
			return err
		}
	}

	return nil
}

// PacketJSON represents a packet in JSON format
type PacketJSON struct {
	FrameNumber    int              `json:"frame.number"`
	FrameTime      string           `json:"frame.time"`
	FrameTimeEpoch float64          `json:"frame.time_epoch"`
	FrameLen       int              `json:"frame.len"`
	FrameProtocols string           `json:"frame.protocols"`
	EthSrc         string           `json:"eth.src,omitempty"`
	EthDst         string           `json:"eth.dst,omitempty"`
	EthType        string           `json:"eth.type,omitempty"`
	IPSrc          string           `json:"ip.src,omitempty"`
	IPDst          string           `json:"ip.dst,omitempty"`
	IPProto        string           `json:"ip.proto,omitempty"`
	TCPSrcPort     *uint16          `json:"tcp.srcport,omitempty"`
	TCPDstPort     *uint16          `json:"tcp.dstport,omitempty"`
	TCPSeq         *uint32          `json:"tcp.seq,omitempty"`
	TCPAck         *uint32          `json:"tcp.ack,omitempty"`
	TCPFlags       *uint16          `json:"tcp.flags,omitempty"`
	TCPLen         *int             `json:"tcp.len,omitempty"`
	TCPStream      string           `json:"tcp.stream,omitempty"`
	UDPSrcPort     *uint16          `json:"udp.srcport,omitempty"`
	UDPDstPort     *uint16          `json:"udp.dstport,omitempty"`
	Protocol       string           `json:"protocol"`
	Info           string           `json:"info"`
	SNI            string           `json:"tls.sni,omitempty"`
	Decrypted      bool             `json:"decrypted,omitempty"`
	Layers         []LayerJSON      `json:"layers,omitempty"`
}

// LayerJSON represents a protocol layer in JSON
type LayerJSON struct {
	Name    string   `json:"name"`
	Details []string `json:"details,omitempty"`
}

// exportJSON exports packet in JSON format
func (e *Exporter) exportJSON(pkt *capture.PacketInfo) error {
	// Build protocol list
	var protocols []string
	for _, layer := range pkt.Layers {
		protocols = append(protocols, strings.ToLower(strings.ReplaceAll(layer.Name, " ", "_")))
	}

	pktJSON := PacketJSON{
		FrameNumber:    pkt.Number,
		FrameTime:      pkt.Timestamp.Format("2006-01-02T15:04:05.000000Z07:00"),
		FrameTimeEpoch: float64(pkt.Timestamp.UnixNano()) / 1e9,
		FrameLen:       pkt.Length,
		FrameProtocols: strings.Join(protocols, ":"),
		EthSrc:         pkt.SrcMAC,
		EthDst:         pkt.DstMAC,
		EthType:        pkt.EtherType,
		IPSrc:          pkt.SrcIP,
		IPDst:          pkt.DstIP,
		IPProto:        pkt.Protocol,
		Protocol:       pkt.Protocol,
		Info:           pkt.Info,
		SNI:            pkt.SNI,
		Decrypted:      pkt.Decrypted,
		TCPStream:      pkt.StreamKey,
	}

	// Add TCP fields if present
	if isTCPPacket(pkt) {
		srcPort := parsePort(pkt.SrcPort)
		dstPort := parsePort(pkt.DstPort)
		pktJSON.TCPSrcPort = &srcPort
		pktJSON.TCPDstPort = &dstPort
		pktJSON.TCPSeq = &pkt.TCPSeq
		pktJSON.TCPAck = &pkt.TCPAck
		pktJSON.TCPFlags = &pkt.TCPFlags
		payloadLen := len(pkt.TCPPayload)
		pktJSON.TCPLen = &payloadLen
	}

	// Add UDP fields if present
	if isUDPPacket(pkt) {
		srcPort := parsePort(pkt.SrcPort)
		dstPort := parsePort(pkt.DstPort)
		pktJSON.UDPSrcPort = &srcPort
		pktJSON.UDPDstPort = &dstPort
	}

	// Add layers
	for _, layer := range pkt.Layers {
		pktJSON.Layers = append(pktJSON.Layers, LayerJSON{
			Name:    layer.Name,
			Details: layer.Details,
		})
	}

	// Marshal to JSON
	data, err := json.Marshal(pktJSON)
	if err != nil {
		return err
	}

	// Handle JSON array formatting
	if e.firstPacket {
		e.firstPacket = false
		_, err = fmt.Fprintf(e.writer, "  %s", data)
	} else {
		_, err = fmt.Fprintf(e.writer, ",\n  %s", data)
	}

	return err
}

// exportFields exports specific fields (for -T fields -e)
func (e *Exporter) exportFields(pkt *capture.PacketInfo) error {
	values := make([]string, len(e.fields))

	for i, fieldName := range e.fields {
		values[i] = e.registry.ExtractString(fieldName, pkt)
	}

	_, err := fmt.Fprintln(e.writer, strings.Join(values, "\t"))
	return err
}

// exportDetail exports packet detail (for -V)
func (e *Exporter) exportDetail(pkt *capture.PacketInfo) error {
	fmt.Fprintf(e.writer, "\nFrame %d: %d bytes on wire\n", pkt.Number, pkt.Length)
	fmt.Fprintf(e.writer, "    Arrival Time: %s\n", pkt.Timestamp.Format("2006-01-02 15:04:05.000000"))

	for _, layer := range pkt.Layers {
		fmt.Fprintf(e.writer, "\n%s:\n", layer.Name)
		for _, detail := range layer.Details {
			fmt.Fprintf(e.writer, "    %s\n", detail)
		}
	}

	fmt.Fprintln(e.writer)
	return nil
}

// exportHexDump exports hex dump (for -x)
func (e *Exporter) exportHexDump(pkt *capture.PacketInfo) error {
	data := pkt.RawData
	fmt.Fprintf(e.writer, "\nHex dump of packet %d (%d bytes):\n", pkt.Number, len(data))

	bytesPerLine := 16
	for i := 0; i < len(data); i += bytesPerLine {
		// Offset
		fmt.Fprintf(e.writer, "%08x  ", i)

		// Hex bytes
		for j := 0; j < bytesPerLine; j++ {
			if i+j < len(data) {
				fmt.Fprintf(e.writer, "%02x ", data[i+j])
			} else {
				fmt.Fprint(e.writer, "   ")
			}
			if j == 7 {
				fmt.Fprint(e.writer, " ")
			}
		}

		// ASCII
		fmt.Fprint(e.writer, " |")
		for j := 0; j < bytesPerLine && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Fprintf(e.writer, "%c", b)
			} else {
				fmt.Fprint(e.writer, ".")
			}
		}
		fmt.Fprintln(e.writer, "|")
	}

	fmt.Fprintln(e.writer)
	return nil
}

func isTCPPacket(pkt *capture.PacketInfo) bool {
	return pkt.Protocol == "TCP" || pkt.Protocol == "HTTP" || pkt.Protocol == "HTTPS" || pkt.Protocol == "TLS"
}

func isUDPPacket(pkt *capture.PacketInfo) bool {
	switch pkt.Protocol {
	case "UDP", "DNS", "NBNS", "LLMNR", "MDNS", "SSDP", "DHCP", "NTP", "SNMP", "SRVLOC", "WS-Discovery":
		return true
	}
	return false
}

func parsePort(s string) uint16 {
	var port uint16
	fmt.Sscanf(s, "%d", &port)
	return port
}
