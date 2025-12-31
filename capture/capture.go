package capture

import (
	"fmt"
	"github.com/Zerofisher/pktanalyzer/stream"
	"github.com/Zerofisher/pktanalyzer/tls"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PacketInfo holds parsed packet information
type PacketInfo struct {
	Number        int
	Timestamp     time.Time
	Length        int
	SrcMAC        string
	DstMAC        string
	EtherType     string
	SrcIP         string
	DstIP         string
	Protocol      string
	SrcPort       string
	DstPort       string
	Info          string
	RawData       []byte
	Layers        []LayerInfo
	Decrypted     bool   // Whether TLS was decrypted
	DecryptedData []byte // Decrypted application data
	SNI           string // TLS Server Name Indication

	// TCP stream info
	TCPSeq     uint32
	TCPAck     uint32
	TCPFlags   uint16
	TCPPayload []byte
	StreamKey  string
}

// LayerInfo holds information about a protocol layer
type LayerInfo struct {
	Name    string
	Details []string
}

// Capturer handles packet capture from interface or file
type Capturer struct {
	handle       *pcap.Handle
	packetChan   chan PacketInfo
	stopChan     chan struct{}
	isLive       bool
	counter      int
	tlsDecryptor *tls.Decryptor
	streamMgr    *stream.StreamManager
}

// ListInterfaces returns available network interfaces
func ListInterfaces() ([]pcap.Interface, error) {
	return pcap.FindAllDevs()
}

// NewLiveCapturer creates a capturer for live interface
func NewLiveCapturer(iface string, filter string) (*Capturer, error) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %w", iface, err)
	}

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	return &Capturer{
		handle:     handle,
		packetChan: make(chan PacketInfo, 1000),
		stopChan:   make(chan struct{}),
		isLive:     true,
	}, nil
}

// NewFileCapturer creates a capturer for pcap file
func NewFileCapturer(filename string, filter string) (*Capturer, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filename, err)
	}

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	return &Capturer{
		handle:     handle,
		packetChan: make(chan PacketInfo, 1000),
		stopChan:   make(chan struct{}),
		isLive:     false,
	}, nil
}

// Start begins packet capture
func (c *Capturer) Start() <-chan PacketInfo {
	go c.captureLoop()
	return c.packetChan
}

// Stop stops the capture
func (c *Capturer) Stop() {
	close(c.stopChan)
	c.handle.Close()
}

// SetDecryptor sets the TLS decryptor for HTTPS decryption
func (c *Capturer) SetDecryptor(decryptor *tls.Decryptor) {
	c.tlsDecryptor = decryptor
}

// SetStreamManager sets the TCP stream manager
func (c *Capturer) SetStreamManager(mgr *stream.StreamManager) {
	c.streamMgr = mgr
}

// GetStreamManager returns the stream manager
func (c *Capturer) GetStreamManager() *stream.StreamManager {
	return c.streamMgr
}

func (c *Capturer) captureLoop() {
	defer close(c.packetChan)

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	packetSource.NoCopy = true

	for {
		select {
		case <-c.stopChan:
			return
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return
			}
			c.counter++
			info := c.parsePacket(packet)
			info.Number = c.counter

			select {
			case c.packetChan <- info:
			case <-c.stopChan:
				return
			}
		}
	}
}

func (c *Capturer) parsePacket(packet gopacket.Packet) PacketInfo {
	info := PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
		RawData:   packet.Data(),
		Layers:    make([]LayerInfo, 0),
	}

	// Parse Ethernet
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		info.SrcMAC = eth.SrcMAC.String()
		info.DstMAC = eth.DstMAC.String()
		info.EtherType = eth.EthernetType.String()

		info.Layers = append(info.Layers, LayerInfo{
			Name: "Ethernet II",
			Details: []string{
				fmt.Sprintf("Source: %s", eth.SrcMAC),
				fmt.Sprintf("Destination: %s", eth.DstMAC),
				fmt.Sprintf("Type: %s (0x%04x)", eth.EthernetType, uint16(eth.EthernetType)),
			},
		})
	}

	// Parse ARP
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		info.Protocol = "ARP"
		info.SrcIP = fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1], arp.SourceProtAddress[2], arp.SourceProtAddress[3])
		info.DstIP = fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1], arp.DstProtAddress[2], arp.DstProtAddress[3])

		opStr := "Unknown"
		switch arp.Operation {
		case 1:
			opStr = "Request"
			info.Info = fmt.Sprintf("Who has %s? Tell %s", info.DstIP, info.SrcIP)
		case 2:
			opStr = "Reply"
			info.Info = fmt.Sprintf("%s is at %s", info.SrcIP, info.SrcMAC)
		}

		info.Layers = append(info.Layers, LayerInfo{
			Name: "ARP",
			Details: []string{
				fmt.Sprintf("Operation: %s (%d)", opStr, arp.Operation),
				fmt.Sprintf("Sender MAC: %s", formatMAC(arp.SourceHwAddress)),
				fmt.Sprintf("Sender IP: %s", info.SrcIP),
				fmt.Sprintf("Target MAC: %s", formatMAC(arp.DstHwAddress)),
				fmt.Sprintf("Target IP: %s", info.DstIP),
			},
		})
	}

	// Parse IPv4
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
		info.Protocol = ip.Protocol.String()

		info.Layers = append(info.Layers, LayerInfo{
			Name: "IPv4",
			Details: []string{
				fmt.Sprintf("Version: 4"),
				fmt.Sprintf("Header Length: %d bytes", ip.IHL*4),
				fmt.Sprintf("Total Length: %d", ip.Length),
				fmt.Sprintf("Identification: 0x%04x (%d)", ip.Id, ip.Id),
				fmt.Sprintf("Flags: 0x%02x", ip.Flags),
				fmt.Sprintf("Fragment Offset: %d", ip.FragOffset),
				fmt.Sprintf("TTL: %d", ip.TTL),
				fmt.Sprintf("Protocol: %s (%d)", ip.Protocol, uint8(ip.Protocol)),
				fmt.Sprintf("Checksum: 0x%04x", ip.Checksum),
				fmt.Sprintf("Source: %s", ip.SrcIP),
				fmt.Sprintf("Destination: %s", ip.DstIP),
			},
		})
	}

	// Parse IPv6
	if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
		info.Protocol = ip.NextHeader.String()

		info.Layers = append(info.Layers, LayerInfo{
			Name: "IPv6",
			Details: []string{
				fmt.Sprintf("Version: 6"),
				fmt.Sprintf("Traffic Class: 0x%02x", ip.TrafficClass),
				fmt.Sprintf("Flow Label: 0x%05x", ip.FlowLabel),
				fmt.Sprintf("Payload Length: %d", ip.Length),
				fmt.Sprintf("Next Header: %s (%d)", ip.NextHeader, uint8(ip.NextHeader)),
				fmt.Sprintf("Hop Limit: %d", ip.HopLimit),
				fmt.Sprintf("Source: %s", ip.SrcIP),
				fmt.Sprintf("Destination: %s", ip.DstIP),
			},
		})
	}

	// Parse TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		info.Protocol = "TCP"
		info.SrcPort = fmt.Sprintf("%d", tcp.SrcPort)
		info.DstPort = fmt.Sprintf("%d", tcp.DstPort)

		// Store TCP-specific fields for stream reassembly
		info.TCPSeq = tcp.Seq
		info.TCPAck = tcp.Ack
		info.TCPFlags = getTCPFlagsValue(tcp)
		info.TCPPayload = tcp.Payload

		flags := formatTCPFlags(tcp)
		info.Info = fmt.Sprintf("%s → %s [%s] Seq=%d Ack=%d Win=%d Len=%d",
			FormatPort(info.SrcPort), FormatPort(info.DstPort), flags, tcp.Seq, tcp.Ack, tcp.Window, len(tcp.Payload))

		info.Layers = append(info.Layers, LayerInfo{
			Name: "TCP",
			Details: []string{
				fmt.Sprintf("Source Port: %d", tcp.SrcPort),
				fmt.Sprintf("Destination Port: %d", tcp.DstPort),
				fmt.Sprintf("Sequence Number: %d", tcp.Seq),
				fmt.Sprintf("Acknowledgment Number: %d", tcp.Ack),
				fmt.Sprintf("Header Length: %d bytes", tcp.DataOffset*4),
				fmt.Sprintf("Flags: 0x%03x (%s)", getTCPFlagsValue(tcp), flags),
				fmt.Sprintf("Window Size: %d", tcp.Window),
				fmt.Sprintf("Checksum: 0x%04x", tcp.Checksum),
				fmt.Sprintf("Urgent Pointer: %d", tcp.Urgent),
			},
		})

		// Process TCP stream if stream manager is enabled
		if c.streamMgr != nil && c.streamMgr.IsEnabled() {
			srcPort, _ := strconv.ParseUint(info.SrcPort, 10, 16)
			dstPort, _ := strconv.ParseUint(info.DstPort, 10, 16)

			pkt := &stream.TCPPacket{
				SrcIP:     info.SrcIP,
				DstIP:     info.DstIP,
				SrcPort:   uint16(srcPort),
				DstPort:   uint16(dstPort),
				Seq:       tcp.Seq,
				Ack:       tcp.Ack,
				Flags:     stream.TCPFlags(info.TCPFlags),
				Payload:   tcp.Payload,
				Timestamp: info.Timestamp,
				PacketNum: c.counter,
			}

			info.StreamKey = c.streamMgr.ProcessPacket(pkt)
		}
	}

	// Parse UDP
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		info.Protocol = "UDP"
		info.SrcPort = fmt.Sprintf("%d", udp.SrcPort)
		info.DstPort = fmt.Sprintf("%d", udp.DstPort)
		info.Info = fmt.Sprintf("%s → %s Len=%d", FormatPort(info.SrcPort), FormatPort(info.DstPort), udp.Length)

		info.Layers = append(info.Layers, LayerInfo{
			Name: "UDP",
			Details: []string{
				fmt.Sprintf("Source Port: %d", udp.SrcPort),
				fmt.Sprintf("Destination Port: %d", udp.DstPort),
				fmt.Sprintf("Length: %d", udp.Length),
				fmt.Sprintf("Checksum: 0x%04x", udp.Checksum),
			},
		})

		// Parse application layer protocols based on port
		payload := udp.Payload
		srcPort := uint16(udp.SrcPort)
		dstPort := uint16(udp.DstPort)

		// NBNS (NetBIOS Name Service) - Port 137
		if srcPort == 137 || dstPort == 137 {
			if nbns, err := ParseNBNS(payload); err == nil {
				info.Protocol = "NBNS"
				info.Info = nbns.GetInfo()
				info.Layers = append(info.Layers, LayerInfo{
					Name: "NetBIOS Name Service",
					Details: []string{
						fmt.Sprintf("Transaction ID: 0x%04x", nbns.TransactionID),
						fmt.Sprintf("Flags: 0x%04x", nbns.Flags),
						fmt.Sprintf("Questions: %d", nbns.Questions),
						fmt.Sprintf("Answer RRs: %d", nbns.AnswerRRs),
					},
				})
			}
		}

		// LLMNR (Link-Local Multicast Name Resolution) - Port 5355
		if srcPort == 5355 || dstPort == 5355 {
			if llmnr, err := ParseLLMNR(payload); err == nil {
				info.Protocol = "LLMNR"
				info.Info = llmnr.GetInfo()
				info.Layers = append(info.Layers, LayerInfo{
					Name: "Link-Local Multicast Name Resolution",
					Details: []string{
						fmt.Sprintf("Transaction ID: 0x%04x", llmnr.TransactionID),
						fmt.Sprintf("Flags: 0x%04x", llmnr.Flags),
						fmt.Sprintf("Questions: %d", llmnr.Questions),
						fmt.Sprintf("Query Name: %s", llmnr.QueryName),
						fmt.Sprintf("Query Type: %s", getDNSTypeName(llmnr.QueryType)),
					},
				})
			}
		}

		// mDNS (Multicast DNS) - Port 5353
		if srcPort == 5353 || dstPort == 5353 {
			if mdns, err := ParseMDNS(payload); err == nil {
				info.Protocol = "MDNS"
				info.Info = mdns.GetInfo()
				details := []string{
					fmt.Sprintf("Transaction ID: 0x%04x", mdns.TransactionID),
					fmt.Sprintf("Flags: 0x%04x", mdns.Flags),
					fmt.Sprintf("Questions: %d", mdns.Questions),
					fmt.Sprintf("Answer RRs: %d", mdns.AnswerRRs),
				}
				for _, q := range mdns.Queries {
					details = append(details, fmt.Sprintf("Query: %s %s", q.Name, getDNSTypeName(q.Type)))
				}
				for _, a := range mdns.Answers {
					details = append(details, fmt.Sprintf("Answer: %s %s → %s", a.Name, getDNSTypeName(a.Type), a.Data))
				}
				info.Layers = append(info.Layers, LayerInfo{
					Name:    "Multicast DNS",
					Details: details,
				})
			}
		}

		// SSDP (Simple Service Discovery Protocol) - Port 1900
		if srcPort == 1900 || dstPort == 1900 {
			if ssdp, err := ParseSSDP(payload); err == nil {
				info.Protocol = "SSDP"
				info.Info = ssdp.GetInfo()
				details := []string{}
				if ssdp.IsResponse {
					details = append(details, fmt.Sprintf("Response: %d %s", ssdp.StatusCode, ssdp.StatusText))
				} else {
					details = append(details, fmt.Sprintf("Method: %s", ssdp.Method))
					details = append(details, fmt.Sprintf("URI: %s", ssdp.URI))
				}
				for k, v := range ssdp.Headers {
					details = append(details, fmt.Sprintf("%s: %s", k, v))
				}
				info.Layers = append(info.Layers, LayerInfo{
					Name:    "Simple Service Discovery Protocol",
					Details: details,
				})
			}
		}

		// SRVLOC (Service Location Protocol) - Port 427
		if srcPort == 427 || dstPort == 427 {
			if srvloc, err := ParseSRVLOC(payload); err == nil {
				info.Protocol = "SRVLOC"
				info.Info = srvloc.GetInfo()
				info.Layers = append(info.Layers, LayerInfo{
					Name: "Service Location Protocol",
					Details: []string{
						fmt.Sprintf("Version: %d", srvloc.Version),
						fmt.Sprintf("Function: %d", srvloc.Function),
						fmt.Sprintf("Length: %d", srvloc.Length),
						fmt.Sprintf("XID: %d", srvloc.XID),
					},
				})
			}
		}

		// WS-Discovery - Port 3702
		if srcPort == 3702 || dstPort == 3702 {
			if wsd, err := ParseWSDiscovery(payload); err == nil {
				info.Protocol = "WS-Discovery"
				info.Info = wsd.GetInfo()
				info.Layers = append(info.Layers, LayerInfo{
					Name: "Web Services Discovery",
					Details: []string{
						fmt.Sprintf("Action: %s", wsd.Action),
					},
				})
			}
		}

		// DHCP/BOOTP - Port 67, 68
		if srcPort == 67 || dstPort == 67 || srcPort == 68 || dstPort == 68 {
			if dhcp, err := ParseDHCP(payload); err == nil {
				info.Protocol = "DHCP"
				info.Info = dhcp.GetInfo()
				details := []string{
					fmt.Sprintf("Message Type: %d", dhcp.MessageType),
					fmt.Sprintf("Transaction ID: 0x%08x", dhcp.XID),
					fmt.Sprintf("Client IP: %s", dhcp.CIAddr),
					fmt.Sprintf("Your IP: %s", dhcp.YIAddr),
					fmt.Sprintf("Server IP: %s", dhcp.SIAddr),
					fmt.Sprintf("Client MAC: %s", dhcp.CHAddr),
				}
				info.Layers = append(info.Layers, LayerInfo{
					Name:    "Dynamic Host Configuration Protocol",
					Details: details,
				})
			}
		}

		// NTP - Port 123
		if srcPort == 123 || dstPort == 123 {
			if ntp, err := ParseNTP(payload); err == nil {
				info.Protocol = "NTP"
				info.Info = ntp.GetInfo()
				info.Layers = append(info.Layers, LayerInfo{
					Name: "Network Time Protocol",
					Details: []string{
						fmt.Sprintf("Leap Indicator: %d", ntp.LI),
						fmt.Sprintf("Version: %d", ntp.VN),
						fmt.Sprintf("Mode: %d", ntp.Mode),
						fmt.Sprintf("Stratum: %d", ntp.Stratum),
						fmt.Sprintf("Reference ID: %s", ntp.RefID),
					},
				})
			}
		}

		// SNMP - Port 161, 162
		if srcPort == 161 || dstPort == 161 || srcPort == 162 || dstPort == 162 {
			if snmp, err := ParseSNMP(payload); err == nil {
				info.Protocol = "SNMP"
				info.Info = snmp.GetInfo()
				info.Layers = append(info.Layers, LayerInfo{
					Name: "Simple Network Management Protocol",
					Details: []string{
						fmt.Sprintf("Version: %d", snmp.Version+1),
						fmt.Sprintf("Community: %s", snmp.Community),
						fmt.Sprintf("PDU Type: %d", snmp.PDUType),
					},
				})
			}
		}
	}

	// Parse ICMP
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv4)
		info.Protocol = "ICMP"

		typeStr := getICMPTypeName(icmp.TypeCode.Type())
		info.Info = fmt.Sprintf("%s (type=%d, code=%d)", typeStr, icmp.TypeCode.Type(), icmp.TypeCode.Code())

		info.Layers = append(info.Layers, LayerInfo{
			Name: "ICMP",
			Details: []string{
				fmt.Sprintf("Type: %d (%s)", icmp.TypeCode.Type(), typeStr),
				fmt.Sprintf("Code: %d", icmp.TypeCode.Code()),
				fmt.Sprintf("Checksum: 0x%04x", icmp.Checksum),
				fmt.Sprintf("ID: %d", icmp.Id),
				fmt.Sprintf("Sequence: %d", icmp.Seq),
			},
		})
	}

	// Parse ICMPv6
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv6)
		info.Protocol = "ICMPv6"
		info.Info = fmt.Sprintf("ICMPv6 (type=%d, code=%d)", icmp.TypeCode.Type(), icmp.TypeCode.Code())

		info.Layers = append(info.Layers, LayerInfo{
			Name: "ICMPv6",
			Details: []string{
				fmt.Sprintf("Type: %d", icmp.TypeCode.Type()),
				fmt.Sprintf("Code: %d", icmp.TypeCode.Code()),
				fmt.Sprintf("Checksum: 0x%04x", icmp.Checksum),
			},
		})
	}

	// Parse DNS
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		info.Protocol = "DNS"

		if dns.QR {
			// Response
			if len(dns.Answers) > 0 {
				info.Info = fmt.Sprintf("Response: %s", formatDNSAnswers(dns.Answers))
			} else {
				info.Info = "Response (no answers)"
			}
		} else {
			// Query
			if len(dns.Questions) > 0 {
				info.Info = fmt.Sprintf("Query: %s %s", string(dns.Questions[0].Name), dns.Questions[0].Type)
			} else {
				info.Info = "Query"
			}
		}

		details := []string{
			fmt.Sprintf("Transaction ID: 0x%04x", dns.ID),
			fmt.Sprintf("Flags: 0x%04x", getDNSFlags(dns)),
			fmt.Sprintf("Questions: %d", len(dns.Questions)),
			fmt.Sprintf("Answer RRs: %d", len(dns.Answers)),
			fmt.Sprintf("Authority RRs: %d", len(dns.Authorities)),
			fmt.Sprintf("Additional RRs: %d", len(dns.Additionals)),
		}

		for i, q := range dns.Questions {
			details = append(details, fmt.Sprintf("Query %d: %s %s %s", i+1, string(q.Name), q.Type, q.Class))
		}
		for i, a := range dns.Answers {
			details = append(details, fmt.Sprintf("Answer %d: %s %s -> %s", i+1, string(a.Name), a.Type, formatDNSData(a)))
		}

		info.Layers = append(info.Layers, LayerInfo{
			Name:    "DNS",
			Details: details,
		})
	}

	// Parse TLS and attempt decryption
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) > 0 && tls.IsTLSRecord(payload) {
			c.parseTLS(&info, payload)
		}
	}

	// Parse HTTP (basic detection) - also check decrypted data
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := string(appLayer.Payload())

		// First check decrypted data
		if info.Decrypted && len(info.DecryptedData) > 0 {
			decrypted := string(info.DecryptedData)
			if isHTTPRequest(decrypted) {
				info.Protocol = "HTTPS"
				info.Info = "[Decrypted] " + getHTTPRequestLine(decrypted)
				info.Layers = append(info.Layers, LayerInfo{
					Name:    "HTTP (Decrypted)",
					Details: parseHTTPDetails(decrypted),
				})
			} else if isHTTPResponse(decrypted) {
				info.Protocol = "HTTPS"
				info.Info = "[Decrypted] " + getHTTPResponseLine(decrypted)
				info.Layers = append(info.Layers, LayerInfo{
					Name:    "HTTP (Decrypted)",
					Details: parseHTTPDetails(decrypted),
				})
			}
		} else if len(payload) > 0 {
			if isHTTPRequest(payload) {
				info.Protocol = "HTTP"
				info.Info = getHTTPRequestLine(payload)
				info.Layers = append(info.Layers, LayerInfo{
					Name:    "HTTP",
					Details: parseHTTPDetails(payload),
				})
			} else if isHTTPResponse(payload) {
				info.Protocol = "HTTP"
				info.Info = getHTTPResponseLine(payload)
				info.Layers = append(info.Layers, LayerInfo{
					Name:    "HTTP",
					Details: parseHTTPDetails(payload),
				})
			}
		}
	}

	// Set default info if empty
	if info.Info == "" && info.Protocol != "" {
		info.Info = fmt.Sprintf("%s %s:%s -> %s:%s", info.Protocol, info.SrcIP, info.SrcPort, info.DstIP, info.DstPort)
	}

	return info
}

// parseTLS handles TLS protocol parsing and decryption
func (c *Capturer) parseTLS(info *PacketInfo, payload []byte) {
	record, _, err := tls.ParseTLSRecord(payload)
	if err != nil {
		return
	}

	// Get session key
	srcPort, _ := strconv.ParseUint(info.SrcPort, 10, 16)
	dstPort, _ := strconv.ParseUint(info.DstPort, 10, 16)
	sessionKey := tls.SessionKey(info.SrcIP, info.DstIP, uint16(srcPort), uint16(dstPort))

	// Determine if this is from client (typically higher port number connecting to 443)
	isFromClient := dstPort == 443 || dstPort == 8443

	// Add TLS layer info
	tlsDetails := []string{
		fmt.Sprintf("Content Type: %s (%d)", tls.GetContentTypeName(record.ContentType), record.ContentType),
		fmt.Sprintf("Version: %s (0x%04x)", tls.GetVersionName(record.Version), record.Version),
		fmt.Sprintf("Length: %d", record.Length),
	}

	// Process based on content type
	switch record.ContentType {
	case tls.ContentTypeHandshake:
		c.parseHandshake(info, record, sessionKey, isFromClient, &tlsDetails)
	case tls.ContentTypeApplicationData:
		c.parseApplicationData(info, record, sessionKey, isFromClient, &tlsDetails)
	case tls.ContentTypeAlert:
		info.Protocol = "TLS"
		info.Info = "TLS Alert"
	case tls.ContentTypeChangeCipherSpec:
		info.Protocol = "TLS"
		info.Info = "Change Cipher Spec"
	}

	info.Layers = append(info.Layers, LayerInfo{
		Name:    "TLS",
		Details: tlsDetails,
	})
}

// parseHandshake handles TLS handshake messages
func (c *Capturer) parseHandshake(info *PacketInfo, record *tls.TLSRecord, sessionKey string, isFromClient bool, details *[]string) {
	msg, _, err := tls.ParseHandshakeMessage(record.Fragment)
	if err != nil {
		return
	}

	*details = append(*details, fmt.Sprintf("Handshake Type: %s (%d)", tls.GetHandshakeTypeName(msg.Type), msg.Type))

	switch msg.Type {
	case tls.HandshakeTypeClientHello:
		ch, err := tls.ParseClientHello(msg.Data)
		if err == nil {
			info.Protocol = "TLS"
			info.Info = "Client Hello"
			if ch.SNI != "" {
				info.SNI = ch.SNI
				info.Info = fmt.Sprintf("Client Hello (SNI: %s)", ch.SNI)
				*details = append(*details, fmt.Sprintf("Server Name: %s", ch.SNI))
			}
			*details = append(*details, fmt.Sprintf("Client Version: %s", tls.GetVersionName(ch.Version)))
			*details = append(*details, fmt.Sprintf("Session ID Length: %d", len(ch.SessionID)))
			*details = append(*details, fmt.Sprintf("Cipher Suites: %d", len(ch.CipherSuites)))

			// Process handshake for decryptor
			if c.tlsDecryptor != nil {
				c.tlsDecryptor.ProcessHandshake(sessionKey, info.SrcIP, info.DstIP,
					uint16(mustParsePort(info.SrcPort)), uint16(mustParsePort(info.DstPort)),
					append([]byte{record.ContentType}, append([]byte{byte(record.Version >> 8), byte(record.Version), byte(record.Length >> 8), byte(record.Length)}, record.Fragment...)...),
					isFromClient)
			}
		}

	case tls.HandshakeTypeServerHello:
		sh, err := tls.ParseServerHello(msg.Data)
		if err == nil {
			info.Protocol = "TLS"
			info.Info = fmt.Sprintf("Server Hello (%s)", tls.GetCipherSuiteName(sh.CipherSuite))
			*details = append(*details, fmt.Sprintf("Server Version: %s", tls.GetVersionName(sh.Version)))
			*details = append(*details, fmt.Sprintf("Cipher Suite: %s", tls.GetCipherSuiteName(sh.CipherSuite)))

			// Process handshake for decryptor
			if c.tlsDecryptor != nil {
				c.tlsDecryptor.ProcessHandshake(sessionKey, info.SrcIP, info.DstIP,
					uint16(mustParsePort(info.SrcPort)), uint16(mustParsePort(info.DstPort)),
					append([]byte{record.ContentType}, append([]byte{byte(record.Version >> 8), byte(record.Version), byte(record.Length >> 8), byte(record.Length)}, record.Fragment...)...),
					isFromClient)
			}
		}

	case tls.HandshakeTypeCertificate:
		info.Protocol = "TLS"
		info.Info = "Certificate"

	case tls.HandshakeTypeServerHelloDone:
		info.Protocol = "TLS"
		info.Info = "Server Hello Done"

	case tls.HandshakeTypeClientKeyExchange:
		info.Protocol = "TLS"
		info.Info = "Client Key Exchange"

	case tls.HandshakeTypeFinished:
		info.Protocol = "TLS"
		info.Info = "Finished"

	default:
		info.Protocol = "TLS"
		info.Info = fmt.Sprintf("Handshake (%s)", tls.GetHandshakeTypeName(msg.Type))
	}
}

// parseApplicationData handles TLS application data
func (c *Capturer) parseApplicationData(info *PacketInfo, record *tls.TLSRecord, sessionKey string, isFromClient bool, details *[]string) {
	info.Protocol = "TLS"
	info.Info = fmt.Sprintf("Application Data [%d bytes]", len(record.Fragment))

	// Attempt decryption
	if c.tlsDecryptor != nil && c.tlsDecryptor.HasKeys(sessionKey) {
		// Reconstruct TLS record for decryption
		tlsRecord := append([]byte{record.ContentType}, []byte{byte(record.Version >> 8), byte(record.Version), byte(record.Length >> 8), byte(record.Length)}...)
		tlsRecord = append(tlsRecord, record.Fragment...)

		decrypted, err := c.tlsDecryptor.DecryptApplicationData(sessionKey, tlsRecord, isFromClient)
		if err == nil && len(decrypted) > 0 {
			info.Decrypted = true
			info.DecryptedData = decrypted
			*details = append(*details, fmt.Sprintf("Decrypted: %d bytes", len(decrypted)))

			// Get SNI if available
			if sni := c.tlsDecryptor.GetSNI(sessionKey); sni != "" {
				info.SNI = sni
			}
		}
	}
}

func mustParsePort(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 16)
	return v
}

func formatMAC(addr []byte) string {
	if len(addr) != 6 {
		return "N/A"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
}

func formatTCPFlags(tcp *layers.TCP) string {
	flags := ""
	if tcp.FIN {
		flags += "FIN,"
	}
	if tcp.SYN {
		flags += "SYN,"
	}
	if tcp.RST {
		flags += "RST,"
	}
	if tcp.PSH {
		flags += "PSH,"
	}
	if tcp.ACK {
		flags += "ACK,"
	}
	if tcp.URG {
		flags += "URG,"
	}
	if tcp.ECE {
		flags += "ECE,"
	}
	if tcp.CWR {
		flags += "CWR,"
	}
	if len(flags) > 0 {
		flags = flags[:len(flags)-1]
	}
	return flags
}

func getTCPFlagsValue(tcp *layers.TCP) uint16 {
	var flags uint16
	if tcp.FIN {
		flags |= 0x001
	}
	if tcp.SYN {
		flags |= 0x002
	}
	if tcp.RST {
		flags |= 0x004
	}
	if tcp.PSH {
		flags |= 0x008
	}
	if tcp.ACK {
		flags |= 0x010
	}
	if tcp.URG {
		flags |= 0x020
	}
	if tcp.ECE {
		flags |= 0x040
	}
	if tcp.CWR {
		flags |= 0x080
	}
	return flags
}

func getICMPTypeName(t uint8) string {
	names := map[uint8]string{
		0:  "Echo Reply",
		3:  "Destination Unreachable",
		4:  "Source Quench",
		5:  "Redirect",
		8:  "Echo Request",
		9:  "Router Advertisement",
		10: "Router Solicitation",
		11: "Time Exceeded",
		12: "Parameter Problem",
		13: "Timestamp Request",
		14: "Timestamp Reply",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return "Unknown"
}

func formatDNSAnswers(answers []layers.DNSResourceRecord) string {
	if len(answers) == 0 {
		return ""
	}
	return fmt.Sprintf("%s -> %s", string(answers[0].Name), formatDNSData(answers[0]))
}

func formatDNSData(rr layers.DNSResourceRecord) string {
	switch rr.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		return rr.IP.String()
	case layers.DNSTypeCNAME:
		return string(rr.CNAME)
	case layers.DNSTypeMX:
		return string(rr.MX.Name)
	case layers.DNSTypeNS:
		return string(rr.NS)
	case layers.DNSTypeTXT:
		return string(rr.TXT)
	default:
		return fmt.Sprintf("%v", rr.Data)
	}
}

func getDNSFlags(dns *layers.DNS) uint16 {
	var flags uint16
	if dns.QR {
		flags |= 0x8000
	}
	flags |= uint16(dns.OpCode) << 11
	if dns.AA {
		flags |= 0x0400
	}
	if dns.TC {
		flags |= 0x0200
	}
	if dns.RD {
		flags |= 0x0100
	}
	if dns.RA {
		flags |= 0x0080
	}
	flags |= uint16(dns.ResponseCode)
	return flags
}

func isHTTPRequest(payload string) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}
	for _, m := range methods {
		if len(payload) >= len(m) && payload[:len(m)] == m {
			return true
		}
	}
	return false
}

func isHTTPResponse(payload string) bool {
	return len(payload) >= 5 && payload[:5] == "HTTP/"
}

func getHTTPRequestLine(payload string) string {
	for i, c := range payload {
		if c == '\r' || c == '\n' {
			return payload[:i]
		}
	}
	if len(payload) > 80 {
		return payload[:80]
	}
	return payload
}

func getHTTPResponseLine(payload string) string {
	return getHTTPRequestLine(payload)
}

func parseHTTPDetails(payload string) []string {
	details := []string{}
	lines := splitLines(payload)
	for i, line := range lines {
		if i == 0 {
			details = append(details, fmt.Sprintf("Request/Response: %s", line))
		} else if line == "" {
			break
		} else if i < 15 {
			details = append(details, line)
		}
	}
	return details
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
