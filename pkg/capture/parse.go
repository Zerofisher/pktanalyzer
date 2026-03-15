package capture

import (
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketInfoFromGopacket converts a gopacket.Packet into a PacketInfo.
// This is the standalone version of the Capturer.parsePacket method,
// used by the replay pipeline when no Capturer is available.
//
// NOTE: This is a simplified version (~50 lines) compared to the full
// Capturer.parsePacket (~800 lines). It handles Ethernet/IP/TCP/UDP which
// covers the vast majority of cases. More protocol support can be added
// incrementally.
// TODO: extract full parsePacket logic for richer replay support.
func PacketInfoFromGopacket(packet gopacket.Packet, ts time.Time, origLen int, rawData []byte) *PacketInfo {
	info := &PacketInfo{
		Timestamp:     ts,
		Length:        origLen,
		CaptureLength: len(rawData),
		RawData:       rawData,
	}

	// Parse Ethernet
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		info.SrcMAC = eth.SrcMAC.String()
		info.DstMAC = eth.DstMAC.String()
		info.EtherType = eth.EthernetType.String()
	}

	// Parse IP
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		info.SrcIP = ipv4.SrcIP.String()
		info.DstIP = ipv4.DstIP.String()
		info.Protocol = ipv4.Protocol.String()
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		info.SrcIP = ipv6.SrcIP.String()
		info.DstIP = ipv6.DstIP.String()
		info.Protocol = ipv6.NextHeader.String()
	}

	// Parse TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		info.SrcPort = strconv.Itoa(int(tcp.SrcPort))
		info.DstPort = strconv.Itoa(int(tcp.DstPort))
		info.Protocol = "TCP"
		info.TCPSeq = tcp.Seq
		info.TCPAck = tcp.Ack
		info.TCPFlags = getTCPFlagsValue(tcp)
		info.TCPWindow = tcp.Window
		info.TCPPayload = tcp.Payload
	}

	// Parse UDP
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		info.SrcPort = strconv.Itoa(int(udp.SrcPort))
		info.DstPort = strconv.Itoa(int(udp.DstPort))
		if info.Protocol == "" || info.Protocol == "UDP" {
			info.Protocol = "UDP"
		}
	}

	// Build layers list
	for _, layer := range packet.Layers() {
		info.Layers = append(info.Layers, LayerInfo{
			Name: layer.LayerType().String(),
		})
	}

	return info
}
