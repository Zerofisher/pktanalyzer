// Package replay re-reads raw packets from pcap files using stored file offsets.
// This bridges the gap between model.PacketSummary (from SQLite index) and
// capture.PacketInfo (full parsed packet) for tools that need complete packet data.
//
// IMPORTANT: File offsets are only populated for classic .pcap files during indexing.
// For .pcapng files, PacketEvidence.FileOffset will be 0, and ReadPacket will
// return an error. Tools that depend on replay will degrade gracefully for pcapng.
package replay

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Zerofisher/pktanalyzer/pkg/capture"
	"github.com/Zerofisher/pktanalyzer/pkg/model"
	"github.com/Zerofisher/pktanalyzer/pkg/tls"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Reader re-reads raw packets from a pcap file using stored offsets.
type Reader struct {
	pcapPath  string
	decryptor *tls.Decryptor // nil if no TLS decryption
}

// NewReader creates a replay reader. decryptor may be nil.
func NewReader(pcapPath string, decryptor *tls.Decryptor) *Reader {
	return &Reader{
		pcapPath:  pcapPath,
		decryptor: decryptor,
	}
}

// ReadPacket reads a single raw packet from the pcap file at the given evidence offset,
// parses it into a full capture.PacketInfo.
//
// Returns an error if FileOffset is 0 (e.g., for pcapng files where offsets
// are not tracked during indexing).
func (r *Reader) ReadPacket(evidence model.PacketEvidence) (*capture.PacketInfo, error) {
	if evidence.FileOffset <= 0 {
		return nil, fmt.Errorf("invalid file offset: %d (packet may not have evidence; pcapng files do not store offsets)", evidence.FileOffset)
	}

	f, err := os.Open(r.pcapPath)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	defer f.Close()

	return r.readPacketAt(f, evidence.FileOffset)
}

// ReadFlowPackets reads all packets for a flow by their evidence offsets.
// Packets with zero offsets are skipped. Results are returned in input order.
func (r *Reader) ReadFlowPackets(packets []*model.PacketSummary) ([]*capture.PacketInfo, error) {
	if len(packets) == 0 {
		return nil, nil
	}

	f, err := os.Open(r.pcapPath)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	defer f.Close()

	var infos []*capture.PacketInfo
	for _, pkt := range packets {
		if pkt.Evidence.FileOffset <= 0 {
			continue // skip packets without file offsets (pcapng)
		}
		info, err := r.readPacketAt(f, pkt.Evidence.FileOffset)
		if err != nil {
			continue // skip unreadable packets, don't fail the whole flow
		}
		info.Number = pkt.Number
		infos = append(infos, info)
	}
	return infos, nil
}

// readPacketAt seeks to offset in f, reads the classic pcap record header (16 bytes)
// and raw data, and parses the packet with gopacket.
//
// This only works for classic .pcap files (not pcapng). The pcap record header format is:
//
//	uint32 ts_sec, uint32 ts_usec, uint32 incl_len, uint32 orig_len (all little-endian)
func (r *Reader) readPacketAt(f *os.File, offset int64) (*capture.PacketInfo, error) {
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek to %d: %w", offset, err)
	}

	// Read pcap record header (16 bytes):
	// uint32 ts_sec, uint32 ts_usec, uint32 incl_len, uint32 orig_len
	var hdr [16]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return nil, fmt.Errorf("read record header: %w", err)
	}

	tsSec := binary.LittleEndian.Uint32(hdr[0:4])
	tsUsec := binary.LittleEndian.Uint32(hdr[4:8])
	inclLen := binary.LittleEndian.Uint32(hdr[8:12])
	origLen := binary.LittleEndian.Uint32(hdr[12:16])

	if inclLen > 65536 {
		return nil, fmt.Errorf("suspicious incl_len=%d at offset %d (file may be pcapng or corrupted)", inclLen, offset)
	}

	// Read raw packet data
	raw := make([]byte, inclLen)
	if _, err := io.ReadFull(f, raw); err != nil {
		return nil, fmt.Errorf("read packet data: %w", err)
	}

	// Parse with gopacket (assume Ethernet link type)
	packet := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	ts := time.Unix(int64(tsSec), int64(tsUsec)*1000)

	info := capture.PacketInfoFromGopacket(packet, ts, int(origLen), raw)

	// TLS decryption is NOT applied during replay for now.
	// The existing Decryptor API requires session keys and per-connection state
	// that cannot be reconstructed from a single packet replay.
	// TODO: If TLS decryption during replay is needed, the Decryptor must be
	// initialized with the full keylog and process packets in connection order.
	// For now, replay returns the encrypted packet as-is.

	return info, nil
}
