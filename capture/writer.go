package capture

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PcapWriter writes packets to a pcap/pcapng file
type PcapWriter struct {
	file       *os.File
	writer     *pcapgo.NgWriter
	mu         sync.Mutex
	count      int
	filename   string
	linkType   layers.LinkType
	snapLen    uint32
	closed     bool
}

// NewPcapWriter creates a new pcap writer
func NewPcapWriter(filename string) (*PcapWriter, error) {
	return NewPcapWriterWithOptions(filename, layers.LinkTypeEthernet, 65536)
}

// NewPcapWriterWithOptions creates a new pcap writer with custom options
func NewPcapWriterWithOptions(filename string, linkType layers.LinkType, snapLen uint32) (*PcapWriter, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create file %s: %w", filename, err)
	}

	// Create pcapng writer with interface options
	ngOptions := pcapgo.NgWriterOptions{
		SectionInfo: pcapgo.NgSectionInfo{
			Application: "pktanalyzer",
		},
	}

	writer, err := pcapgo.NewNgWriterInterface(file, pcapgo.NgInterface{
		Name:       "pktanalyzer",
		LinkType:   linkType,
		SnapLength: snapLen,
	}, ngOptions)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to create pcapng writer: %w", err)
	}

	return &PcapWriter{
		file:     file,
		writer:   writer,
		filename: filename,
		linkType: linkType,
		snapLen:  snapLen,
	}, nil
}

// WritePacket writes a single packet to the file
func (w *PcapWriter) WritePacket(pkt *PacketInfo) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return fmt.Errorf("writer is closed")
	}

	if len(pkt.RawData) == 0 {
		return nil // Skip empty packets
	}

	ci := gopacket.CaptureInfo{
		Timestamp:      pkt.Timestamp,
		CaptureLength:  len(pkt.RawData),
		Length:         pkt.Length,
		InterfaceIndex: 0,
	}

	if err := w.writer.WritePacket(ci, pkt.RawData); err != nil {
		return fmt.Errorf("failed to write packet: %w", err)
	}

	w.count++
	return nil
}

// WritePackets writes multiple packets to the file
func (w *PcapWriter) WritePackets(packets []PacketInfo) (int, error) {
	written := 0
	for i := range packets {
		if err := w.WritePacket(&packets[i]); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// Flush flushes any buffered data to disk
func (w *PcapWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	return w.writer.Flush()
}

// Close closes the writer and the underlying file
func (w *PcapWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	w.closed = true

	// Flush before closing
	if err := w.writer.Flush(); err != nil {
		w.file.Close()
		return fmt.Errorf("failed to flush: %w", err)
	}

	return w.file.Close()
}

// Count returns the number of packets written
func (w *PcapWriter) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}

// Filename returns the output filename
func (w *PcapWriter) Filename() string {
	return w.filename
}

// SavePackets is a convenience function to save packets to a file
func SavePackets(filename string, packets []PacketInfo) (int, error) {
	if len(packets) == 0 {
		return 0, fmt.Errorf("no packets to save")
	}

	writer, err := NewPcapWriter(filename)
	if err != nil {
		return 0, err
	}
	defer writer.Close()

	return writer.WritePackets(packets)
}

// GenerateFilename generates a unique filename with timestamp
func GenerateFilename(prefix string) string {
	ts := time.Now().Format("20060102_150405")
	return fmt.Sprintf("%s_%s.pcapng", prefix, ts)
}
