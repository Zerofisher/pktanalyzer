package replay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zerofisher/pktanalyzer/pkg/ingest"
	"github.com/Zerofisher/pktanalyzer/pkg/model"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
)

// findTestPcap locates a test pcap in examples/.
// Prefers classic .pcap files (not .pcapng) because only .pcap files
// have FileOffset values populated during indexing. Replay requires offsets.
func findTestPcap(t *testing.T) string {
	t.Helper()
	// Walk up to find examples/ directory
	dir, _ := os.Getwd()
	for i := 0; i < 5; i++ {
		// Prefer .pcap (classic) over .pcapng for replay tests
		pattern := filepath.Join(dir, "examples", "*.pcap")
		matches, _ := filepath.Glob(pattern)
		// Filter out .pcapng matches (Glob "*.pcap" also matches "*.pcapng")
		var classicPcaps []string
		for _, m := range matches {
			if !strings.HasSuffix(m, ".pcapng") {
				classicPcaps = append(classicPcaps, m)
			}
		}
		if len(classicPcaps) > 0 {
			return classicPcaps[0]
		}
		// Fallback to pcapng (tests that need offsets will t.Skip)
		ngPattern := filepath.Join(dir, "examples", "*.pcapng")
		ngMatches, _ := filepath.Glob(ngPattern)
		if len(ngMatches) > 0 {
			return ngMatches[0]
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("no test pcap found in examples/")
	return ""
}

func TestReadPacket(t *testing.T) {
	pcapPath := findTestPcap(t)

	// Index the pcap first
	needsIndex, _ := ingest.NeedsReindex(pcapPath)
	if needsIndex {
		_, err := ingest.IndexFile(pcapPath, nil)
		if err != nil {
			t.Fatalf("index: %v", err)
		}
	}

	// Open query engine
	engine, err := query.NewFromPcap(pcapPath)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer engine.Close()

	// Get first packet
	pkt, err := engine.GetPacket(t.Context(), 1)
	if err != nil {
		t.Fatalf("get packet: %v", err)
	}

	// Ensure it has a file offset
	if pkt.Evidence.FileOffset <= 0 {
		t.Skip("packet has no file offset (may be pcapng)")
	}

	// Replay it
	reader := NewReader(pcapPath, nil)
	info, err := reader.ReadPacket(pkt.Evidence)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}

	// Verify basic fields match
	if info.SrcIP != pkt.SrcIP {
		t.Errorf("SrcIP = %q, want %q", info.SrcIP, pkt.SrcIP)
	}
	if info.Length != pkt.Length {
		t.Errorf("Length = %d, want %d", info.Length, pkt.Length)
	}
}

func TestReadPacket_ZeroOffset(t *testing.T) {
	reader := NewReader("/dev/null", nil)
	_, err := reader.ReadPacket(model.PacketEvidence{FileOffset: 0})
	if err == nil {
		t.Error("expected error for zero offset")
	}
}

func TestReadFlowPackets(t *testing.T) {
	pcapPath := findTestPcap(t)

	needsIndex, _ := ingest.NeedsReindex(pcapPath)
	if needsIndex {
		_, err := ingest.IndexFile(pcapPath, nil)
		if err != nil {
			t.Fatalf("index: %v", err)
		}
	}

	engine, err := query.NewFromPcap(pcapPath)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer engine.Close()

	// Get first flow
	flows, err := engine.GetFlows(t.Context(), query.FlowFilter{Limit: 1})
	if err != nil || len(flows) == 0 {
		t.Skip("no flows in test pcap")
	}

	// Get flow packets
	pkts, err := engine.GetFlowPackets(t.Context(), flows[0].ID, 10)
	if err != nil || len(pkts) == 0 {
		t.Skip("no packets in flow")
	}

	// Check at least one has an offset
	hasOffset := false
	for _, p := range pkts {
		if p.Evidence.FileOffset > 0 {
			hasOffset = true
			break
		}
	}
	if !hasOffset {
		t.Skip("no packets with file offsets")
	}

	reader := NewReader(pcapPath, nil)
	infos, err := reader.ReadFlowPackets(pkts)
	if err != nil {
		t.Fatalf("ReadFlowPackets: %v", err)
	}
	if len(infos) == 0 {
		t.Error("expected at least one PacketInfo")
	}
}
