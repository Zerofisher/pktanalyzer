package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zerofisher/pktanalyzer/pkg/ingest"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
	"github.com/Zerofisher/pktanalyzer/pkg/replay"
	"github.com/Zerofisher/pktanalyzer/pkg/security"
)

// findTestPcap locates a test pcap in examples/.
func findTestPcap(t *testing.T) string {
	t.Helper()
	dir, _ := os.Getwd()
	for i := 0; i < 5; i++ {
		pattern := filepath.Join(dir, "examples", "*.pcap")
		matches, _ := filepath.Glob(pattern)
		var classicPcaps []string
		for _, m := range matches {
			if !strings.HasSuffix(m, ".pcapng") {
				classicPcaps = append(classicPcaps, m)
			}
		}
		if len(classicPcaps) > 0 {
			return classicPcaps[0]
		}
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

// setupTestContext creates a ToolContext with a real pcap for integration tests.
func setupTestContext(t *testing.T) *ToolContext {
	t.Helper()
	pcapPath := findTestPcap(t)

	needsIndex, _ := ingest.NeedsReindex(pcapPath)
	if needsIndex {
		if _, err := ingest.IndexFile(pcapPath, nil); err != nil {
			t.Fatalf("index: %v", err)
		}
	}

	engine, err := query.NewFromPcap(pcapPath)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { engine.Close() })

	reader := replay.NewReader(pcapPath, nil)

	return &ToolContext{
		Query:    engine,
		Replay:   reader,
		Security: security.DefaultConfig(),
		PcapPath: pcapPath,
	}
}
