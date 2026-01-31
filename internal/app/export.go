package app

import (
	"fmt"
	"io"

	"github.com/Zerofisher/pktanalyzer/export"
)

// ExportConfig holds export configuration.
type ExportConfig struct {
	CaptureConfig
	DisplayFilter string
	Format        export.OutputFormat
	MaxCount      int
	ShowDetail    bool
	ShowHex       bool
	Fields        []string
}

// RunExport executes the export flow: capture -> filter -> export.
func RunExport(out io.Writer, cfg ExportConfig) error {
	// 1. Setup capturer
	result, err := SetupCapturer(cfg.CaptureConfig)
	if err != nil {
		return err
	}
	capturer := result.Capturer
	defer capturer.Stop()

	// 2. Compile display filter
	filterFunc, err := CompileDisplayFilter(cfg.DisplayFilter)
	if err != nil {
		return fmt.Errorf("error compiling display filter: %w", err)
	}

	// 3. Create exporter
	exporter := export.NewExporter(out, cfg.Format)
	exporter.SetMaxCount(cfg.MaxCount)

	if cfg.Format == export.FormatText {
		exporter.SetShowDetail(cfg.ShowDetail)
		exporter.SetShowHex(cfg.ShowHex)
	}
	if cfg.Format == export.FormatFields {
		exporter.SetFields(cfg.Fields)
	}

	if err := exporter.Start(); err != nil {
		return fmt.Errorf("error starting export: %w", err)
	}

	// 4. Process packets
	for pkt := range capturer.Start() {
		if filterFunc != nil && !filterFunc(&pkt) {
			continue
		}
		if err := exporter.ExportPacket(&pkt); err != nil {
			return fmt.Errorf("error exporting packet: %w", err)
		}
		if exporter.ShouldStop() {
			break
		}
	}

	return exporter.Finish()
}

// ValidateFields checks if required fields are provided for fields export.
func ValidateFields(fields []string) error {
	if len(fields) == 0 {
		return fmt.Errorf("at least one field must be specified with -e")
	}
	return nil
}
