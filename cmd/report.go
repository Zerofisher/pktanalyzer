package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Zerofisher/pktanalyzer/internal/report"
	"github.com/Zerofisher/pktanalyzer/pkg/ingest"
	"github.com/Zerofisher/pktanalyzer/pkg/query"
	"github.com/Zerofisher/pktanalyzer/pkg/store/sqlite"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:     "report [pcap file]",
	Short:   "Generate analysis report from pcap file",
	Long:    `Generate a Markdown analysis report from an indexed pcap file.`,
	GroupID: "analysis",
	Args:    cobra.ExactArgs(1),
	RunE:    runReport,
}

var (
	reportFormat string
	reportOutput string
)

func init() {
	reportCmd.Flags().StringVarP(&reportFormat, "format", "f", "markdown", "Output format: markdown, html, json")
	reportCmd.Flags().StringVarP(&reportOutput, "output", "o", "", "Output file (default: stdout)")
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	pcapPath := args[0]

	// Check if pcap exists
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", pcapPath)
	}

	// Check if needs indexing
	needsIndex, err := ingest.NeedsReindex(pcapPath)
	if err != nil {
		return fmt.Errorf("check index: %w", err)
	}

	if needsIndex {
		fmt.Fprintf(os.Stderr, "Indexing %s...\n", pcapPath)
		result, err := ingest.IndexFile(pcapPath, func(processed, total int, elapsed time.Duration) {
			fmt.Fprintf(os.Stderr, "\rProcessed %d packets (%.1f pkt/s)", processed, float64(processed)/elapsed.Seconds())
		})
		if err != nil {
			return fmt.Errorf("index file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "\nIndexed %d packets, %d flows in %v\n", result.TotalPackets, result.TotalFlows, result.Duration.Round(time.Millisecond))
	}

	// Open query engine
	store, err := sqlite.NewFromPcap(pcapPath, true)
	if err != nil {
		return fmt.Errorf("open index: %w", err)
	}
	defer store.Close()

	engine := query.NewSQLiteEngine(store, pcapPath)
	ctx := context.Background()

	// Generate report
	data, err := report.Generate(ctx, engine)
	if err != nil {
		return fmt.Errorf("generate report: %w", err)
	}

	// Output
	var out *os.File
	if reportOutput == "" || reportOutput == "-" {
		out = os.Stdout
	} else {
		out, err = os.Create(reportOutput)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer out.Close()
	}

	switch reportFormat {
	case "markdown", "md":
		return report.WriteMarkdown(out, data)
	case "json":
		return fmt.Errorf("JSON format not yet implemented")
	case "html":
		return fmt.Errorf("HTML format not yet implemented")
	default:
		return fmt.Errorf("unknown format: %s", reportFormat)
	}
}
