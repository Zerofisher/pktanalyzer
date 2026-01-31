package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/expert"
	"github.com/Zerofisher/pktanalyzer/internal/app"
	"github.com/Zerofisher/pktanalyzer/stats"
	"github.com/spf13/cobra"
)

// stats command flags
var (
	statsInputFile     string
	statsDisplayFilter string
)

var statsCmd = &cobra.Command{
	Use:     "stats",
	Short:   "Packet statistics and analysis",
	Long:    `Analyze packets and display various statistics.`,
	GroupID: "analysis",
}

// endpoints subcommand flags
var statsEndpointsType string

var statsEndpointsCmd = &cobra.Command{
	Use:   "endpoints",
	Short: "Show endpoint statistics",
	Long:  `Display statistics about network endpoints (IP addresses).`,
	Example: `  pktanalyzer stats endpoints -r capture.pcap
  pktanalyzer stats endpoints -r capture.pcap --type ip`,
	RunE: runStatsEndpoints,
}

// conversations subcommand flags
var statsConversationsProto string

var statsConversationsCmd = &cobra.Command{
	Use:   "conversations",
	Short: "Show conversation statistics",
	Long:  `Display statistics about network conversations (connections between endpoints).`,
	Example: `  pktanalyzer stats conversations -r capture.pcap
  pktanalyzer stats conversations -r capture.pcap --proto tcp
  pktanalyzer stats conversations -r capture.pcap --proto udp`,
	RunE: runStatsConversations,
}

// io subcommand flags
var statsIOInterval float64

var statsIOCmd = &cobra.Command{
	Use:   "io",
	Short: "Show I/O statistics",
	Long:  `Display I/O statistics showing packet/byte rates over time.`,
	Example: `  pktanalyzer stats io -r capture.pcap
  pktanalyzer stats io -r capture.pcap --interval 2`,
	RunE: runStatsIO,
}

// expert subcommand flags
var statsExpertSeverity string

var statsExpertCmd = &cobra.Command{
	Use:   "expert",
	Short: "Expert analysis (anomaly detection)",
	Long: `Perform expert analysis to detect anomalies and potential issues in the capture.
Detects: TCP retransmissions, out-of-order packets, zero windows, RST packets, etc.`,
	Example: `  pktanalyzer stats expert -r capture.pcap
  pktanalyzer stats expert -r capture.pcap --severity warning`,
	RunE: runStatsExpert,
}

func init() {
	// Persistent flags for stats command (inherited by all subcommands)
	statsCmd.PersistentFlags().StringVarP(&statsInputFile, "read", "r", "",
		"Input pcap file (required)")
	statsCmd.PersistentFlags().StringVarP(&statsDisplayFilter, "filter", "Y", "",
		"Display filter expression")
	statsCmd.MarkPersistentFlagRequired("read")

	// endpoints flags
	statsEndpointsCmd.Flags().StringVar(&statsEndpointsType, "type", "ip",
		"Endpoint type: ip or eth")

	// conversations flags
	statsConversationsCmd.Flags().StringVar(&statsConversationsProto, "proto", "tcp",
		"Protocol: tcp or udp")

	// io flags
	statsIOCmd.Flags().Float64Var(&statsIOInterval, "interval", 1.0,
		"Statistics interval in seconds")

	// expert flags
	statsExpertCmd.Flags().StringVar(&statsExpertSeverity, "severity", "note",
		"Minimum severity level: chat, note, warning, error")

	// Add subcommands
	statsCmd.AddCommand(statsEndpointsCmd)
	statsCmd.AddCommand(statsConversationsCmd)
	statsCmd.AddCommand(statsIOCmd)
	statsCmd.AddCommand(statsExpertCmd)
}

// setupStatsCapturer creates a capturer for stats analysis
func setupStatsCapturer() (*capture.Capturer, func(*capture.PacketInfo) bool, error) {
	capturer, err := capture.NewFileCapturer(statsInputFile, "")
	if err != nil {
		return nil, nil, fmt.Errorf("error opening file: %w", err)
	}

	filterFunc, err := app.CompileDisplayFilter(statsDisplayFilter)
	if err != nil {
		capturer.Stop()
		return nil, nil, fmt.Errorf("error compiling display filter: %w", err)
	}

	return capturer, filterFunc, nil
}

// runStatsEndpoints shows endpoint statistics
func runStatsEndpoints(cmd *cobra.Command, args []string) error {
	capturer, filterFunc, err := setupStatsCapturer()
	if err != nil {
		return err
	}

	statsMgr := stats.NewManager()
	packetChan := capturer.Start()

	for pkt := range packetChan {
		if filterFunc != nil && !filterFunc(&pkt) {
			continue
		}
		statsMgr.ProcessPacket(&pkt)
	}

	statsMgr.PrintEndpoints(os.Stdout, statsEndpointsType)
	capturer.Stop()
	return nil
}

// runStatsConversations shows conversation statistics
func runStatsConversations(cmd *cobra.Command, args []string) error {
	capturer, filterFunc, err := setupStatsCapturer()
	if err != nil {
		return err
	}

	statsMgr := stats.NewManager()
	packetChan := capturer.Start()

	for pkt := range packetChan {
		if filterFunc != nil && !filterFunc(&pkt) {
			continue
		}
		statsMgr.ProcessPacket(&pkt)
	}

	statsMgr.PrintConversations(os.Stdout, statsConversationsProto)
	capturer.Stop()
	return nil
}

// runStatsIO shows I/O statistics
func runStatsIO(cmd *cobra.Command, args []string) error {
	capturer, filterFunc, err := setupStatsCapturer()
	if err != nil {
		return err
	}

	statsMgr := stats.NewManager()
	statsMgr.SetBucketSize(time.Duration(statsIOInterval * float64(time.Second)))
	packetChan := capturer.Start()

	for pkt := range packetChan {
		if filterFunc != nil && !filterFunc(&pkt) {
			continue
		}
		statsMgr.ProcessPacket(&pkt)
	}

	statsMgr.PrintIOStats(os.Stdout, statsIOInterval)
	capturer.Stop()
	return nil
}

// runStatsExpert performs expert analysis
func runStatsExpert(cmd *cobra.Command, args []string) error {
	capturer, filterFunc, err := setupStatsCapturer()
	if err != nil {
		return err
	}

	// Parse severity level
	var minSeverity expert.Severity
	switch statsExpertSeverity {
	case "chat":
		minSeverity = expert.SeverityChat
	case "note":
		minSeverity = expert.SeverityNote
	case "warning", "warn":
		minSeverity = expert.SeverityWarning
	case "error":
		minSeverity = expert.SeverityError
	default:
		capturer.Stop()
		return fmt.Errorf("unknown severity level: %s (use: chat, note, warning, error)", statsExpertSeverity)
	}

	analyzer := expert.NewAnalyzer()
	packetChan := capturer.Start()
	packetCount := 0

	for pkt := range packetChan {
		packetCount++
		if filterFunc != nil && !filterFunc(&pkt) {
			continue
		}
		analyzer.Analyze(&pkt)
	}

	fmt.Printf("Analyzed %d packets\n\n", packetCount)
	analyzer.PrintSummary(os.Stdout)
	fmt.Println()
	analyzer.PrintDetails(os.Stdout, minSeverity)
	capturer.Stop()
	return nil
}
