package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/stream"
	"github.com/spf13/cobra"
)

// follow command flags
var (
	followInputFile string
	followFormat    string
	followProto     string
)

var followCmd = &cobra.Command{
	Use:   "follow <stream-id>",
	Short: "Follow and display a TCP stream",
	Long: `Follow a specific TCP stream and display its reassembled content.
Stream IDs can be found by analyzing packets with stream reassembly enabled.`,
	Example: `  pktanalyzer follow 1 -r capture.pcap
  pktanalyzer follow 1 -r capture.pcap --format hex
  pktanalyzer follow 1 -r capture.pcap --format raw > stream.bin`,
	Args:    cobra.ExactArgs(1),
	GroupID: "analysis",
	RunE:    runFollow,
}

func init() {
	followCmd.Flags().StringVarP(&followInputFile, "read", "r", "",
		"Input pcap file (required)")
	followCmd.Flags().StringVar(&followFormat, "format", "ascii",
		"Output format: ascii, hex, or raw")
	followCmd.Flags().StringVar(&followProto, "proto", "tcp",
		"Protocol (currently only tcp is supported)")
	followCmd.MarkFlagRequired("read")
}

// runFollow displays a TCP stream's content
func runFollow(cmd *cobra.Command, args []string) error {
	// Parse stream ID
	streamID, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid stream ID: %s", args[0])
	}

	// Validate protocol
	if followProto != "tcp" {
		return fmt.Errorf("only TCP follow is supported. Use: --proto tcp")
	}

	// Validate format
	if followFormat != "ascii" && followFormat != "hex" && followFormat != "raw" {
		return fmt.Errorf("unsupported format: %s. Use: ascii, hex, or raw", followFormat)
	}

	// Create capturer with stream reassembly enabled
	capturer, err := capture.NewFileCapturer(followInputFile, "")
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}

	streamMgr := stream.NewStreamManager()
	capturer.SetStreamManager(streamMgr)

	// Process all packets to build streams
	packetChan := capturer.Start()
	for range packetChan {
		// Just consume packets to trigger stream reassembly
	}

	// Find the target stream
	targetStream := streamMgr.GetStreamByID(streamID)
	if targetStream == nil {
		streams := streamMgr.GetStreams()
		fmt.Fprintf(os.Stderr, "Stream #%d not found. Available streams:\n", streamID)
		for _, s := range streams {
			fmt.Fprintf(os.Stderr, "  #%d: %s <-> %s (%d bytes)\n",
				s.ID, s.ClientAddr, s.ServerAddr, s.TotalBytes())
		}
		capturer.Stop()
		return fmt.Errorf("stream not found")
	}

	// Print stream header
	fmt.Printf("================================================================================\n")
	fmt.Printf("Follow TCP Stream #%d\n", targetStream.ID)
	fmt.Printf("================================================================================\n")
	fmt.Printf("Client: %s\n", targetStream.ClientAddr)
	fmt.Printf("Server: %s\n", targetStream.ServerAddr)
	fmt.Printf("State:  %s\n", targetStream.State)
	fmt.Printf("================================================================================\n\n")

	// Output the stream data
	clientData := targetStream.GetClientData()
	serverData := targetStream.GetServerData()

	switch followFormat {
	case "ascii":
		if len(clientData) > 0 {
			fmt.Println("=== Client -> Server ===")
			printASCII(clientData)
			fmt.Println()
		}
		if len(serverData) > 0 {
			fmt.Println("=== Server -> Client ===")
			printASCII(serverData)
			fmt.Println()
		}

	case "hex":
		if len(clientData) > 0 {
			fmt.Println("=== Client -> Server ===")
			printHexDump(clientData)
			fmt.Println()
		}
		if len(serverData) > 0 {
			fmt.Println("=== Server -> Client ===")
			printHexDump(serverData)
			fmt.Println()
		}

	case "raw":
		os.Stdout.Write(clientData)
		os.Stdout.Write(serverData)
		capturer.Stop()
		return nil // Skip footer for raw output
	}

	fmt.Printf("================================================================================\n")
	fmt.Printf("Total: Client sent %d bytes, Server sent %d bytes\n", len(clientData), len(serverData))
	capturer.Stop()
	return nil
}

// printASCII prints data in ASCII format, replacing non-printable chars with dots
func printASCII(data []byte) {
	for _, b := range data {
		if b >= 32 && b <= 126 {
			fmt.Printf("%c", b)
		} else if b == '\n' || b == '\r' || b == '\t' {
			fmt.Printf("%c", b)
		} else {
			fmt.Print(".")
		}
	}
}

// printHexDump prints data in hex dump format
func printHexDump(data []byte) {
	bytesPerLine := 16
	for i := 0; i < len(data); i += bytesPerLine {
		// Offset
		fmt.Printf("%08x  ", i)

		// Hex bytes
		for j := 0; j < bytesPerLine; j++ {
			if i+j < len(data) {
				fmt.Printf("%02x ", data[i+j])
			} else {
				fmt.Print("   ")
			}
			if j == 7 {
				fmt.Print(" ")
			}
		}

		// ASCII
		fmt.Print(" |")
		for j := 0; j < bytesPerLine && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}
