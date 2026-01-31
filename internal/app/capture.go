// Package app provides application-level orchestration for pktanalyzer.
package app

import (
	"fmt"
	"os"

	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/filter"
	"github.com/Zerofisher/pktanalyzer/stream"
	"github.com/Zerofisher/pktanalyzer/tls"
)

// CaptureConfig holds unified capture configuration.
type CaptureConfig struct {
	Source        string // File path or interface name
	IsLive        bool   // true=interface, false=file
	BPFFilter     string
	KeylogFile    string
	EnableStreams bool
}

// CaptureResult holds the result of SetupCapturer.
type CaptureResult struct {
	Capturer  *capture.Capturer
	Decryptor *tls.Decryptor
}

// SetupCapturer creates and configures a Capturer based on the given config.
func SetupCapturer(cfg CaptureConfig) (*CaptureResult, error) {
	var capturer *capture.Capturer
	var err error

	if cfg.IsLive {
		capturer, err = capture.NewLiveCapturer(cfg.Source, cfg.BPFFilter)
	} else {
		capturer, err = capture.NewFileCapturer(cfg.Source, cfg.BPFFilter)
	}
	if err != nil {
		return nil, fmt.Errorf("error opening source: %w", err)
	}

	result := &CaptureResult{Capturer: capturer}

	// Load TLS key log if specified
	if cfg.KeylogFile != "" {
		keyLog, err := tls.LoadKeyLogFile(cfg.KeylogFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to load key log file: %v\n", err)
		} else {
			result.Decryptor = tls.NewDecryptor(keyLog)
			capturer.SetDecryptor(result.Decryptor)
		}
	}

	// Enable stream reassembly if requested
	if cfg.EnableStreams {
		capturer.SetStreamManager(stream.NewStreamManager())
	}

	return result, nil
}

// CompileDisplayFilter compiles a display filter expression.
// Returns nil filter function if filterStr is empty.
func CompileDisplayFilter(filterStr string) (func(*capture.PacketInfo) bool, error) {
	if filterStr == "" {
		return nil, nil
	}
	return filter.Compile(filterStr)
}
