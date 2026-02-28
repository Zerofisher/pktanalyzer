package report

import "github.com/Zerofisher/pktanalyzer/internal/format"

// FormatBytes formats bytes to a human-readable string with appropriate unit.
// Delegates to the shared implementation in internal/format.
func FormatBytes(b int64) string {
	return format.FormatBytes(b)
}
