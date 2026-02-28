package format

import "fmt"

// FormatBytes formats a byte count to a human-readable string (KB/MB/GB).
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// FormatBits formats a bit rate to a human-readable string (kbps/Mbps/Gbps).
func FormatBits(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d bps", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cbps", float64(b)/float64(div), "kMGTPE"[exp])
}
