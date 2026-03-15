// Package security provides parameter validation, rate limiting, and output
// redaction for the MCP server layer.
package security

// Config holds all security settings, configured at server startup via CLI flags.
type Config struct {
	// Parameter limits
	MaxLimit     int // Max items per query (default 200)
	MaxOffset    int // Max offset value (default 10000)
	MaxStringLen int // Max filter string length (default 500)

	// Raw data access
	EnableRaw   bool // Allow raw packet data access (default false)
	RawMaxBytes int  // Max raw bytes per packet (default 1024)

	// TLS decryption
	KeylogFile string // Path to SSLKEYLOGFILE (default "")

	// Output redaction
	RedactIPs   bool // Redact IP addresses (default false)
	RedactMACs  bool // Redact MAC addresses (default false)
	RedactCreds bool // Redact HTTP credentials (default false)

	// Rate limiting
	RateLimit int // Max tool calls per minute (default 100)
}

// DefaultConfig returns a Config with safe defaults.
func DefaultConfig() *Config {
	return &Config{
		MaxLimit:     200,
		MaxOffset:    10000,
		MaxStringLen: 500,
		EnableRaw:    false,
		RawMaxBytes:  1024,
		RedactIPs:    false,
		RedactMACs:   false,
		RedactCreds:  false,
		RateLimit:    100,
	}
}
