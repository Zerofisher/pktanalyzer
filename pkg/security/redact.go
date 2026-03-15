package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// RedactConfig controls output redaction.
type RedactConfig struct {
	Enabled         bool
	RedactIPs       bool
	RedactMACs      bool
	RedactHTTPCreds bool
	RedactQuery     bool
}

var (
	ipv4Regex       = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)
	ipv6Regex       = regexp.MustCompile(`([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)`)
	macRegex        = regexp.MustCompile(`([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}`)
	authHeaderRegex = regexp.MustCompile(`(?i)(Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token):\s*(.+)`)
	queryParamRegex = regexp.MustCompile(`\?([^#\s]+)`)
)

var rfc1918_172 = func() *net.IPNet {
	_, cidr, _ := net.ParseCIDR("172.16.0.0/12")
	return cidr
}()

func hashShort(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:8]
}

func isPrivate172(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && rfc1918_172.Contains(parsed)
}

// RedactIP replaces an IP address with a hash-based pseudonym.
// Private IPs keep the first two octets for context.
func RedactIP(ip string) string {
	if ip == "" {
		return ip
	}
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "10.") || isPrivate172(ip) {
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			return fmt.Sprintf("%s.%s.x.x[%s]", parts[0], parts[1], hashShort(ip))
		}
	}
	return fmt.Sprintf("IP[%s]", hashShort(ip))
}

// RedactMAC replaces a MAC address with a hash-based pseudonym.
// Keeps the OUI (first 3 octets) for vendor identification.
func RedactMAC(mac string) string {
	if mac == "" {
		return mac
	}
	parts := strings.Split(mac, ":")
	if len(parts) == 6 {
		return fmt.Sprintf("%s:%s:%s:xx:xx:xx[%s]", parts[0], parts[1], parts[2], hashShort(mac))
	}
	return fmt.Sprintf("MAC[%s]", hashShort(mac))
}

// RedactHTTPHeader redacts sensitive HTTP headers.
func RedactHTTPHeader(header string) string {
	return authHeaderRegex.ReplaceAllStringFunc(header, func(match string) string {
		parts := authHeaderRegex.FindStringSubmatch(match)
		if len(parts) >= 3 {
			return fmt.Sprintf("%s: [REDACTED-%s]", parts[1], hashShort(parts[2]))
		}
		return match
	})
}

// RedactQueryParams redacts URL query parameters.
func RedactQueryParams(url string) string {
	return queryParamRegex.ReplaceAllStringFunc(url, func(match string) string {
		return fmt.Sprintf("?[PARAMS-REDACTED-%s]", hashShort(match))
	})
}

// RedactText applies configured redactions to a text string.
func RedactText(text string, cfg *RedactConfig) string {
	if cfg == nil || !cfg.Enabled {
		return text
	}
	result := text
	if cfg.RedactIPs {
		result = ipv4Regex.ReplaceAllStringFunc(result, RedactIP)
		result = ipv6Regex.ReplaceAllStringFunc(result, func(ip string) string {
			return fmt.Sprintf("IPv6[%s]", hashShort(ip))
		})
	}
	if cfg.RedactMACs {
		result = macRegex.ReplaceAllStringFunc(result, RedactMAC)
	}
	if cfg.RedactHTTPCreds {
		result = RedactHTTPHeader(result)
	}
	if cfg.RedactQuery {
		result = RedactQueryParams(result)
	}
	return result
}

// RedactConfigFromSecurityConfig builds a RedactConfig from the main security Config.
func RedactConfigFromSecurityConfig(cfg *Config) *RedactConfig {
	return &RedactConfig{
		Enabled:         cfg.RedactIPs || cfg.RedactMACs || cfg.RedactCreds,
		RedactIPs:       cfg.RedactIPs,
		RedactMACs:      cfg.RedactMACs,
		RedactHTTPCreds: cfg.RedactCreds,
		RedactQuery:     cfg.RedactCreds, // redact query params when creds redaction is on
	}
}
