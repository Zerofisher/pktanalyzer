// Package agent provides security constraints for AI agent tools
package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Security limits - prevent token explosion and DoS
const (
	MaxLimit        = 50   // Maximum packets/results per query
	MaxOffset       = 1000 // Maximum offset value
	MaxStringLen    = 200  // Maximum filter string length (contains/url/domain)
	MaxRawBytes     = 256  // Maximum raw bytes when include_raw=true
	DefaultRawBytes = 0    // Default: no raw bytes
	MaxInfoLen      = 100  // Maximum Info field length in output
)

// RedactConfig controls what data types are redacted
type RedactConfig struct {
	Enabled    bool // Master switch
	RedactIPs  bool // Redact IP addresses
	RedactMACs bool // Redact MAC addresses
	// RedactDomains   bool // Redact domain names  // unused for now
	RedactHTTPCreds bool // Redact HTTP Authorization/Cookie
	RedactQuery     bool // Redact URL query parameters
}

// DefaultRedactConfig returns default redaction settings (all enabled)
func DefaultRedactConfig() *RedactConfig {
	return &RedactConfig{
		Enabled:    true,
		RedactIPs:  true,
		RedactMACs: true,
		// RedactDomains:   false, // Usually needed for analysis
		RedactHTTPCreds: true,
		RedactQuery:     true,
	}
}

// Evidence tracks packet/connection references for AI conclusions
type Evidence struct {
	PacketIDs    []int    // Related packet numbers
	Connections  []string // Related connection keys (IP:port-IP:port)
	StreamIDs    []int    // Related stream IDs
	Summary      string   // Brief summary of what was found
	EvidenceType string   // Type: "anomaly", "connection", "dns", "http", etc.
}

// FormatEvidence formats evidence for tool output
func (e *Evidence) Format() string {
	if e == nil || (len(e.PacketIDs) == 0 && len(e.Connections) == 0 && len(e.StreamIDs) == 0) {
		return ""
	}

	var parts []string

	if len(e.PacketIDs) > 0 {
		// Limit to first 20 packet IDs to avoid output explosion
		pktIDs := e.PacketIDs
		if len(pktIDs) > 20 {
			pktIDs = pktIDs[:20]
		}
		parts = append(parts, fmt.Sprintf("packets=%v", pktIDs))
		if len(e.PacketIDs) > 20 {
			parts = append(parts, fmt.Sprintf("(+%d more)", len(e.PacketIDs)-20))
		}
	}

	if len(e.Connections) > 0 {
		conns := e.Connections
		if len(conns) > 10 {
			conns = conns[:10]
		}
		parts = append(parts, fmt.Sprintf("connections=%v", conns))
		if len(e.Connections) > 10 {
			parts = append(parts, fmt.Sprintf("(+%d more)", len(e.Connections)-10))
		}
	}

	if len(e.StreamIDs) > 0 {
		parts = append(parts, fmt.Sprintf("streams=%v", e.StreamIDs))
	}

	return fmt.Sprintf("\n\nEvidence: %s", strings.Join(parts, ", "))
}

// --- Redaction functions ---

var (
	ipv4Regex = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)
	ipv6Regex = regexp.MustCompile(`([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)`)
	macRegex  = regexp.MustCompile(`([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}`)
	// credRegex matches common credential patterns in HTTP headers
	authHeaderRegex  = regexp.MustCompile(`(?i)(Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token):\s*(.+)`)
	queryParamsRegex = regexp.MustCompile(`\?([^#\s]+)`)
)

// hashShort returns first 8 chars of SHA256 hash for anonymization
func hashShort(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:8]
}

// RedactIP replaces IP with hash-based pseudonym
func RedactIP(ip string) string {
	if ip == "" {
		return ip
	}
	// Keep localhost/private network indicators
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") {
		// Keep first octet(s) for context, hash the rest
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			return fmt.Sprintf("%s.%s.x.x[%s]", parts[0], parts[1], hashShort(ip))
		}
	}
	return fmt.Sprintf("IP[%s]", hashShort(ip))
}

// RedactMAC replaces MAC address with hash-based pseudonym
func RedactMAC(mac string) string {
	if mac == "" {
		return mac
	}
	// Keep OUI (first 3 octets) for vendor identification
	parts := strings.Split(mac, ":")
	if len(parts) == 6 {
		return fmt.Sprintf("%s:%s:%s:xx:xx:xx[%s]", parts[0], parts[1], parts[2], hashShort(mac))
	}
	return fmt.Sprintf("MAC[%s]", hashShort(mac))
}

// RedactHTTPHeader redacts sensitive HTTP headers
func RedactHTTPHeader(header string) string {
	return authHeaderRegex.ReplaceAllStringFunc(header, func(match string) string {
		parts := authHeaderRegex.FindStringSubmatch(match)
		if len(parts) >= 2 {
			return fmt.Sprintf("%s: [REDACTED-%s]", parts[1], hashShort(parts[2]))
		}
		return match
	})
}

// RedactQueryParams redacts URL query parameters
func RedactQueryParams(url string) string {
	return queryParamsRegex.ReplaceAllStringFunc(url, func(match string) string {
		return fmt.Sprintf("?[PARAMS-REDACTED-%s]", hashShort(match))
	})
}

// RedactText applies all configured redactions to a text string
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

// --- Parameter validation ---

// ClampInt clamps a value between min and max
func ClampInt(val, min, max int) int {
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}

// ClampString truncates string to max length
func ClampString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ValidateLimit validates and clamps limit parameter
func ValidateLimit(input map[string]interface{}) int {
	limit := 20 // default
	if v, ok := input["limit"].(float64); ok {
		limit = ClampInt(int(v), 1, MaxLimit)
	}
	return limit
}

// ValidateOffset validates and clamps offset parameter
func ValidateOffset(input map[string]interface{}) int {
	offset := 0 // default
	if v, ok := input["offset"].(float64); ok {
		offset = ClampInt(int(v), 0, MaxOffset)
	}
	return offset
}

// ValidateStringParam validates and clamps string parameters
func ValidateStringParam(input map[string]interface{}, key string) string {
	if v, ok := input[key].(string); ok {
		return ClampString(v, MaxStringLen)
	}
	return ""
}

// --- Tool output safety ---

// TruncateInfo safely truncates Info field for output
func TruncateInfo(info string) string {
	if len(info) <= MaxInfoLen {
		return info
	}
	return info[:MaxInfoLen] + "..."
}

// SanitizeToolOutput applies all safety measures to tool output
func SanitizeToolOutput(output string, redactCfg *RedactConfig) string {
	// Apply redaction if configured
	result := RedactText(output, redactCfg)
	return result
}

// --- Raw data control ---

// RawDataPolicy controls how raw packet data is handled
type RawDataPolicy struct {
	AllowRaw        bool // Whether raw data is allowed at all
	MaxBytes        int  // Maximum bytes to include
	RequireExplicit bool // Require explicit user authorization
}

// DefaultRawDataPolicy returns conservative defaults
func DefaultRawDataPolicy() *RawDataPolicy {
	return &RawDataPolicy{
		AllowRaw:        false,
		MaxBytes:        0,
		RequireExplicit: true,
	}
}

// --- Authorization confirmation system ---

// AuthorizationType defines the type of authorization needed
type AuthorizationType string

const (
	AuthTypeRawData AuthorizationType = "raw_data" // Access to raw packet data (hex dump)
	// Future: AuthTypeExport, AuthTypeCapture, etc.
)

// ConfirmationRequest represents a pending authorization request from AI
type ConfirmationRequest struct {
	Type        AuthorizationType      // Type of authorization needed
	ToolName    string                 // Tool that requested authorization
	Description string                 // Human-readable description
	Context     map[string]interface{} // Context data (e.g., packet number)
	Granted     bool                   // Whether authorization was granted
	Responded   bool                   // Whether user has responded
}

// NewConfirmationRequest creates a new confirmation request
func NewConfirmationRequest(authType AuthorizationType, toolName string, ctx map[string]interface{}) *ConfirmationRequest {
	var desc string
	switch authType {
	case AuthTypeRawData:
		pktNum := 0
		if v, ok := ctx["packet_number"].(int); ok {
			pktNum = v
		}
		desc = fmt.Sprintf("AI 请求显示数据包 #%d 的原始数据 (hex dump)，可能包含敏感信息", pktNum)
	default:
		desc = "AI 请求执行敏感操作"
	}

	return &ConfirmationRequest{
		Type:        authType,
		ToolName:    toolName,
		Description: desc,
		Context:     ctx,
		Granted:     false,
		Responded:   false,
	}
}

// AuthorizationStore manages pending authorizations with session-based grants
type AuthorizationStore struct {
	pendingRequest *ConfirmationRequest       // Current pending request
	sessionGrants  map[AuthorizationType]bool // Grants for this session
}

// NewAuthorizationStore creates a new authorization store
func NewAuthorizationStore() *AuthorizationStore {
	return &AuthorizationStore{
		sessionGrants: make(map[AuthorizationType]bool),
	}
}

// RequestAuthorization creates a pending authorization request
func (s *AuthorizationStore) RequestAuthorization(authType AuthorizationType, toolName string, ctx map[string]interface{}) *ConfirmationRequest {
	// Check if already granted for this session
	if s.sessionGrants[authType] {
		return &ConfirmationRequest{
			Type:      authType,
			Granted:   true,
			Responded: true,
		}
	}

	s.pendingRequest = NewConfirmationRequest(authType, toolName, ctx)
	return s.pendingRequest
}

// GetPendingRequest returns the current pending request (nil if none)
func (s *AuthorizationStore) GetPendingRequest() *ConfirmationRequest {
	return s.pendingRequest
}

// GrantAuthorization grants the pending authorization
func (s *AuthorizationStore) GrantAuthorization(forSession bool) {
	if s.pendingRequest != nil {
		s.pendingRequest.Granted = true
		s.pendingRequest.Responded = true

		// If granted for session, remember it
		if forSession {
			s.sessionGrants[s.pendingRequest.Type] = true
		}
	}
}

// GrantSessionAuthorization directly grants session-wide authorization for a type
// Used for pre-authorizing before any request is made
func (s *AuthorizationStore) GrantSessionAuthorization(authType AuthorizationType) {
	s.sessionGrants[authType] = true
}

// DenyAuthorization denies the pending authorization
func (s *AuthorizationStore) DenyAuthorization() {
	if s.pendingRequest != nil {
		s.pendingRequest.Granted = false
		s.pendingRequest.Responded = true
	}
}

// ClearPendingRequest clears the pending request after handling
func (s *AuthorizationStore) ClearPendingRequest() {
	s.pendingRequest = nil
}

// IsAuthorized checks if an authorization type is granted (session-wide)
func (s *AuthorizationStore) IsAuthorized(authType AuthorizationType) bool {
	return s.sessionGrants[authType]
}

// ClearSessionGrants clears all session grants (e.g., on conversation reset)
func (s *AuthorizationStore) ClearSessionGrants() {
	s.sessionGrants = make(map[AuthorizationType]bool)
}

// CheckRawDataAuthorization checks if raw data can be returned
// Returns: (allowed, maxBytes, errorMessage, needsConfirmation)
func CheckRawDataAuthorization(userInput string, includeRaw bool, authStore *AuthorizationStore) (bool, int, string, bool) {
	if !includeRaw {
		return false, 0, "", false
	}

	// First check session grants - if already authorized in this session, allow
	if authStore != nil && authStore.IsAuthorized(AuthTypeRawData) {
		return true, MaxRawBytes, "", false
	}

	// All include_raw=true requests require explicit user confirmation
	// This is more secure than keyword matching - user must actively approve
	return false, 0, "需要用户确认才能显示原始数据", true
}

// Legacy function for backward compatibility
func CheckRawDataAuthorizationLegacy(userInput string, includeRaw bool) (bool, int, string) {
	allowed, maxBytes, errMsg, _ := CheckRawDataAuthorization(userInput, includeRaw, nil)
	return allowed, maxBytes, errMsg
}
