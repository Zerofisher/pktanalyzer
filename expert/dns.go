// Package expert provides DNS analysis and anomaly detection
package expert

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Zerofisher/pktanalyzer/capture"
)

// DNSAnalysisContext maintains state for DNS analysis
type DNSAnalysisContext struct {
	mu sync.RWMutex

	// Track pending queries (transaction ID -> query info)
	pendingQueries map[uint16]*DNSQueryRecord

	// Query timeout for detecting unanswered queries
	queryTimeout time.Duration
}

// DNSQueryRecord tracks a DNS query
type DNSQueryRecord struct {
	PacketNum int
	Timestamp time.Time
	QueryName string
	QueryType string
	SrcIP     string
	DstIP     string
	Checked   bool // Whether we've already reported this as unanswered
}

// DNSExpertType represents specific DNS expert info types
type DNSExpertType int

const (
	DNSQueryNoResponse DNSExpertType = iota
	DNSQueryNXDOMAIN
	DNSQuerySERVFAIL
	DNSQueryRefused
	DNSMalformedQuery
	DNSMalformedResponse
	DNSRetransmission
	DNSLongQuery
)

// String returns a human-readable description
func (t DNSExpertType) String() string {
	switch t {
	case DNSQueryNoResponse:
		return "DNS Query Without Response"
	case DNSQueryNXDOMAIN:
		return "DNS NXDOMAIN"
	case DNSQuerySERVFAIL:
		return "DNS SERVFAIL"
	case DNSQueryRefused:
		return "DNS Query Refused"
	case DNSMalformedQuery:
		return "Malformed DNS Query"
	case DNSMalformedResponse:
		return "Malformed DNS Response"
	case DNSRetransmission:
		return "DNS Retransmission"
	case DNSLongQuery:
		return "DNS Query Name Too Long"
	default:
		return "Unknown DNS Issue"
	}
}

// Severity returns the default severity for this DNS expert type
func (t DNSExpertType) Severity() Severity {
	switch t {
	case DNSQueryNXDOMAIN, DNSLongQuery:
		return SeverityNote
	case DNSQueryNoResponse, DNSQuerySERVFAIL, DNSRetransmission:
		return SeverityWarning
	case DNSQueryRefused, DNSMalformedQuery, DNSMalformedResponse:
		return SeverityError
	default:
		return SeverityNote
	}
}

// NewDNSAnalysisContext creates a new DNS analysis context
func NewDNSAnalysisContext() *DNSAnalysisContext {
	return &DNSAnalysisContext{
		pendingQueries: make(map[uint16]*DNSQueryRecord),
		queryTimeout:   time.Second * 5,
	}
}

// Analyze processes a DNS packet and returns any expert info
func (ctx *DNSAnalysisContext) Analyze(pkt *capture.PacketInfo) []*ExpertInfo {
	if pkt.Protocol != "DNS" {
		return nil
	}

	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	var results []*ExpertInfo

	// Parse DNS info from packet Info field
	isResponse := strings.HasPrefix(pkt.Info, "Response")
	isQuery := strings.HasPrefix(pkt.Info, "Query")

	if isQuery {
		// Extract transaction ID (simplified - in real implementation parse from raw data)
		queryResults := ctx.analyzeQuery(pkt)
		results = append(results, queryResults...)
	} else if isResponse {
		// Analyze response
		responseResults := ctx.analyzeResponse(pkt)
		results = append(results, responseResults...)
	}

	// Check for timed-out queries
	timeoutResults := ctx.checkTimeouts(pkt.Timestamp)
	results = append(results, timeoutResults...)

	return results
}

// analyzeQuery processes a DNS query
func (ctx *DNSAnalysisContext) analyzeQuery(pkt *capture.PacketInfo) []*ExpertInfo {
	var results []*ExpertInfo

	// Extract query name from Info field: "Query: example.com A"
	queryName := ""
	queryType := ""
	if strings.HasPrefix(pkt.Info, "Query: ") {
		parts := strings.SplitN(pkt.Info[7:], " ", 2)
		if len(parts) > 0 {
			queryName = parts[0]
		}
		if len(parts) > 1 {
			queryType = parts[1]
		}
	}

	// Check for very long query names (potential DNS tunneling or attack)
	if len(queryName) > 253 {
		results = append(results, &ExpertInfo{
			PacketNum: pkt.Number,
			Timestamp: pkt.Timestamp,
			Severity:  DNSLongQuery.Severity(),
			Group:     GroupProtocol,
			Protocol:  "DNS",
			Summary:   DNSLongQuery.String(),
			Details:   fmt.Sprintf("Query name length: %d bytes (max 253)", len(queryName)),
		})
	}

	// Check for empty query name
	if queryName == "" {
		results = append(results, &ExpertInfo{
			PacketNum: pkt.Number,
			Timestamp: pkt.Timestamp,
			Severity:  DNSMalformedQuery.Severity(),
			Group:     GroupMalformed,
			Protocol:  "DNS",
			Summary:   DNSMalformedQuery.String(),
			Details:   "Query with empty name",
		})
	}

	// Generate a simple hash-based ID for tracking (in real impl, parse actual DNS ID)
	txID := generateTxID(pkt)

	// Check for retransmission
	if existing, ok := ctx.pendingQueries[txID]; ok {
		if existing.QueryName == queryName && existing.SrcIP == pkt.SrcIP {
			results = append(results, &ExpertInfo{
				PacketNum:   pkt.Number,
				Timestamp:   pkt.Timestamp,
				Severity:    DNSRetransmission.Severity(),
				Group:       GroupSequence,
				Protocol:    "DNS",
				Summary:     DNSRetransmission.String(),
				Details:     fmt.Sprintf("Query for %s (original in #%d)", queryName, existing.PacketNum),
				RelatedPkts: []int{existing.PacketNum},
			})
		}
	}

	// Track this query
	ctx.pendingQueries[txID] = &DNSQueryRecord{
		PacketNum: pkt.Number,
		Timestamp: pkt.Timestamp,
		QueryName: queryName,
		QueryType: queryType,
		SrcIP:     pkt.SrcIP,
		DstIP:     pkt.DstIP,
	}

	return results
}

// analyzeResponse processes a DNS response
func (ctx *DNSAnalysisContext) analyzeResponse(pkt *capture.PacketInfo) []*ExpertInfo {
	var results []*ExpertInfo

	// Parse response info
	info := pkt.Info

	// Check for NXDOMAIN (Non-Existent Domain)
	if strings.Contains(info, "NXDOMAIN") || strings.Contains(info, "no such name") {
		queryName := extractQueryNameFromResponse(info)
		results = append(results, &ExpertInfo{
			PacketNum: pkt.Number,
			Timestamp: pkt.Timestamp,
			Severity:  DNSQueryNXDOMAIN.Severity(),
			Group:     GroupResponse,
			Protocol:  "DNS",
			Summary:   DNSQueryNXDOMAIN.String(),
			Details:   fmt.Sprintf("Domain does not exist: %s", queryName),
		})
	}

	// Check for SERVFAIL
	if strings.Contains(info, "SERVFAIL") || strings.Contains(info, "server failure") {
		results = append(results, &ExpertInfo{
			PacketNum: pkt.Number,
			Timestamp: pkt.Timestamp,
			Severity:  DNSQuerySERVFAIL.Severity(),
			Group:     GroupResponse,
			Protocol:  "DNS",
			Summary:   DNSQuerySERVFAIL.String(),
			Details:   "DNS server failed to process query",
		})
	}

	// Check for REFUSED
	if strings.Contains(info, "REFUSED") || strings.Contains(info, "refused") {
		results = append(results, &ExpertInfo{
			PacketNum: pkt.Number,
			Timestamp: pkt.Timestamp,
			Severity:  DNSQueryRefused.Severity(),
			Group:     GroupResponse,
			Protocol:  "DNS",
			Summary:   DNSQueryRefused.String(),
			Details:   "DNS server refused the query",
		})
	}

	// Mark corresponding query as answered
	txID := generateTxID(pkt)
	// For response, swap src/dst to find the original query
	if query, ok := ctx.pendingQueries[generateTxIDForResponse(pkt)]; ok {
		query.Checked = true
		delete(ctx.pendingQueries, generateTxIDForResponse(pkt))
	}
	// Also try direct match
	delete(ctx.pendingQueries, txID)

	return results
}

// checkTimeouts checks for queries that haven't received responses
func (ctx *DNSAnalysisContext) checkTimeouts(currentTime time.Time) []*ExpertInfo {
	var results []*ExpertInfo

	for txID, query := range ctx.pendingQueries {
		if query.Checked {
			continue
		}

		elapsed := currentTime.Sub(query.Timestamp)
		if elapsed > ctx.queryTimeout {
			results = append(results, &ExpertInfo{
				PacketNum: query.PacketNum,
				Timestamp: query.Timestamp,
				Severity:  DNSQueryNoResponse.Severity(),
				Group:     GroupResponse,
				Protocol:  "DNS",
				Summary:   DNSQueryNoResponse.String(),
				Details:   fmt.Sprintf("No response for %s %s after %v", query.QueryName, query.QueryType, elapsed.Round(time.Millisecond)),
			})
			query.Checked = true
			delete(ctx.pendingQueries, txID)
		}
	}

	return results
}

// CheckPendingQueries can be called at the end of capture to report any remaining unanswered queries
func (ctx *DNSAnalysisContext) CheckPendingQueries() []*ExpertInfo {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	var results []*ExpertInfo

	for _, query := range ctx.pendingQueries {
		if !query.Checked {
			results = append(results, &ExpertInfo{
				PacketNum: query.PacketNum,
				Timestamp: query.Timestamp,
				Severity:  DNSQueryNoResponse.Severity(),
				Group:     GroupResponse,
				Protocol:  "DNS",
				Summary:   DNSQueryNoResponse.String(),
				Details:   fmt.Sprintf("No response for %s %s (end of capture)", query.QueryName, query.QueryType),
			})
		}
	}

	return results
}

// Helper functions

func generateTxID(pkt *capture.PacketInfo) uint16 {
	// Simple hash based on packet attributes
	// In real implementation, parse actual DNS transaction ID from raw data
	hash := uint16(0)
	for _, c := range pkt.SrcIP {
		hash = hash*31 + uint16(c)
	}
	for _, c := range pkt.DstIP {
		hash = hash*31 + uint16(c)
	}
	for _, c := range pkt.Info {
		hash = hash*31 + uint16(c)
	}
	return hash
}

func generateTxIDForResponse(pkt *capture.PacketInfo) uint16 {
	// For response, swap src/dst
	hash := uint16(0)
	for _, c := range pkt.DstIP {
		hash = hash*31 + uint16(c)
	}
	for _, c := range pkt.SrcIP {
		hash = hash*31 + uint16(c)
	}
	// Response info is different, so use query name from response
	queryName := extractQueryNameFromResponse(pkt.Info)
	for _, c := range "Query: " + queryName {
		hash = hash*31 + uint16(c)
	}
	return hash
}

func extractQueryNameFromResponse(info string) string {
	// Try to extract domain name from response info
	// Format varies: "Response: example.com -> 1.2.3.4"
	if strings.HasPrefix(info, "Response: ") {
		rest := info[10:]
		if idx := strings.Index(rest, " ->"); idx > 0 {
			return rest[:idx]
		}
		if idx := strings.Index(rest, " "); idx > 0 {
			return rest[:idx]
		}
		return rest
	}
	return ""
}
