// Package expert provides network traffic analysis and anomaly detection
package expert

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/Zerofisher/pktanalyzer/capture"
)

// Analyzer is the main expert analysis engine
type Analyzer struct {
	mu      sync.RWMutex
	infos   []*ExpertInfo
	tcpCtx  *TCPAnalysisContext
	dnsCtx  *DNSAnalysisContext
	httpCtx *HTTPAnalysisContext

	// Statistics
	countBySeverity map[Severity]int
	countByProtocol map[string]int
	countByGroup    map[Group]int
}

// NewAnalyzer creates a new expert analyzer
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		infos:           make([]*ExpertInfo, 0),
		tcpCtx:          NewTCPAnalysisContext(),
		dnsCtx:          NewDNSAnalysisContext(),
		httpCtx:         NewHTTPAnalysisContext(),
		countBySeverity: make(map[Severity]int),
		countByProtocol: make(map[string]int),
		countByGroup:    make(map[Group]int),
	}
}

// Analyze processes a packet and returns any expert info found
func (a *Analyzer) Analyze(pkt *capture.PacketInfo) []*ExpertInfo {
	var results []*ExpertInfo

	// TCP analysis
	if isTCPPacket(pkt) {
		tcpInfos := a.tcpCtx.Analyze(pkt)
		results = append(results, tcpInfos...)
	}

	// DNS analysis
	if pkt.Protocol == "DNS" {
		dnsInfos := a.dnsCtx.Analyze(pkt)
		results = append(results, dnsInfos...)
	}

	// HTTP analysis
	if pkt.Protocol == "HTTP" || pkt.Protocol == "HTTPS" {
		httpInfos := a.httpCtx.Analyze(pkt)
		results = append(results, httpInfos...)
	}

	// Store results and update statistics
	a.mu.Lock()
	for _, info := range results {
		a.infos = append(a.infos, info)
		a.countBySeverity[info.Severity]++
		a.countByProtocol[info.Protocol]++
		a.countByGroup[info.Group]++
	}
	a.mu.Unlock()

	return results
}

// GetInfos returns all expert info entries
func (a *Analyzer) GetInfos() []*ExpertInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]*ExpertInfo, len(a.infos))
	copy(result, a.infos)
	return result
}

// GetInfosBySeverity returns expert info filtered by minimum severity
func (a *Analyzer) GetInfosBySeverity(minSeverity Severity) []*ExpertInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var result []*ExpertInfo
	for _, info := range a.infos {
		if info.Severity >= minSeverity {
			result = append(result, info)
		}
	}
	return result
}

// GetInfosByProtocol returns expert info filtered by protocol
func (a *Analyzer) GetInfosByProtocol(protocol string) []*ExpertInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var result []*ExpertInfo
	for _, info := range a.infos {
		if strings.EqualFold(info.Protocol, protocol) {
			result = append(result, info)
		}
	}
	return result
}

// GetStatistics returns analysis statistics
func (a *Analyzer) GetStatistics() Statistics {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return Statistics{
		TotalCount:      len(a.infos),
		CountBySeverity: copyMapInt(a.countBySeverity),
		CountByProtocol: copyMapStringInt(a.countByProtocol),
		CountByGroup:    copyMapGroupInt(a.countByGroup),
	}
}

// Statistics holds expert analysis statistics
type Statistics struct {
	TotalCount      int
	CountBySeverity map[Severity]int
	CountByProtocol map[string]int
	CountByGroup    map[Group]int
}

// PrintSummary writes a summary of expert info to the writer
func (a *Analyzer) PrintSummary(w io.Writer) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintln(w, "Expert Information Summary")
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintf(w, "Total entries: %d\n\n", len(a.infos))

	// By severity
	fmt.Fprintln(w, "By Severity:")
	severities := []Severity{SeverityError, SeverityWarning, SeverityNote, SeverityChat}
	for _, sev := range severities {
		count := a.countBySeverity[sev]
		if count > 0 {
			fmt.Fprintf(w, "  [%s] %-10s: %d\n", sev.Symbol(), sev.String(), count)
		}
	}

	// By protocol
	fmt.Fprintln(w, "\nBy Protocol:")
	protocols := sortedKeys(a.countByProtocol)
	for _, proto := range protocols {
		fmt.Fprintf(w, "  %-10s: %d\n", proto, a.countByProtocol[proto])
	}

	// By group
	fmt.Fprintln(w, "\nBy Group:")
	for group, count := range a.countByGroup {
		fmt.Fprintf(w, "  %-12s: %d\n", group, count)
	}

	fmt.Fprintln(w, "================================================================================")
}

// PrintDetails writes detailed expert info to the writer
func (a *Analyzer) PrintDetails(w io.Writer, minSeverity Severity) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintln(w, "Expert Information Details")
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintf(w, "%-6s %-8s %-10s %-10s %-30s %s\n",
		"Packet", "Severity", "Group", "Protocol", "Summary", "Details")
	fmt.Fprintln(w, strings.Repeat("-", 100))

	for _, info := range a.infos {
		if info.Severity >= minSeverity {
			// Truncate details if too long
			details := info.Details
			if len(details) > 40 {
				details = details[:37] + "..."
			}
			fmt.Fprintf(w, "%-6d %-8s %-10s %-10s %-30s %s\n",
				info.PacketNum,
				info.Severity.String(),
				info.Group,
				info.Protocol,
				info.Summary,
				details,
			)
		}
	}

	fmt.Fprintln(w, "================================================================================")
}

// PrintForPacket returns expert info formatted for a specific packet
func (a *Analyzer) PrintForPacket(pktNum int) []string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var lines []string
	for _, info := range a.infos {
		if info.PacketNum == pktNum {
			lines = append(lines, fmt.Sprintf("[%s] %s: %s",
				info.Severity.Symbol(), info.Summary, info.Details))
		}
	}
	return lines
}

// HasIssues returns true if any warnings or errors were detected
func (a *Analyzer) HasIssues() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.countBySeverity[SeverityWarning] > 0 || a.countBySeverity[SeverityError] > 0
}

// Reset clears all expert info and statistics
func (a *Analyzer) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.infos = make([]*ExpertInfo, 0)
	a.tcpCtx = NewTCPAnalysisContext()
	a.dnsCtx = NewDNSAnalysisContext()
	a.httpCtx = NewHTTPAnalysisContext()
	a.countBySeverity = make(map[Severity]int)
	a.countByProtocol = make(map[string]int)
	a.countByGroup = make(map[Group]int)
}

// Helper functions

func isTCPPacket(pkt *capture.PacketInfo) bool {
	switch pkt.Protocol {
	case "TCP", "HTTP", "HTTPS", "TLS":
		return true
	}
	return false
}

func copyMapInt[K comparable](m map[K]int) map[K]int {
	result := make(map[K]int, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

func copyMapStringInt(m map[string]int) map[string]int {
	return copyMapInt(m)
}

func copyMapGroupInt(m map[Group]int) map[Group]int {
	return copyMapInt(m)
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
