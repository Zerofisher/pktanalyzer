// Package expert provides HTTP analysis and anomaly detection
package expert

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Zerofisher/pktanalyzer/capture"
)

// HTTPAnalysisContext maintains state for HTTP analysis
type HTTPAnalysisContext struct {
	mu sync.RWMutex

	// Track pending requests (stream key -> request info)
	pendingRequests map[string]*HTTPRequestRecord

	// Request timeout
	requestTimeout time.Duration
}

// HTTPRequestRecord tracks an HTTP request
type HTTPRequestRecord struct {
	PacketNum int
	Timestamp time.Time
	Method    string
	URI       string
	Host      string
	StreamKey string
}

// HTTPExpertType represents specific HTTP expert info types
type HTTPExpertType int

const (
	HTTPClientError4xx HTTPExpertType = iota // 400-499
	HTTPServerError5xx                       // 500-599
	HTTPRedirect3xx                          // 300-399
	HTTPRequestNoResponse
	HTTPMalformedRequest
	HTTPMalformedResponse
	HTTPSlowResponse
	HTTPLargeRequest
	HTTPLargeResponse
)

// String returns a human-readable description
func (t HTTPExpertType) String() string {
	switch t {
	case HTTPClientError4xx:
		return "HTTP Client Error"
	case HTTPServerError5xx:
		return "HTTP Server Error"
	case HTTPRedirect3xx:
		return "HTTP Redirect"
	case HTTPRequestNoResponse:
		return "HTTP Request Without Response"
	case HTTPMalformedRequest:
		return "Malformed HTTP Request"
	case HTTPMalformedResponse:
		return "Malformed HTTP Response"
	case HTTPSlowResponse:
		return "Slow HTTP Response"
	case HTTPLargeRequest:
		return "Large HTTP Request"
	case HTTPLargeResponse:
		return "Large HTTP Response"
	default:
		return "Unknown HTTP Issue"
	}
}

// Severity returns the default severity for this HTTP expert type
func (t HTTPExpertType) Severity() Severity {
	switch t {
	case HTTPRedirect3xx:
		return SeverityChat
	case HTTPClientError4xx, HTTPSlowResponse:
		return SeverityWarning
	case HTTPServerError5xx, HTTPRequestNoResponse:
		return SeverityError
	case HTTPMalformedRequest, HTTPMalformedResponse:
		return SeverityError
	case HTTPLargeRequest, HTTPLargeResponse:
		return SeverityNote
	default:
		return SeverityNote
	}
}

// NewHTTPAnalysisContext creates a new HTTP analysis context
func NewHTTPAnalysisContext() *HTTPAnalysisContext {
	return &HTTPAnalysisContext{
		pendingRequests: make(map[string]*HTTPRequestRecord),
		requestTimeout:  time.Second * 30,
	}
}

// Analyze processes an HTTP packet and returns any expert info
func (ctx *HTTPAnalysisContext) Analyze(pkt *capture.PacketInfo) []*ExpertInfo {
	if pkt.Protocol != "HTTP" && pkt.Protocol != "HTTPS" {
		return nil
	}

	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	var results []*ExpertInfo

	info := pkt.Info
	// Remove decrypted prefix if present
	if strings.HasPrefix(info, "[Decrypted] ") {
		info = info[12:]
	}

	// Determine if request or response
	isRequest := isHTTPRequestInfo(info)
	isResponse := isHTTPResponseInfo(info)

	if isRequest {
		requestResults := ctx.analyzeRequest(pkt, info)
		results = append(results, requestResults...)
	} else if isResponse {
		responseResults := ctx.analyzeResponse(pkt, info)
		results = append(results, responseResults...)
	}

	// Check for timed-out requests
	timeoutResults := ctx.checkTimeouts(pkt.Timestamp)
	results = append(results, timeoutResults...)

	return results
}

// analyzeRequest processes an HTTP request
func (ctx *HTTPAnalysisContext) analyzeRequest(pkt *capture.PacketInfo, info string) []*ExpertInfo {
	var results []*ExpertInfo

	// Parse request line: "GET /path HTTP/1.1"
	parts := strings.SplitN(info, " ", 3)
	method := ""
	uri := ""
	if len(parts) >= 2 {
		method = parts[0]
		uri = parts[1]
	}

	// Validate method
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"HEAD": true, "OPTIONS": true, "PATCH": true, "CONNECT": true, "TRACE": true,
	}
	if method != "" && !validMethods[method] {
		results = append(results, &ExpertInfo{
			PacketNum: pkt.Number,
			Timestamp: pkt.Timestamp,
			Severity:  HTTPMalformedRequest.Severity(),
			Group:     GroupMalformed,
			Protocol:  "HTTP",
			Summary:   HTTPMalformedRequest.String(),
			Details:   fmt.Sprintf("Invalid HTTP method: %s", method),
			StreamKey: pkt.StreamKey,
		})
	}

	// Check for very long URI
	if len(uri) > 2048 {
		results = append(results, &ExpertInfo{
			PacketNum: pkt.Number,
			Timestamp: pkt.Timestamp,
			Severity:  HTTPLargeRequest.Severity(),
			Group:     GroupProtocol,
			Protocol:  "HTTP",
			Summary:   HTTPLargeRequest.String(),
			Details:   fmt.Sprintf("URI length: %d bytes", len(uri)),
			StreamKey: pkt.StreamKey,
		})
	}

	// Track request for response matching
	streamKey := pkt.StreamKey
	if streamKey == "" {
		streamKey = fmt.Sprintf("%s:%s-%s:%s", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)
	}

	ctx.pendingRequests[streamKey] = &HTTPRequestRecord{
		PacketNum: pkt.Number,
		Timestamp: pkt.Timestamp,
		Method:    method,
		URI:       uri,
		StreamKey: streamKey,
	}

	return results
}

// analyzeResponse processes an HTTP response
func (ctx *HTTPAnalysisContext) analyzeResponse(pkt *capture.PacketInfo, info string) []*ExpertInfo {
	var results []*ExpertInfo

	// Parse response line: "HTTP/1.1 200 OK"
	parts := strings.SplitN(info, " ", 3)
	statusCode := 0
	statusText := ""
	if len(parts) >= 2 {
		code, err := strconv.Atoi(parts[1])
		if err == nil {
			statusCode = code
		}
		if len(parts) >= 3 {
			statusText = parts[2]
		}
	}

	// Find matching request
	streamKey := pkt.StreamKey
	if streamKey == "" {
		// For response, the direction is reversed
		streamKey = fmt.Sprintf("%s:%s-%s:%s", pkt.DstIP, pkt.DstPort, pkt.SrcIP, pkt.SrcPort)
	}

	var request *HTTPRequestRecord
	if req, ok := ctx.pendingRequests[streamKey]; ok {
		request = req
		delete(ctx.pendingRequests, streamKey)
	} else {
		// Try reverse direction
		reverseKey := fmt.Sprintf("%s:%s-%s:%s", pkt.DstIP, pkt.DstPort, pkt.SrcIP, pkt.SrcPort)
		if req, ok := ctx.pendingRequests[reverseKey]; ok {
			request = req
			delete(ctx.pendingRequests, reverseKey)
		}
	}

	// Analyze status code
	if statusCode >= 400 && statusCode < 500 {
		// Client error
		detail := getHTTPErrorDetail(statusCode, statusText)
		if request != nil {
			detail = fmt.Sprintf("%s %s: %d %s", request.Method, request.URI, statusCode, statusText)
		}
		results = append(results, &ExpertInfo{
			PacketNum:   pkt.Number,
			Timestamp:   pkt.Timestamp,
			Severity:    HTTPClientError4xx.Severity(),
			Group:       GroupResponse,
			Protocol:    "HTTP",
			Summary:     fmt.Sprintf("HTTP %d %s", statusCode, getHTTPStatusCategory(statusCode)),
			Details:     detail,
			RelatedPkts: getRelatedPkts(request),
			StreamKey:   pkt.StreamKey,
		})
	} else if statusCode >= 500 && statusCode < 600 {
		// Server error
		detail := getHTTPErrorDetail(statusCode, statusText)
		if request != nil {
			detail = fmt.Sprintf("%s %s: %d %s", request.Method, request.URI, statusCode, statusText)
		}
		results = append(results, &ExpertInfo{
			PacketNum:   pkt.Number,
			Timestamp:   pkt.Timestamp,
			Severity:    HTTPServerError5xx.Severity(),
			Group:       GroupResponse,
			Protocol:    "HTTP",
			Summary:     fmt.Sprintf("HTTP %d %s", statusCode, getHTTPStatusCategory(statusCode)),
			Details:     detail,
			RelatedPkts: getRelatedPkts(request),
			StreamKey:   pkt.StreamKey,
		})
	} else if statusCode >= 300 && statusCode < 400 {
		// Redirect
		results = append(results, &ExpertInfo{
			PacketNum:   pkt.Number,
			Timestamp:   pkt.Timestamp,
			Severity:    HTTPRedirect3xx.Severity(),
			Group:       GroupResponse,
			Protocol:    "HTTP",
			Summary:     fmt.Sprintf("HTTP %d Redirect", statusCode),
			Details:     fmt.Sprintf("%d %s", statusCode, statusText),
			RelatedPkts: getRelatedPkts(request),
			StreamKey:   pkt.StreamKey,
		})
	}

	// Check for slow response
	if request != nil {
		responseTime := pkt.Timestamp.Sub(request.Timestamp)
		if responseTime > 5*time.Second {
			results = append(results, &ExpertInfo{
				PacketNum:   pkt.Number,
				Timestamp:   pkt.Timestamp,
				Severity:    HTTPSlowResponse.Severity(),
				Group:       GroupResponse,
				Protocol:    "HTTP",
				Summary:     HTTPSlowResponse.String(),
				Details:     fmt.Sprintf("Response time: %v for %s %s", responseTime.Round(time.Millisecond), request.Method, request.URI),
				RelatedPkts: []int{request.PacketNum},
				StreamKey:   pkt.StreamKey,
			})
		}
	}

	return results
}

// checkTimeouts checks for requests that haven't received responses
func (ctx *HTTPAnalysisContext) checkTimeouts(currentTime time.Time) []*ExpertInfo {
	var results []*ExpertInfo

	for streamKey, request := range ctx.pendingRequests {
		elapsed := currentTime.Sub(request.Timestamp)
		if elapsed > ctx.requestTimeout {
			results = append(results, &ExpertInfo{
				PacketNum: request.PacketNum,
				Timestamp: request.Timestamp,
				Severity:  HTTPRequestNoResponse.Severity(),
				Group:     GroupResponse,
				Protocol:  "HTTP",
				Summary:   HTTPRequestNoResponse.String(),
				Details:   fmt.Sprintf("No response for %s %s after %v", request.Method, request.URI, elapsed.Round(time.Millisecond)),
				StreamKey: streamKey,
			})
			delete(ctx.pendingRequests, streamKey)
		}
	}

	return results
}

// CheckPendingRequests can be called at the end of capture
func (ctx *HTTPAnalysisContext) CheckPendingRequests() []*ExpertInfo {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	var results []*ExpertInfo

	for _, request := range ctx.pendingRequests {
		results = append(results, &ExpertInfo{
			PacketNum: request.PacketNum,
			Timestamp: request.Timestamp,
			Severity:  SeverityWarning,
			Group:     GroupResponse,
			Protocol:  "HTTP",
			Summary:   HTTPRequestNoResponse.String(),
			Details:   fmt.Sprintf("No response for %s %s (end of capture)", request.Method, request.URI),
		})
	}

	return results
}

// Helper functions

func isHTTPRequestInfo(info string) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}
	for _, m := range methods {
		if strings.HasPrefix(info, m) {
			return true
		}
	}
	return false
}

func isHTTPResponseInfo(info string) bool {
	return strings.HasPrefix(info, "HTTP/")
}

func getHTTPStatusCategory(code int) string {
	switch {
	case code >= 100 && code < 200:
		return "Informational"
	case code >= 200 && code < 300:
		return "Success"
	case code >= 300 && code < 400:
		return "Redirect"
	case code >= 400 && code < 500:
		return "Client Error"
	case code >= 500 && code < 600:
		return "Server Error"
	default:
		return "Unknown"
	}
}

func getHTTPErrorDetail(code int, text string) string {
	descriptions := map[int]string{
		400: "Bad Request - The server cannot process the request",
		401: "Unauthorized - Authentication required",
		403: "Forbidden - Access denied",
		404: "Not Found - Resource does not exist",
		405: "Method Not Allowed",
		408: "Request Timeout",
		429: "Too Many Requests - Rate limited",
		500: "Internal Server Error",
		501: "Not Implemented",
		502: "Bad Gateway",
		503: "Service Unavailable",
		504: "Gateway Timeout",
	}

	if desc, ok := descriptions[code]; ok {
		return desc
	}
	return fmt.Sprintf("%d %s", code, text)
}

func getRelatedPkts(request *HTTPRequestRecord) []int {
	if request != nil {
		return []int{request.PacketNum}
	}
	return nil
}
