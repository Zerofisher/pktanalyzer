package stream

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// HTTPMessage represents a complete HTTP message
type HTTPMessage struct {
	IsRequest  bool
	Method     string // GET, POST, etc.
	URI        string
	Version    string // HTTP/1.0, HTTP/1.1
	StatusCode int
	StatusText string
	Headers    map[string]string
	Body       []byte
	RawData    []byte
}

// ContentLength returns the Content-Length header value
func (m *HTTPMessage) ContentLength() int {
	if cl, ok := m.Headers["content-length"]; ok {
		if n, err := strconv.Atoi(cl); err == nil {
			return n
		}
	}
	return -1
}

// IsChunked returns true if Transfer-Encoding is chunked
func (m *HTTPMessage) IsChunked() bool {
	te, ok := m.Headers["transfer-encoding"]
	return ok && strings.Contains(strings.ToLower(te), "chunked")
}

// Summary returns a one-line summary of the message
func (m *HTTPMessage) Summary() string {
	if m.IsRequest {
		return fmt.Sprintf("%s %s %s", m.Method, m.URI, m.Version)
	}
	return fmt.Sprintf("%s %d %s", m.Version, m.StatusCode, m.StatusText)
}

// HTTPParser parses HTTP messages from reassembled TCP data
type HTTPParser struct {
	Requests  []HTTPMessage
	Responses []HTTPMessage
}

// NewHTTPParser creates a new HTTP parser
func NewHTTPParser() *HTTPParser {
	return &HTTPParser{
		Requests:  make([]HTTPMessage, 0),
		Responses: make([]HTTPMessage, 0),
	}
}

// ParseStream parses HTTP messages from a TCP stream
func (p *HTTPParser) ParseStream(stream *TCPStream) {
	// Parse client → server (requests)
	if clientData := stream.GetClientData(); len(clientData) > 0 {
		p.parseMessages(clientData, true)
	}

	// Parse server → client (responses)
	if serverData := stream.GetServerData(); len(serverData) > 0 {
		p.parseMessages(serverData, false)
	}
}

// parseMessages parses HTTP messages from data
func (p *HTTPParser) parseMessages(data []byte, isRequest bool) {
	offset := 0

	for offset < len(data) {
		msg, consumed := p.parseOneMessage(data[offset:], isRequest)
		if msg == nil || consumed == 0 {
			break
		}

		if isRequest {
			p.Requests = append(p.Requests, *msg)
		} else {
			p.Responses = append(p.Responses, *msg)
		}

		offset += consumed
	}
}

// parseOneMessage parses a single HTTP message
func (p *HTTPParser) parseOneMessage(data []byte, isRequest bool) (*HTTPMessage, int) {
	// Find header end (double CRLF)
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil, 0
	}

	headerData := data[:headerEnd]
	bodyStart := headerEnd + 4

	msg := &HTTPMessage{
		IsRequest: isRequest,
		Headers:   make(map[string]string),
	}

	// Parse first line and headers
	lines := bytes.Split(headerData, []byte("\r\n"))
	if len(lines) == 0 {
		return nil, 0
	}

	// Parse first line (request line or status line)
	firstLine := string(lines[0])
	if isRequest {
		if !p.parseRequestLine(firstLine, msg) {
			return nil, 0
		}
	} else {
		if !p.parseStatusLine(firstLine, msg) {
			return nil, 0
		}
	}

	// Parse headers
	for i := 1; i < len(lines); i++ {
		p.parseHeader(string(lines[i]), msg)
	}

	// Determine body length
	bodyLen := 0
	totalLen := bodyStart

	if msg.IsChunked() {
		// Parse chunked encoding
		body, consumed := p.parseChunkedBody(data[bodyStart:])
		msg.Body = body
		totalLen = bodyStart + consumed
	} else if cl := msg.ContentLength(); cl >= 0 {
		// Fixed content length
		if bodyStart+cl <= len(data) {
			msg.Body = data[bodyStart : bodyStart+cl]
			bodyLen = cl
		} else {
			// Incomplete body
			msg.Body = data[bodyStart:]
			bodyLen = len(data) - bodyStart
		}
		totalLen = bodyStart + bodyLen
	} else if !isRequest {
		// Response without Content-Length, read until end
		msg.Body = data[bodyStart:]
		totalLen = len(data)
	}

	// Store raw data
	msg.RawData = make([]byte, totalLen)
	copy(msg.RawData, data[:totalLen])

	return msg, totalLen
}

// parseRequestLine parses "GET /path HTTP/1.1"
func (p *HTTPParser) parseRequestLine(line string, msg *HTTPMessage) bool {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return false
	}

	msg.Method = parts[0]
	msg.URI = parts[1]
	if len(parts) >= 3 {
		msg.Version = parts[2]
	} else {
		msg.Version = "HTTP/1.0"
	}

	// Validate method
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"HEAD": true, "OPTIONS": true, "PATCH": true, "CONNECT": true, "TRACE": true,
	}
	return validMethods[msg.Method]
}

// parseStatusLine parses "HTTP/1.1 200 OK"
func (p *HTTPParser) parseStatusLine(line string, msg *HTTPMessage) bool {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return false
	}

	if !strings.HasPrefix(parts[0], "HTTP/") {
		return false
	}

	msg.Version = parts[0]
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	msg.StatusCode = code

	if len(parts) >= 3 {
		msg.StatusText = parts[2]
	}

	return true
}

// parseHeader parses "Header-Name: value"
func (p *HTTPParser) parseHeader(line string, msg *HTTPMessage) {
	idx := strings.Index(line, ":")
	if idx == -1 {
		return
	}

	name := strings.TrimSpace(line[:idx])
	value := strings.TrimSpace(line[idx+1:])

	// Store in lowercase for easier lookup
	msg.Headers[strings.ToLower(name)] = value
}

// parseChunkedBody parses chunked transfer encoding
func (p *HTTPParser) parseChunkedBody(data []byte) ([]byte, int) {
	var body []byte
	offset := 0

	for offset < len(data) {
		// Find chunk size line
		lineEnd := bytes.Index(data[offset:], []byte("\r\n"))
		if lineEnd == -1 {
			break
		}

		// Parse chunk size (hex)
		sizeLine := string(data[offset : offset+lineEnd])
		// Remove chunk extensions
		if idx := strings.Index(sizeLine, ";"); idx != -1 {
			sizeLine = sizeLine[:idx]
		}

		size, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 32)
		if err != nil {
			break
		}

		offset += lineEnd + 2 // Skip size line and CRLF

		if size == 0 {
			// Last chunk, skip trailing CRLF
			offset += 2
			break
		}

		// Read chunk data
		if offset+int(size)+2 > len(data) {
			// Incomplete chunk
			break
		}

		body = append(body, data[offset:offset+int(size)]...)
		offset += int(size) + 2 // Skip data and CRLF
	}

	return body, offset
}

// FormatHTTPData formats HTTP data for display
func FormatHTTPData(data []byte, maxLines int) []string {
	var lines []string
	text := string(data)

	for _, line := range strings.Split(text, "\r\n") {
		if len(lines) >= maxLines {
			lines = append(lines, "... (truncated)")
			break
		}
		// Truncate long lines
		if len(line) > 120 {
			line = line[:117] + "..."
		}
		lines = append(lines, line)
	}

	return lines
}

// IsHTTPPort checks if a port is commonly used for HTTP
func IsHTTPPort(port uint16) bool {
	httpPorts := map[uint16]bool{
		80: true, 8080: true, 8000: true, 8888: true,
		3000: true, 5000: true, 9000: true,
	}
	return httpPorts[port]
}

// IsHTTPSPort checks if a port is commonly used for HTTPS
func IsHTTPSPort(port uint16) bool {
	httpsPorts := map[uint16]bool{
		443: true, 8443: true,
	}
	return httpsPorts[port]
}
