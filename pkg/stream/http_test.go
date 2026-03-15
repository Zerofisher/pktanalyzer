package stream

import (
	"strings"
	"testing"
	"time"
)

// newTestStream creates a TCPStream with client and server data populated
// from the provided raw byte slices via ReassemblyBuffer.
func newTestStream(clientRaw, serverRaw []byte) *TCPStream {
	var initialSeq uint32 = 1000

	stream := &TCPStream{
		ID:         1,
		Key:        "test-stream",
		ClientAddr: "10.0.0.1:12345",
		ServerAddr: "10.0.0.2:80",
		State:      StateEstablished,
		ClientData: NewReassemblyBuffer(initialSeq),
		ServerData: NewReassemblyBuffer(initialSeq),
		StartTime:  time.Now(),
		LastSeen:   time.Now(),
	}

	now := time.Now()
	if len(clientRaw) > 0 {
		stream.ClientData.AddSegment(initialSeq, clientRaw, now)
	}
	if len(serverRaw) > 0 {
		stream.ServerData.AddSegment(initialSeq, serverRaw, now)
	}

	return stream
}

func TestHTTPParser_ParseRequest_GET(t *testing.T) {
	raw := []byte("GET /index.html HTTP/1.1\r\n" +
		"Host: www.example.com\r\n" +
		"User-Agent: Go-Test/1.0\r\n" +
		"Accept: */*\r\n" +
		"\r\n")

	stream := newTestStream(raw, nil)
	parser := NewHTTPParser()
	parser.ParseStream(stream)

	if len(parser.Requests) != 1 {
		t.Fatalf("Expected 1 request, got %d", len(parser.Requests))
	}

	req := parser.Requests[0]
	if !req.IsRequest {
		t.Error("Expected IsRequest=true")
	}
	if req.Method != "GET" {
		t.Errorf("Expected Method=GET, got %s", req.Method)
	}
	if req.URI != "/index.html" {
		t.Errorf("Expected URI=/index.html, got %s", req.URI)
	}
	if req.Version != "HTTP/1.1" {
		t.Errorf("Expected Version=HTTP/1.1, got %s", req.Version)
	}
	if req.Headers["host"] != "www.example.com" {
		t.Errorf("Expected Host=www.example.com, got %s", req.Headers["host"])
	}
	if req.Headers["user-agent"] != "Go-Test/1.0" {
		t.Errorf("Expected User-Agent=Go-Test/1.0, got %s", req.Headers["user-agent"])
	}
	if len(req.Body) != 0 {
		t.Errorf("Expected empty body, got %d bytes", len(req.Body))
	}
}

func TestHTTPParser_ParseRequest_POST(t *testing.T) {
	body := `{"username":"test","password":"secret"}`
	raw := []byte("POST /api/login HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n" +
		"\r\n" +
		body)

	stream := newTestStream(raw, nil)
	parser := NewHTTPParser()
	parser.ParseStream(stream)

	if len(parser.Requests) != 1 {
		t.Fatalf("Expected 1 request, got %d", len(parser.Requests))
	}

	req := parser.Requests[0]
	if req.Method != "POST" {
		t.Errorf("Expected Method=POST, got %s", req.Method)
	}
	if req.URI != "/api/login" {
		t.Errorf("Expected URI=/api/login, got %s", req.URI)
	}
	if req.Headers["content-type"] != "application/json" {
		t.Errorf("Expected Content-Type=application/json, got %s", req.Headers["content-type"])
	}
	if string(req.Body) != body {
		t.Errorf("Expected body=%q, got %q", body, string(req.Body))
	}
	if req.ContentLength() != len(body) {
		t.Errorf("Expected ContentLength=%d, got %d", len(body), req.ContentLength())
	}
}

func TestHTTPParser_ParseResponse_200(t *testing.T) {
	body := "<html><body>Hello</body></html>"
	raw := []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n" +
		"Server: Go-Test\r\n" +
		"\r\n" +
		body)

	stream := newTestStream(nil, raw)
	parser := NewHTTPParser()
	parser.ParseStream(stream)

	if len(parser.Responses) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(parser.Responses))
	}

	resp := parser.Responses[0]
	if resp.IsRequest {
		t.Error("Expected IsRequest=false")
	}
	if resp.Version != "HTTP/1.1" {
		t.Errorf("Expected Version=HTTP/1.1, got %s", resp.Version)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected StatusCode=200, got %d", resp.StatusCode)
	}
	if resp.StatusText != "OK" {
		t.Errorf("Expected StatusText=OK, got %s", resp.StatusText)
	}
	if resp.Headers["content-type"] != "text/html" {
		t.Errorf("Expected Content-Type=text/html, got %s", resp.Headers["content-type"])
	}
	if string(resp.Body) != body {
		t.Errorf("Expected body=%q, got %q", body, string(resp.Body))
	}
}

func TestHTTPParser_ParseResponse_404(t *testing.T) {
	body := "Not Found"
	raw := []byte("HTTP/1.1 404 Not Found\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n" +
		"\r\n" +
		body)

	stream := newTestStream(nil, raw)
	parser := NewHTTPParser()
	parser.ParseStream(stream)

	if len(parser.Responses) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(parser.Responses))
	}

	resp := parser.Responses[0]
	if resp.StatusCode != 404 {
		t.Errorf("Expected StatusCode=404, got %d", resp.StatusCode)
	}
	if resp.StatusText != "Not Found" {
		t.Errorf("Expected StatusText='Not Found', got %s", resp.StatusText)
	}
	if string(resp.Body) != body {
		t.Errorf("Expected body=%q, got %q", body, string(resp.Body))
	}
}

func TestHTTPParser_ContentLength(t *testing.T) {
	body := "ABCDEFGHIJ" // exactly 10 bytes
	raw := []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Length: 10\r\n" +
		"\r\n" +
		body)

	stream := newTestStream(nil, raw)
	parser := NewHTTPParser()
	parser.ParseStream(stream)

	if len(parser.Responses) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(parser.Responses))
	}

	resp := parser.Responses[0]
	if resp.ContentLength() != 10 {
		t.Errorf("Expected ContentLength=10, got %d", resp.ContentLength())
	}
	if len(resp.Body) != 10 {
		t.Errorf("Expected body length=10, got %d", len(resp.Body))
	}
	if string(resp.Body) != body {
		t.Errorf("Expected body=%q, got %q", body, string(resp.Body))
	}
}

func TestHTTPParser_ChunkedEncoding(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"5\r\n" +
		"Hello\r\n" +
		"6\r\n" +
		" World\r\n" +
		"0\r\n" +
		"\r\n")

	stream := newTestStream(nil, raw)
	parser := NewHTTPParser()
	parser.ParseStream(stream)

	if len(parser.Responses) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(parser.Responses))
	}

	resp := parser.Responses[0]
	if !resp.IsChunked() {
		t.Error("Expected IsChunked=true")
	}
	if string(resp.Body) != "Hello World" {
		t.Errorf("Expected body='Hello World', got %q", string(resp.Body))
	}
}

func TestHTTPParser_MultipleMessages(t *testing.T) {
	// Two pipelined GET requests
	clientRaw := []byte(
		"GET /page1 HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Connection: keep-alive\r\n" +
			"\r\n" +
			"GET /page2 HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Connection: keep-alive\r\n" +
			"\r\n")

	// Two corresponding responses with Content-Length
	body1 := "Page One"
	body2 := "Page Two"
	serverRaw := []byte(
		"HTTP/1.1 200 OK\r\n" +
			"Content-Length: " + itoa(len(body1)) + "\r\n" +
			"\r\n" +
			body1 +
			"HTTP/1.1 200 OK\r\n" +
			"Content-Length: " + itoa(len(body2)) + "\r\n" +
			"\r\n" +
			body2)

	stream := newTestStream(clientRaw, serverRaw)
	parser := NewHTTPParser()
	parser.ParseStream(stream)

	if len(parser.Requests) != 2 {
		t.Fatalf("Expected 2 requests, got %d", len(parser.Requests))
	}
	if len(parser.Responses) != 2 {
		t.Fatalf("Expected 2 responses, got %d", len(parser.Responses))
	}

	if parser.Requests[0].URI != "/page1" {
		t.Errorf("Expected first request URI=/page1, got %s", parser.Requests[0].URI)
	}
	if parser.Requests[1].URI != "/page2" {
		t.Errorf("Expected second request URI=/page2, got %s", parser.Requests[1].URI)
	}
	if string(parser.Responses[0].Body) != body1 {
		t.Errorf("Expected first response body=%q, got %q", body1, string(parser.Responses[0].Body))
	}
	if string(parser.Responses[1].Body) != body2 {
		t.Errorf("Expected second response body=%q, got %q", body2, string(parser.Responses[1].Body))
	}
}

func TestHTTPMessage_Summary(t *testing.T) {
	tests := []struct {
		name     string
		msg      HTTPMessage
		expected string
	}{
		{
			name: "GET request",
			msg: HTTPMessage{
				IsRequest: true,
				Method:    "GET",
				URI:       "/api/users",
				Version:   "HTTP/1.1",
			},
			expected: "GET /api/users HTTP/1.1",
		},
		{
			name: "POST request",
			msg: HTTPMessage{
				IsRequest: true,
				Method:    "POST",
				URI:       "/submit",
				Version:   "HTTP/1.1",
			},
			expected: "POST /submit HTTP/1.1",
		},
		{
			name: "200 response",
			msg: HTTPMessage{
				IsRequest:  false,
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
			},
			expected: "HTTP/1.1 200 OK",
		},
		{
			name: "404 response",
			msg: HTTPMessage{
				IsRequest:  false,
				Version:    "HTTP/1.1",
				StatusCode: 404,
				StatusText: "Not Found",
			},
			expected: "HTTP/1.1 404 Not Found",
		},
		{
			name: "301 redirect",
			msg: HTTPMessage{
				IsRequest:  false,
				Version:    "HTTP/1.1",
				StatusCode: 301,
				StatusText: "Moved Permanently",
			},
			expected: "HTTP/1.1 301 Moved Permanently",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.msg.Summary()
			if got != tt.expected {
				t.Errorf("Summary() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestHTTPMessage_ContentLength(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected int
	}{
		{
			name:     "valid content-length",
			headers:  map[string]string{"content-length": "42"},
			expected: 42,
		},
		{
			name:     "zero content-length",
			headers:  map[string]string{"content-length": "0"},
			expected: 0,
		},
		{
			name:     "missing content-length",
			headers:  map[string]string{"content-type": "text/html"},
			expected: -1,
		},
		{
			name:     "empty headers",
			headers:  map[string]string{},
			expected: -1,
		},
		{
			name:     "non-numeric content-length",
			headers:  map[string]string{"content-length": "invalid"},
			expected: -1,
		},
		{
			name:     "large content-length",
			headers:  map[string]string{"content-length": "1048576"},
			expected: 1048576,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &HTTPMessage{Headers: tt.headers}
			got := msg.ContentLength()
			if got != tt.expected {
				t.Errorf("ContentLength() = %d, expected %d", got, tt.expected)
			}
		})
	}
}

func TestHTTPMessage_IsChunked(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name:     "chunked lowercase",
			headers:  map[string]string{"transfer-encoding": "chunked"},
			expected: true,
		},
		{
			name:     "chunked mixed case",
			headers:  map[string]string{"transfer-encoding": "Chunked"},
			expected: true,
		},
		{
			name:     "chunked uppercase",
			headers:  map[string]string{"transfer-encoding": "CHUNKED"},
			expected: true,
		},
		{
			name:     "gzip then chunked",
			headers:  map[string]string{"transfer-encoding": "gzip, chunked"},
			expected: true,
		},
		{
			name:     "not chunked",
			headers:  map[string]string{"transfer-encoding": "gzip"},
			expected: false,
		},
		{
			name:     "no transfer-encoding",
			headers:  map[string]string{"content-type": "text/html"},
			expected: false,
		},
		{
			name:     "empty headers",
			headers:  map[string]string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &HTTPMessage{Headers: tt.headers}
			got := msg.IsChunked()
			if got != tt.expected {
				t.Errorf("IsChunked() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestFormatHTTPData(t *testing.T) {
	t.Run("basic formatting", func(t *testing.T) {
		data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		lines := FormatHTTPData(data, 10)

		if len(lines) != 4 {
			t.Fatalf("Expected 4 lines, got %d: %v", len(lines), lines)
		}
		if lines[0] != "GET / HTTP/1.1" {
			t.Errorf("Expected first line='GET / HTTP/1.1', got %q", lines[0])
		}
		if lines[1] != "Host: example.com" {
			t.Errorf("Expected second line='Host: example.com', got %q", lines[1])
		}
	})

	t.Run("truncation at maxLines", func(t *testing.T) {
		data := []byte("Line1\r\nLine2\r\nLine3\r\nLine4\r\nLine5\r\n")
		lines := FormatHTTPData(data, 3)

		if len(lines) != 4 {
			t.Fatalf("Expected 4 lines (3 + truncated), got %d: %v", len(lines), lines)
		}
		if lines[3] != "... (truncated)" {
			t.Errorf("Expected truncation marker, got %q", lines[3])
		}
	})

	t.Run("long line truncation at 120 chars", func(t *testing.T) {
		longLine := strings.Repeat("A", 200)
		data := []byte(longLine + "\r\n")
		lines := FormatHTTPData(data, 10)

		if len(lines) < 1 {
			t.Fatal("Expected at least 1 line")
		}
		// 117 chars + "..." = 120 chars
		if len(lines[0]) != 120 {
			t.Errorf("Expected truncated line length=120, got %d", len(lines[0]))
		}
		if !strings.HasSuffix(lines[0], "...") {
			t.Errorf("Expected line to end with '...', got suffix %q", lines[0][len(lines[0])-3:])
		}
	})

	t.Run("exact 120 char line not truncated", func(t *testing.T) {
		exactLine := strings.Repeat("B", 120)
		data := []byte(exactLine + "\r\n")
		lines := FormatHTTPData(data, 10)

		if len(lines) < 1 {
			t.Fatal("Expected at least 1 line")
		}
		if lines[0] != exactLine {
			t.Errorf("Expected exact 120 char line to be preserved, got length %d", len(lines[0]))
		}
	})

	t.Run("empty data", func(t *testing.T) {
		lines := FormatHTTPData([]byte{}, 10)
		// Splitting empty string yields one empty element
		if len(lines) != 1 {
			t.Errorf("Expected 1 line for empty data, got %d", len(lines))
		}
	})
}

func TestIsHTTPPort(t *testing.T) {
	tests := []struct {
		port     uint16
		expected bool
	}{
		{80, true},
		{8080, true},
		{8000, true},
		{8888, true},
		{3000, true},
		{5000, true},
		{9000, true},
		{443, false},
		{8443, false},
		{22, false},
		{0, false},
		{65535, false},
		{1234, false},
	}

	for _, tt := range tests {
		name := itoa(int(tt.port))
		t.Run(name, func(t *testing.T) {
			got := IsHTTPPort(tt.port)
			if got != tt.expected {
				t.Errorf("IsHTTPPort(%d) = %v, expected %v", tt.port, got, tt.expected)
			}
		})
	}
}

func TestIsHTTPSPort(t *testing.T) {
	tests := []struct {
		port     uint16
		expected bool
	}{
		{443, true},
		{8443, true},
		{80, false},
		{8080, false},
		{22, false},
		{0, false},
		{65535, false},
		{9443, false},
	}

	for _, tt := range tests {
		name := itoa(int(tt.port))
		t.Run(name, func(t *testing.T) {
			got := IsHTTPSPort(tt.port)
			if got != tt.expected {
				t.Errorf("IsHTTPSPort(%d) = %v, expected %v", tt.port, got, tt.expected)
			}
		})
	}
}

// --- Additional edge case tests ---

func TestHTTPParser_InvalidMethod(t *testing.T) {
	raw := []byte("INVALID /path HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"\r\n")

	stream := newTestStream(raw, nil)
	parser := NewHTTPParser()
	parser.ParseStream(stream)

	if len(parser.Requests) != 0 {
		t.Errorf("Expected 0 requests for invalid method, got %d", len(parser.Requests))
	}
}

func TestHTTPParser_AllValidMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			raw := []byte(method + " /path HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n")

			stream := newTestStream(raw, nil)
			parser := NewHTTPParser()
			parser.ParseStream(stream)

			if len(parser.Requests) != 1 {
				t.Fatalf("Expected 1 request for method %s, got %d", method, len(parser.Requests))
			}
			if parser.Requests[0].Method != method {
				t.Errorf("Expected Method=%s, got %s", method, parser.Requests[0].Method)
			}
		})
	}
}

func TestHTTPParser_ResponseWithoutContentLength(t *testing.T) {
	// Response without Content-Length reads until end of data
	raw := []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"all remaining data is the body")

	stream := newTestStream(nil, raw)
	parser := NewHTTPParser()
	parser.ParseStream(stream)

	if len(parser.Responses) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(parser.Responses))
	}

	resp := parser.Responses[0]
	if resp.ContentLength() != -1 {
		t.Errorf("Expected ContentLength=-1, got %d", resp.ContentLength())
	}
	if string(resp.Body) != "all remaining data is the body" {
		t.Errorf("Expected body='all remaining data is the body', got %q", string(resp.Body))
	}
}

func TestHTTPParser_RawDataPreserved(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"\r\n")

	stream := newTestStream(raw, nil)
	parser := NewHTTPParser()
	parser.ParseStream(stream)

	if len(parser.Requests) != 1 {
		t.Fatalf("Expected 1 request, got %d", len(parser.Requests))
	}

	req := parser.Requests[0]
	if len(req.RawData) == 0 {
		t.Error("Expected RawData to be non-empty")
	}
	// RawData should contain the full request including headers and CRLF separator
	if !strings.Contains(string(req.RawData), "GET / HTTP/1.1") {
		t.Error("Expected RawData to contain the request line")
	}
}

func TestHTTPParser_ChunkedWithExtensions(t *testing.T) {
	// Chunked encoding with chunk extensions (should be ignored)
	raw := []byte("HTTP/1.1 200 OK\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"4;ext=val\r\n" +
		"Wiki\r\n" +
		"5\r\n" +
		"pedia\r\n" +
		"0\r\n" +
		"\r\n")

	stream := newTestStream(nil, raw)
	parser := NewHTTPParser()
	parser.ParseStream(stream)

	if len(parser.Responses) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(parser.Responses))
	}

	resp := parser.Responses[0]
	if string(resp.Body) != "Wikipedia" {
		t.Errorf("Expected body='Wikipedia', got %q", string(resp.Body))
	}
}

func TestHTTPParser_EmptyClientAndServerData(t *testing.T) {
	stream := newTestStream(nil, nil)
	parser := NewHTTPParser()
	parser.ParseStream(stream)

	if len(parser.Requests) != 0 {
		t.Errorf("Expected 0 requests, got %d", len(parser.Requests))
	}
	if len(parser.Responses) != 0 {
		t.Errorf("Expected 0 responses, got %d", len(parser.Responses))
	}
}

func TestNewHTTPParser(t *testing.T) {
	parser := NewHTTPParser()

	if parser == nil {
		t.Fatal("Expected non-nil parser")
	}
	if parser.Requests == nil {
		t.Error("Expected Requests slice to be initialized")
	}
	if parser.Responses == nil {
		t.Error("Expected Responses slice to be initialized")
	}
	if len(parser.Requests) != 0 {
		t.Errorf("Expected empty Requests, got %d", len(parser.Requests))
	}
	if len(parser.Responses) != 0 {
		t.Errorf("Expected empty Responses, got %d", len(parser.Responses))
	}
}

// itoa is a minimal int-to-string helper to avoid importing strconv in tests.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
