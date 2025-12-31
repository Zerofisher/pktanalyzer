package stream

import (
	"testing"
)

func TestHPACKStaticTable(t *testing.T) {
	decoder := DefaultHPACKDecoder()

	// Test indexed header from static table
	// Index 2 is :method GET
	data := []byte{0x82} // Indexed (1xxxxxxx), index 2

	headers, err := decoder.Decode(data)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if len(headers) != 1 {
		t.Fatalf("Expected 1 header, got %d", len(headers))
	}

	if headers[0].Name != ":method" || headers[0].Value != "GET" {
		t.Errorf("Expected :method GET, got %s %s", headers[0].Name, headers[0].Value)
	}
}

func TestHPACKLiteralHeaderIncremental(t *testing.T) {
	decoder := DefaultHPACKDecoder()

	// Literal header with incremental indexing, new name
	// 0x40 (01xxxxxx) with index 0 means new name
	// Then name length (7 prefix), then name, then value length, then value
	data := []byte{
		0x40,                                     // Literal with incremental indexing, index 0 (new name)
		0x0a,                                     // Name length: 10 (no Huffman)
		'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y', // Name: "custom-key"
		0x0d, // Value length: 13 (no Huffman)
		'c', 'u', 's', 't', 'o', 'm', '-', 'v', 'a', 'l', 'u', 'e', '.', // Value: "custom-value."
	}

	headers, err := decoder.Decode(data)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if len(headers) != 1 {
		t.Fatalf("Expected 1 header, got %d", len(headers))
	}

	if headers[0].Name != "custom-key" {
		t.Errorf("Expected name 'custom-key', got '%s'", headers[0].Name)
	}

	if headers[0].Value != "custom-value." {
		t.Errorf("Expected value 'custom-value.', got '%s'", headers[0].Value)
	}
}

func TestHPACKLiteralHeaderWithIndexedName(t *testing.T) {
	decoder := DefaultHPACKDecoder()

	// Literal header with indexed name (:path from static table, index 4)
	// 0x44 = 01000100, index 4
	data := []byte{
		0x44, // Literal with incremental indexing, index 4 (:path)
		0x0c, // Value length: 12 (no Huffman)
		'/', 's', 'a', 'm', 'p', 'l', 'e', '/', 'p', 'a', 't', 'h', // Value: "/sample/path"
	}

	headers, err := decoder.Decode(data)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if len(headers) != 1 {
		t.Fatalf("Expected 1 header, got %d", len(headers))
	}

	if headers[0].Name != ":path" {
		t.Errorf("Expected name ':path', got '%s'", headers[0].Name)
	}

	if headers[0].Value != "/sample/path" {
		t.Errorf("Expected value '/sample/path', got '%s'", headers[0].Value)
	}
}

func TestHPACKMultipleHeaders(t *testing.T) {
	decoder := DefaultHPACKDecoder()

	// Multiple indexed headers
	data := []byte{
		0x82, // :method GET (index 2)
		0x84, // :path / (index 4)
		0x86, // :scheme http (index 6)
	}

	headers, err := decoder.Decode(data)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if len(headers) != 3 {
		t.Fatalf("Expected 3 headers, got %d", len(headers))
	}

	expected := []HPACKHeader{
		{":method", "GET"},
		{":path", "/"},
		{":scheme", "http"},
	}

	for i, h := range headers {
		if h.Name != expected[i].Name || h.Value != expected[i].Value {
			t.Errorf("Header %d: expected %s=%s, got %s=%s",
				i, expected[i].Name, expected[i].Value, h.Name, h.Value)
		}
	}
}

func TestHPACKDynamicTable(t *testing.T) {
	decoder := DefaultHPACKDecoder()

	// Add a custom header with incremental indexing
	data1 := []byte{
		0x40,                               // Literal with incremental indexing
		0x07,                               // Name length: 7
		'm', 'y', '-', 'n', 'a', 'm', 'e', // Name
		0x08,                                     // Value length: 8
		'm', 'y', '-', 'v', 'a', 'l', 'u', 'e', // Value
	}

	_, err := decoder.Decode(data1)
	if err != nil {
		t.Fatalf("Failed to decode first header: %v", err)
	}

	// Now reference it via dynamic table
	// Dynamic table index = static table size + 1 = 62
	data2 := []byte{0xbe} // Indexed, index 62

	headers, err := decoder.Decode(data2)
	if err != nil {
		t.Fatalf("Failed to decode second header: %v", err)
	}

	if len(headers) != 1 {
		t.Fatalf("Expected 1 header, got %d", len(headers))
	}

	if headers[0].Name != "my-name" || headers[0].Value != "my-value" {
		t.Errorf("Expected my-name=my-value, got %s=%s", headers[0].Name, headers[0].Value)
	}
}

func TestHPACKInteger(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		prefixBits int
		expected   uint64
	}{
		{"small value", []byte{0x0a}, 5, 10},                // 10 < 31
		{"max prefix", []byte{0x1f, 0x00}, 5, 31},           // 31 = 0x1f
		{"multi-byte", []byte{0x1f, 0x9a, 0x0a}, 5, 1337},   // 1337 = 31 + 128*10 + 26
		{"zero", []byte{0x00}, 7, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, _, err := decodeInteger(tt.data, tt.prefixBits)
			if err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}
			if val != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, val)
			}
		})
	}
}

func TestExtractPseudoHeaders(t *testing.T) {
	headers := []HPACKHeader{
		{":method", "GET"},
		{":scheme", "https"},
		{":authority", "www.example.com"},
		{":path", "/index.html"},
		{"accept", "text/html"},
		{"user-agent", "test"},
	}

	ph := ExtractPseudoHeaders(headers)

	if ph.Method != "GET" {
		t.Errorf("Expected method GET, got %s", ph.Method)
	}
	if ph.Scheme != "https" {
		t.Errorf("Expected scheme https, got %s", ph.Scheme)
	}
	if ph.Authority != "www.example.com" {
		t.Errorf("Expected authority www.example.com, got %s", ph.Authority)
	}
	if ph.Path != "/index.html" {
		t.Errorf("Expected path /index.html, got %s", ph.Path)
	}
}

func TestHTTP2ConnectionProcessFrames(t *testing.T) {
	conn := NewHTTP2Connection()

	// Process SETTINGS frame
	settingsFrame := &HTTP2Frame{
		Type:     HTTP2FrameSettings,
		StreamID: 0,
		Payload: []byte{
			0x00, 0x03, 0x00, 0x00, 0x00, 0x64, // MAX_CONCURRENT_STREAMS: 100
		},
	}

	err := conn.ProcessFrame(settingsFrame, true)
	if err != nil {
		t.Fatalf("Failed to process SETTINGS: %v", err)
	}

	if conn.PeerSettings.MaxConcurrentStreams != 100 {
		t.Errorf("Expected MAX_CONCURRENT_STREAMS 100, got %d", conn.PeerSettings.MaxConcurrentStreams)
	}
}
