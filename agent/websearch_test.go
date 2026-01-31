package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExtractRFCNumber(t *testing.T) {
	tests := []struct {
		query    string
		expected string
	}{
		{"793", "793"},
		{"RFC 793", "793"},
		{"rfc793", "793"},
		{"RFC-793", "793"},
		{"rfc 793", "793"},
		{"TCP protocol", ""},
		{"TLS handshake", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			result := extractRFCNumber(tt.query)
			if result != tt.expected {
				t.Errorf("extractRFCNumber(%q) = %q, want %q", tt.query, result, tt.expected)
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 100, "short"},
		{"this is a longer string that needs truncation", 20, "this is a longer..."},
		{"", 10, ""},
		{"exact len", 9, "exact len"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxLen)
			if len(result) > tt.maxLen+3 { // +3 for "..."
				t.Errorf("truncateString result too long: got %d, max %d", len(result), tt.maxLen)
			}
		})
	}
}

func TestWebSearchClientCreation(t *testing.T) {
	client := NewWebSearchClient()
	if client == nil {
		t.Fatal("NewWebSearchClient returned nil")
	}
	if client.httpClient == nil {
		t.Error("httpClient is nil")
	}
	if client.httpClient.Timeout != WebSearchTimeout*time.Second {
		t.Errorf("unexpected timeout: got %v, want %v", client.httpClient.Timeout, WebSearchTimeout*time.Second)
	}
}

func TestSearchRFCByNumber(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "rfc793") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"name": "rfc793",
				"title": "Transmission Control Protocol",
				"pages": 85,
				"abstract": "TCP is a connection-oriented protocol."
			}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Note: This test would need to modify the client to use a custom base URL
	// For now, we test the format functions which don't require network access
}

func TestFormatRFCResults(t *testing.T) {
	tests := []struct {
		name     string
		results  []RFCResult
		contains []string
	}{
		{
			name:     "empty results",
			results:  []RFCResult{},
			contains: []string{"未找到"},
		},
		{
			name: "single result",
			results: []RFCResult{
				{
					Number:   "793",
					Title:    "Transmission Control Protocol",
					Pages:    85,
					Abstract: "TCP specification",
					FullText: "https://www.rfc-editor.org/rfc/rfc793.txt",
				},
			},
			contains: []string{"RFC 793", "Transmission Control Protocol", "85", "rfc793.txt"},
		},
		{
			name: "multiple results",
			results: []RFCResult{
				{Number: "793", Title: "TCP"},
				{Number: "768", Title: "UDP"},
			},
			contains: []string{"2 个", "RFC 793", "RFC 768"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatRFCResults(tt.results)
			for _, substr := range tt.contains {
				if !strings.Contains(result, substr) {
					t.Errorf("FormatRFCResults() missing %q in output:\n%s", substr, result)
				}
			}
		})
	}
}

func TestFormatDocResults(t *testing.T) {
	tests := []struct {
		name     string
		results  []DocResult
		query    string
		contains []string
	}{
		{
			name:     "empty results",
			results:  []DocResult{},
			query:    "test query",
			contains: []string{"未找到", "test query"},
		},
		{
			name: "single result",
			results: []DocResult{
				{
					Title:   "TCP Guide",
					Snippet: "A guide to TCP",
					URL:     "https://example.com/tcp",
				},
			},
			query:    "TCP",
			contains: []string{"1 个", "TCP Guide", "example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatDocResults(tt.results, tt.query)
			for _, substr := range tt.contains {
				if !strings.Contains(result, substr) {
					t.Errorf("FormatDocResults() missing %q in output:\n%s", substr, result)
				}
			}
		})
	}
}

func TestExtractActualURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "https://example.com"},
		{"http://example.com", "http://example.com"},
		{"//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com", "https://example.com"},
		{"/relative/path", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractActualURL(tt.input)
			if result != tt.expected {
				t.Errorf("extractActualURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseHTMLResults(t *testing.T) {
	html := `
		<a class="result__a" href="https://example.com/1">Result 1</a>
		<a class="result__snippet">Snippet for result 1</a>
		<a class="result__a" href="https://example.com/2">Result 2</a>
		<a class="result__snippet">Snippet for result 2</a>
	`

	results := parseHTMLResults(html, 5)

	if len(results) != 2 {
		t.Errorf("parseHTMLResults returned %d results, want 2", len(results))
	}

	if len(results) > 0 && results[0].Title != "Result 1" {
		t.Errorf("First result title = %q, want %q", results[0].Title, "Result 1")
	}
}

func TestSearchRFCValidation(t *testing.T) {
	client := NewWebSearchClient()

	// Test with invalid context (already cancelled)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.SearchRFC(ctx, "TCP", 5)
	if err == nil {
		t.Error("SearchRFC should fail with cancelled context")
	}
}

func TestSearchDocsValidation(t *testing.T) {
	client := NewWebSearchClient()

	// Test with invalid context (already cancelled)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.SearchDocs(ctx, "TCP troubleshooting", 5)
	if err == nil {
		t.Error("SearchDocs should fail with cancelled context")
	}
}

func TestSearchToolHandlers(t *testing.T) {
	executor := NewToolExecutor()

	// Test lookup_rfc with missing query
	_, err := executor.lookupRFC(map[string]interface{}{})
	if err == nil {
		t.Error("lookupRFC should fail without query")
	}

	// Test web_search with missing query
	_, err = executor.webSearch(map[string]interface{}{})
	if err == nil {
		t.Error("webSearch should fail without query")
	}

	// Test with valid query (will fail on network but validates input handling)
	// We just verify it doesn't panic
	_, _ = executor.lookupRFC(map[string]interface{}{
		"query": "TCP",
	})

	_, _ = executor.webSearch(map[string]interface{}{
		"query": "TCP troubleshooting",
	})
}

func TestHTMLToMarkdown(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains []string
		absent   []string
	}{
		{
			name:     "basic paragraph",
			input:    "<p>Hello world</p>",
			contains: []string{"Hello world"},
			absent:   []string{"<p>", "</p>"},
		},
		{
			name:     "headers",
			input:    "<h1>Title</h1><h2>Subtitle</h2>",
			contains: []string{"# Title", "## Subtitle"},
		},
		{
			name:     "links",
			input:    `<a href="https://example.com">Click here</a>`,
			contains: []string{"[Click here](https://example.com)"},
		},
		{
			name:     "script removal",
			input:    "<p>Text</p><script>alert('xss')</script><p>More</p>",
			contains: []string{"Text", "More"},
			absent:   []string{"alert", "script"},
		},
		{
			name:     "style removal",
			input:    "<style>.red{color:red}</style><p>Content</p>",
			contains: []string{"Content"},
			absent:   []string{".red", "style"},
		},
		{
			name:     "list items",
			input:    "<ul><li>First</li><li>Second</li></ul>",
			contains: []string{"- First", "- Second"},
		},
		{
			name:     "code block",
			input:    "<pre>func main() {}</pre>",
			contains: []string{"```", "func main()"},
		},
		{
			name:     "inline code",
			input:    "<code>var x = 1</code>",
			contains: []string{"`var x = 1`"},
		},
		{
			name:     "bold text",
			input:    "<strong>important</strong>",
			contains: []string{"**important**"},
		},
		{
			name:     "italic text",
			input:    "<em>emphasized</em>",
			contains: []string{"*emphasized*"},
		},
		{
			name:     "HTML entities",
			input:    "<p>a &amp; b &lt; c &gt; d</p>",
			contains: []string{"a & b < c > d"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := htmlToMarkdown(tt.input)
			for _, substr := range tt.contains {
				if !strings.Contains(result, substr) {
					t.Errorf("htmlToMarkdown() missing %q in output:\n%s", substr, result)
				}
			}
			for _, substr := range tt.absent {
				if strings.Contains(result, substr) {
					t.Errorf("htmlToMarkdown() should not contain %q in output:\n%s", substr, result)
				}
			}
		})
	}
}

func TestExtractRFCSection(t *testing.T) {
	rfcContent := `
1.  Introduction

This is the introduction section with some text.

1.1.  Background

Some background information here.

2.  Overview

This is the overview section.

2.1.  Design Goals

Design goals listed here.

2.2.  Implementation

Implementation details here.

3.  Specification

The main specification section.

3.1.  Header Format

Header format details.

3.2.  Connection Setup

Connection setup details.

4.  Conclusion

Final conclusions.
`

	tests := []struct {
		name     string
		section  string
		contains []string
		absent   []string
	}{
		{
			name:     "section 1",
			section:  "1",
			contains: []string{"Introduction", "introduction section"},
			absent:   []string{"Overview"},
		},
		{
			name:     "section 2",
			section:  "2",
			contains: []string{"Overview"},
			absent:   []string{"Specification", "Conclusion"},
		},
		{
			name:     "section 3.1",
			section:  "3.1",
			contains: []string{"Header Format", "Header format details"},
			absent:   []string{"Connection Setup"},
		},
		{
			name:    "nonexistent section",
			section: "99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRFCSection(rfcContent, tt.section)
			for _, substr := range tt.contains {
				if !strings.Contains(result, substr) {
					t.Errorf("extractRFCSection(%q) missing %q in output:\n%s", tt.section, substr, result)
				}
			}
			for _, substr := range tt.absent {
				if strings.Contains(result, substr) {
					t.Errorf("extractRFCSection(%q) should not contain %q in output:\n%s", tt.section, substr, result)
				}
			}
		})
	}
}

func TestTruncateWithContext(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxChars int
		checkLen bool
	}{
		{
			name:     "short content",
			input:    "Hello world",
			maxChars: 100,
			checkLen: true,
		},
		{
			name:     "long content truncated",
			input:    strings.Repeat("This is a test sentence. ", 100),
			maxChars: 100,
			checkLen: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateWithContext(tt.input, tt.maxChars)
			if len(tt.input) <= tt.maxChars {
				// Should not be truncated
				if result != tt.input {
					t.Errorf("Short content should not be truncated")
				}
			} else {
				// Should be truncated and contain indicator
				if !strings.Contains(result, "内容已截断") {
					t.Errorf("Truncated content should contain truncation indicator")
				}
			}
		})
	}
}

func TestDecodeHTMLEntities(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"&amp;", "&"},
		{"&lt;", "<"},
		{"&gt;", ">"},
		{"&quot;", "\""},
		{"&#65;", "A"},
		{"no entities", "no entities"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := decodeHTMLEntities(tt.input)
			if result != tt.expected {
				t.Errorf("decodeHTMLEntities(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestStripTags(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"<p>hello</p>", "hello"},
		{"<a href='url'>link</a>", "link"},
		{"no tags", "no tags"},
		{"<div><span>nested</span></div>", "nested"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := stripTags(tt.input)
			if result != tt.expected {
				t.Errorf("stripTags(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestReadRFCWithMockServer(t *testing.T) {
	// Create a mock RFC text server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`
1.  Introduction

This is a test RFC document.

2.  Specification

The main specification.

2.1.  Details

Some details here.

3.  Conclusion

Final notes.
`))
	}))
	defer server.Close()

	// Note: can't directly test ReadRFC since it uses hardcoded URL
	// But we can test the internal functions it relies on
	client := NewWebSearchClient()

	// Test fetchTextContent with mock server
	ctx := context.Background()
	content, err := client.fetchTextContent(ctx, server.URL)
	if err != nil {
		t.Fatalf("fetchTextContent failed: %v", err)
	}
	if !strings.Contains(content, "Introduction") {
		t.Error("Content should contain 'Introduction'")
	}
}

func TestFetchURLWithMockServer(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		contains    []string
	}{
		{
			name:        "plain text",
			contentType: "text/plain",
			body:        "Hello, this is plain text content.",
			contains:    []string{"Hello", "plain text"},
		},
		{
			name:        "html content",
			contentType: "text/html",
			body:        "<html><body><h1>Title</h1><p>Content here</p></body></html>",
			contains:    []string{"Title", "Content here"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := NewWebSearchClient()
			ctx := context.Background()
			result, err := client.FetchURL(ctx, server.URL, DefaultContentChars)
			if err != nil {
				t.Fatalf("FetchURL failed: %v", err)
			}

			for _, substr := range tt.contains {
				if !strings.Contains(result, substr) {
					t.Errorf("FetchURL() missing %q in output:\n%s", substr, result)
				}
			}
		})
	}
}

func TestFetchURLInvalidScheme(t *testing.T) {
	client := NewWebSearchClient()
	ctx := context.Background()

	_, err := client.FetchURL(ctx, "ftp://example.com/file", DefaultContentChars)
	if err == nil {
		t.Error("FetchURL should reject non-http schemes")
	}
	if !strings.Contains(err.Error(), "http/https") {
		t.Errorf("Error should mention http/https, got: %v", err)
	}
}

func TestReadRFCInvalidNumber(t *testing.T) {
	client := NewWebSearchClient()
	ctx := context.Background()

	_, err := client.ReadRFC(ctx, "not-a-number", "", DefaultContentChars)
	if err == nil {
		t.Error("ReadRFC should reject invalid RFC number")
	}
}

func TestNewToolsRegistered(t *testing.T) {
	toolNames := GetToolNames()

	expectedTools := []string{"lookup_rfc", "web_search"}
	for _, name := range expectedTools {
		if !toolNames[name] {
			t.Errorf("Tool %q not registered in GetToolNames()", name)
		}
	}
}

func TestNewToolsInExecuteTool(t *testing.T) {
	executor := NewToolExecutor()

	// Test lookup_rfc handler exists
	_, err := executor.ExecuteTool("lookup_rfc", map[string]interface{}{
		"query": "793",
	})
	// Will fail with network error, but should not return "unknown tool"
	if err != nil && strings.Contains(err.Error(), "未知工具") {
		t.Error("lookup_rfc should be a recognized tool")
	}

	// Test web_search handler exists
	_, err = executor.ExecuteTool("web_search", map[string]interface{}{
		"query": "TCP troubleshooting",
	})
	if err != nil && strings.Contains(err.Error(), "未知工具") {
		t.Error("web_search should be a recognized tool")
	}
}
