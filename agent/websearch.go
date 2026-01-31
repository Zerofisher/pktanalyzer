// Package agent provides web search functionality for AI agent tools
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Web search constants
const (
	MaxWebSearchResults = 10      // Maximum search results
	DefaultWebResults   = 5       // Default results count
	WebSearchTimeout    = 15      // Timeout in seconds
	MaxAbstractLen      = 500     // RFC abstract truncation length
	MaxSnippetLen       = 200     // Search result snippet length
	MaxResponseBody     = 1 << 20 // 1MB max response size

	// Content fetching constants
	MaxRFCContentChars = 16000 // RFC content max characters
	MaxURLContentChars = 8000  // URL content max characters
	DefaultContentChars = 8000 // Default content characters
	FetchTimeout        = 30   // Fetch timeout in seconds
	MaxFetchBody        = 2 << 20 // 2MB max fetch body
)

// IETF API endpoints
const (
	ietfSearchURL = "https://datatracker.ietf.org/api/v1/doc/document/?name__contains=rfc&title__icontains=%s&format=json&limit=%d"
	ietfDirectURL = "https://datatracker.ietf.org/api/v1/doc/document/rfc%s/?format=json"
	rfcTextURL    = "https://www.rfc-editor.org/rfc/rfc%s.txt"
)

// DuckDuckGo API endpoints
const (
	ddgInstantAPI = "https://api.duckduckgo.com/?q=%s&format=json&no_html=1&skip_disambig=1"
	ddgHTMLSearch = "https://html.duckduckgo.com/html/?q=%s"
)

// WebSearchClient handles web searches for RFC and technical documentation
type WebSearchClient struct {
	httpClient *http.Client
}

// NewWebSearchClient creates a new WebSearchClient
func NewWebSearchClient() *WebSearchClient {
	return &WebSearchClient{
		httpClient: &http.Client{
			Timeout: WebSearchTimeout * time.Second,
		},
	}
}

// RFCResult represents a single RFC search result
type RFCResult struct {
	Number   string `json:"number"`
	Title    string `json:"title"`
	Pages    int    `json:"pages"`
	Abstract string `json:"abstract"`
	FullText string `json:"full_text"`
}

// DocResult represents a single documentation search result
type DocResult struct {
	Title   string `json:"title"`
	Snippet string `json:"snippet"`
	URL     string `json:"url"`
}

// ietfDocResponse represents IETF API response for a single document
type ietfDocResponse struct {
	Name     string `json:"name"`
	Title    string `json:"title"`
	Pages    int    `json:"pages"`
	Abstract string `json:"abstract"`
}

// ietfSearchResponse represents IETF API search response
type ietfSearchResponse struct {
	Meta struct {
		TotalCount int `json:"total_count"`
	} `json:"meta"`
	Objects []ietfDocResponse `json:"objects"`
}

// ddgInstantResponse represents DuckDuckGo Instant Answer API response
type ddgInstantResponse struct {
	AbstractText   string `json:"AbstractText"`
	AbstractSource string `json:"AbstractSource"`
	AbstractURL    string `json:"AbstractURL"`
	Heading        string `json:"Heading"`
	RelatedTopics  []struct {
		Text     string `json:"Text"`
		FirstURL string `json:"FirstURL"`
		Result   string `json:"Result"`
	} `json:"RelatedTopics"`
	Results []struct {
		Text     string `json:"Text"`
		FirstURL string `json:"FirstURL"`
	} `json:"Results"`
}

// extractRFCNumber extracts RFC number from a query string
// Returns empty string if no RFC number found
func extractRFCNumber(query string) string {
	query = strings.TrimSpace(strings.ToLower(query))

	// Pattern: "rfc 793", "rfc793", "RFC-793"
	rfcPattern := regexp.MustCompile(`(?i)rfc[- ]?(\d+)`)
	if matches := rfcPattern.FindStringSubmatch(query); len(matches) > 1 {
		return matches[1]
	}

	// Pattern: just a number like "793"
	if regexp.MustCompile(`^\d+$`).MatchString(query) {
		return query
	}

	return ""
}

// truncateString truncates a string to max length with ellipsis
func truncateString(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	// Try to break at a word boundary
	truncated := s[:maxLen]
	if lastSpace := strings.LastIndex(truncated, " "); lastSpace > maxLen-50 {
		truncated = truncated[:lastSpace]
	}
	return truncated + "..."
}

// LookupRFC is the unified RFC tool: if the query is a specific RFC number,
// it fetches the full content (or a section) directly; if it's a keyword search,
// it returns a list of matching RFCs. This follows the DeepAgent pattern of
// performing search + content fetch in a single tool call.
func (c *WebSearchClient) LookupRFC(ctx context.Context, query string, section string, maxChars int, limit int) (string, error) {
	if maxChars <= 0 || maxChars > MaxRFCContentChars {
		maxChars = DefaultContentChars
	}
	if limit <= 0 || limit > MaxWebSearchResults {
		limit = DefaultWebResults
	}

	// If the query is a direct RFC number, fetch full content immediately
	if rfcNum := extractRFCNumber(query); rfcNum != "" {
		return c.ReadRFC(ctx, rfcNum, section, maxChars)
	}

	// Otherwise, keyword search → return list with abstracts
	results, err := c.searchRFCByKeywords(ctx, query, limit)
	if err != nil {
		return "", err
	}

	return FormatRFCResults(results), nil
}

// SearchRFC searches for RFC documents (kept for backward compatibility)
func (c *WebSearchClient) SearchRFC(ctx context.Context, query string, limit int) ([]RFCResult, error) {
	if limit <= 0 || limit > MaxWebSearchResults {
		limit = DefaultWebResults
	}

	// Check if query is a direct RFC number
	if rfcNum := extractRFCNumber(query); rfcNum != "" {
		result, err := c.fetchRFCByNumber(ctx, rfcNum)
		if err != nil {
			return nil, err
		}
		if result != nil {
			return []RFCResult{*result}, nil
		}
	}

	// Otherwise, search by keywords
	return c.searchRFCByKeywords(ctx, query, limit)
}

// fetchRFCByNumber fetches a specific RFC by number
func (c *WebSearchClient) fetchRFCByNumber(ctx context.Context, number string) (*RFCResult, error) {
	url := fmt.Sprintf(ietfDirectURL, number)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 IETF API 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("RFC %s 不存在", number)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IETF API 返回错误: %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	var doc ietfDocResponse
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	return &RFCResult{
		Number:   number,
		Title:    doc.Title,
		Pages:    doc.Pages,
		Abstract: truncateString(doc.Abstract, MaxAbstractLen),
		FullText: fmt.Sprintf(rfcTextURL, number),
	}, nil
}

// searchRFCByKeywords searches RFCs by keywords
func (c *WebSearchClient) searchRFCByKeywords(ctx context.Context, query string, limit int) ([]RFCResult, error) {
	searchURL := fmt.Sprintf(ietfSearchURL, url.QueryEscape(query), limit)

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 IETF API 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IETF API 返回错误: %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	var searchResp ietfSearchResponse
	if err := json.Unmarshal(body, &searchResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	results := make([]RFCResult, 0, len(searchResp.Objects))
	for _, doc := range searchResp.Objects {
		// Extract RFC number from name (e.g., "rfc793" -> "793")
		rfcNum := strings.TrimPrefix(strings.ToLower(doc.Name), "rfc")
		if rfcNum == "" || rfcNum == doc.Name {
			continue
		}

		results = append(results, RFCResult{
			Number:   rfcNum,
			Title:    doc.Title,
			Pages:    doc.Pages,
			Abstract: truncateString(doc.Abstract, MaxAbstractLen),
			FullText: fmt.Sprintf(rfcTextURL, rfcNum),
		})
	}

	return results, nil
}

// SearchDocs searches for technical documentation using DuckDuckGo
func (c *WebSearchClient) SearchDocs(ctx context.Context, query string, limit int) ([]DocResult, error) {
	if limit <= 0 || limit > MaxWebSearchResults {
		limit = DefaultWebResults
	}

	// Add technical context to improve results
	searchQuery := query
	if !strings.Contains(strings.ToLower(query), "network") &&
		!strings.Contains(strings.ToLower(query), "protocol") &&
		!strings.Contains(strings.ToLower(query), "tcp") &&
		!strings.Contains(strings.ToLower(query), "http") {
		// Don't add context if already technical
	}

	// Try Instant Answer API first
	results, err := c.searchDDGInstant(ctx, searchQuery, limit)
	if err == nil && len(results) > 0 {
		return results, nil
	}

	// Fallback to HTML parsing if Instant Answer returns empty
	return c.searchDDGHTML(ctx, searchQuery, limit)
}

// searchDDGInstant uses DuckDuckGo Instant Answer API
func (c *WebSearchClient) searchDDGInstant(ctx context.Context, query string, limit int) ([]DocResult, error) {
	searchURL := fmt.Sprintf(ddgInstantAPI, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "pktanalyzer/1.0 (network packet analyzer)")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 DuckDuckGo API 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DuckDuckGo API 返回错误: %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	var ddgResp ddgInstantResponse
	if err := json.Unmarshal(body, &ddgResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	results := make([]DocResult, 0, limit)

	// Add main abstract if available
	if ddgResp.AbstractText != "" && ddgResp.AbstractURL != "" {
		results = append(results, DocResult{
			Title:   ddgResp.Heading,
			Snippet: truncateString(ddgResp.AbstractText, MaxSnippetLen),
			URL:     ddgResp.AbstractURL,
		})
	}

	// Add related topics
	for _, topic := range ddgResp.RelatedTopics {
		if len(results) >= limit {
			break
		}
		if topic.Text != "" && topic.FirstURL != "" {
			// Extract title from text (usually first sentence or phrase)
			title := topic.Text
			if idx := strings.Index(title, " - "); idx > 0 && idx < 100 {
				title = title[:idx]
			}
			results = append(results, DocResult{
				Title:   truncateString(title, 100),
				Snippet: truncateString(topic.Text, MaxSnippetLen),
				URL:     topic.FirstURL,
			})
		}
	}

	// Add direct results
	for _, result := range ddgResp.Results {
		if len(results) >= limit {
			break
		}
		if result.Text != "" && result.FirstURL != "" {
			results = append(results, DocResult{
				Title:   truncateString(result.Text, 100),
				Snippet: truncateString(result.Text, MaxSnippetLen),
				URL:     result.FirstURL,
			})
		}
	}

	return results, nil
}

// searchDDGHTML parses DuckDuckGo HTML results as fallback
func (c *WebSearchClient) searchDDGHTML(ctx context.Context, query string, limit int) ([]DocResult, error) {
	searchURL := fmt.Sprintf(ddgHTMLSearch, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "pktanalyzer/1.0 (network packet analyzer)")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 DuckDuckGo 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DuckDuckGo 返回错误: %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	// Parse HTML results with simple regex (avoid heavy HTML parsing dependency)
	return parseHTMLResults(string(body), limit), nil
}

// parseHTMLResults extracts search results from DuckDuckGo HTML
func parseHTMLResults(html string, limit int) []DocResult {
	results := make([]DocResult, 0, limit)

	// Pattern to match result links and snippets
	// DuckDuckGo HTML structure: <a class="result__a" href="...">title</a>
	// and <a class="result__snippet" ...>snippet</a>
	resultPattern := regexp.MustCompile(`<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>([^<]+)</a>`)
	snippetPattern := regexp.MustCompile(`<a[^>]*class="result__snippet"[^>]*>([^<]+)</a>`)

	resultMatches := resultPattern.FindAllStringSubmatch(html, limit*2)
	snippetMatches := snippetPattern.FindAllStringSubmatch(html, limit*2)

	for i := 0; i < len(resultMatches) && len(results) < limit; i++ {
		if len(resultMatches[i]) < 3 {
			continue
		}

		rawURL := resultMatches[i][1]
		title := strings.TrimSpace(resultMatches[i][2])

		// DuckDuckGo uses redirect URLs, extract actual URL
		actualURL := extractActualURL(rawURL)
		if actualURL == "" {
			continue
		}

		snippet := ""
		if i < len(snippetMatches) && len(snippetMatches[i]) > 1 {
			snippet = strings.TrimSpace(snippetMatches[i][1])
		}

		results = append(results, DocResult{
			Title:   truncateString(title, 100),
			Snippet: truncateString(snippet, MaxSnippetLen),
			URL:     actualURL,
		})
	}

	return results
}

// extractActualURL extracts the actual URL from DuckDuckGo redirect URL
func extractActualURL(ddgURL string) string {
	// DuckDuckGo format: //duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com
	if strings.Contains(ddgURL, "uddg=") {
		if u, err := url.Parse(ddgURL); err == nil {
			if uddg := u.Query().Get("uddg"); uddg != "" {
				return uddg
			}
		}
	}

	// Sometimes it's a direct URL
	if strings.HasPrefix(ddgURL, "http") {
		return ddgURL
	}

	return ""
}

// FormatRFCResults formats RFC results for display
func FormatRFCResults(results []RFCResult) string {
	if len(results) == 0 {
		return "未找到匹配的 RFC 文档"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("找到 %d 个 RFC 文档:\n\n", len(results)))

	for i, r := range results {
		sb.WriteString(fmt.Sprintf("--- RFC %s ---\n", r.Number))
		sb.WriteString(fmt.Sprintf("标题: %s\n", r.Title))
		if r.Pages > 0 {
			sb.WriteString(fmt.Sprintf("页数: %d\n", r.Pages))
		}
		if r.Abstract != "" {
			sb.WriteString(fmt.Sprintf("摘要: %s\n", r.Abstract))
		}
		sb.WriteString(fmt.Sprintf("全文: %s\n", r.FullText))
		if i < len(results)-1 {
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// FormatDocResults formats documentation results for display
func FormatDocResults(results []DocResult, query string) string {
	if len(results) == 0 {
		return fmt.Sprintf("未找到关于 \"%s\" 的文档", query)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("找到 %d 个关于 \"%s\" 的结果:\n\n", len(results), query))

	for i, r := range results {
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, r.Title))
		if r.Snippet != "" {
			sb.WriteString(fmt.Sprintf("   %s\n", r.Snippet))
		}
		sb.WriteString(fmt.Sprintf("   URL: %s\n", r.URL))
		if i < len(results)-1 {
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// WebSearch performs a web search and fetches content from top results.
// This follows the DeepAgent pattern: search → auto-fetch content.
// Instead of just returning URLs, it returns actual page content.
func (c *WebSearchClient) WebSearch(ctx context.Context, query string, maxResults int, maxCharsPerResult int) (string, error) {
	if maxResults <= 0 || maxResults > 3 {
		maxResults = 1 // Default to 1 result for efficiency
	}
	if maxCharsPerResult <= 0 || maxCharsPerResult > MaxURLContentChars {
		maxCharsPerResult = 4000 // Smaller default for multi-result fetches
	}

	// Search using DuckDuckGo
	results, err := c.SearchDocs(ctx, query, maxResults)
	if err != nil {
		return "", fmt.Errorf("搜索失败: %w", err)
	}

	if len(results) == 0 {
		return fmt.Sprintf("未找到关于 \"%s\" 的搜索结果", query), nil
	}

	// Fetch content from each result URL (similar to DeepAgent's tavily_search)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🔍 搜索 \"%s\" 找到 %d 个结果:\n\n", query, len(results)))

	for i, result := range results {
		sb.WriteString(fmt.Sprintf("## %d. %s\n", i+1, result.Title))
		sb.WriteString(fmt.Sprintf("**URL:** %s\n\n", result.URL))

		// Fetch full content
		content, err := c.FetchURL(ctx, result.URL, maxCharsPerResult)
		if err != nil {
			sb.WriteString(fmt.Sprintf("⚠️ 无法获取内容: %s\n\n", err.Error()))
		} else {
			// Remove the header we add in FetchURL since we already have one
			content = strings.TrimPrefix(content, fmt.Sprintf("=== %s ===\n\n", result.URL))
			sb.WriteString(content)
			sb.WriteString("\n\n")
		}
		sb.WriteString("---\n\n")
	}

	return sb.String(), nil
}

// ReadRFC reads the full content of an RFC document
func (c *WebSearchClient) ReadRFC(ctx context.Context, rfcNumber string, section string, maxChars int) (string, error) {
	if maxChars <= 0 || maxChars > MaxRFCContentChars {
		maxChars = DefaultContentChars
	}

	// Validate RFC number (should be digits only)
	rfcNumber = strings.TrimSpace(rfcNumber)
	if !regexp.MustCompile(`^\d+$`).MatchString(rfcNumber) {
		// Try to extract number from "rfc793" format
		if num := extractRFCNumber(rfcNumber); num != "" {
			rfcNumber = num
		} else {
			return "", fmt.Errorf("无效的 RFC 编号: %s", rfcNumber)
		}
	}

	// Fetch RFC full text
	rfcURL := fmt.Sprintf(rfcTextURL, rfcNumber)
	content, err := c.fetchTextContent(ctx, rfcURL)
	if err != nil {
		return "", fmt.Errorf("获取 RFC %s 失败: %w", rfcNumber, err)
	}

	// If section specified, extract that section
	if section != "" {
		content = extractRFCSection(content, section)
		if content == "" {
			return "", fmt.Errorf("未找到 RFC %s 的第 %s 节", rfcNumber, section)
		}
	}

	// Truncate with context
	content = truncateWithContext(content, maxChars)

	// Format output
	var sb strings.Builder
	if section != "" {
		sb.WriteString(fmt.Sprintf("=== RFC %s Section %s ===\n\n", rfcNumber, section))
	} else {
		sb.WriteString(fmt.Sprintf("=== RFC %s ===\n\n", rfcNumber))
	}
	sb.WriteString(content)

	return sb.String(), nil
}

// FetchURL fetches content from a URL and converts HTML to readable text
func (c *WebSearchClient) FetchURL(ctx context.Context, targetURL string, maxChars int) (string, error) {
	if maxChars <= 0 || maxChars > MaxURLContentChars {
		maxChars = DefaultContentChars
	}

	// Validate URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("无效的 URL: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("仅支持 http/https 协议")
	}

	// Create request with timeout
	fetchCtx, cancel := context.WithTimeout(ctx, FetchTimeout*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, "GET", targetURL, nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; pktanalyzer/1.0; network packet analyzer)")
	req.Header.Set("Accept", "text/html,text/plain,application/xhtml+xml")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP 错误: %s", resp.Status)
	}

	// Read body with limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxFetchBody))
	if err != nil {
		return "", fmt.Errorf("读取内容失败: %w", err)
	}

	content := string(body)

	// Determine content type and process accordingly
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/plain") {
		// Plain text, use as is
		content = truncateWithContext(content, maxChars)
	} else {
		// Assume HTML, convert to markdown
		content = htmlToMarkdown(content)
		content = truncateWithContext(content, maxChars)
	}

	// Format output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== %s ===\n\n", targetURL))
	sb.WriteString(content)

	return sb.String(), nil
}

// fetchTextContent fetches plain text content from a URL
func (c *WebSearchClient) fetchTextContent(ctx context.Context, targetURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "pktanalyzer/1.0 (network packet analyzer)")
	req.Header.Set("Accept", "text/plain")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("文档不存在 (404)")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP 错误: %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxFetchBody))
	if err != nil {
		return "", fmt.Errorf("读取内容失败: %w", err)
	}

	return string(body), nil
}

// extractRFCSection extracts a specific section from RFC text
func extractRFCSection(content string, section string) string {
	lines := strings.Split(content, "\n")

	// Build section pattern: "3." or "3.1" or "3.1.2" at start of line
	// RFC sections typically start with the number followed by period and space
	sectionPrefix := section + "."
	sectionPattern := regexp.MustCompile(`^` + regexp.QuoteMeta(section) + `\.?\s+\S`)

	var result strings.Builder
	inSection := false
	sectionDepth := strings.Count(section, ".") + 1 // e.g., "3.1" has depth 2

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check if we're starting the target section
		if !inSection && sectionPattern.MatchString(trimmed) {
			inSection = true
			result.WriteString(line + "\n")
			continue
		}

		if inSection {
			// Check if we've hit the next section at same or higher level
			// Look for patterns like "4." or "3.2" when in section "3.1"
			if isNextSection(trimmed, sectionPrefix, sectionDepth) {
				break
			}
			result.WriteString(line + "\n")
		}
	}

	return strings.TrimSpace(result.String())
}

// isNextSection checks if a line marks the start of the next section
func isNextSection(line string, currentPrefix string, currentDepth int) bool {
	// Match section numbers at line start
	sectionNumPattern := regexp.MustCompile(`^(\d+(?:\.\d+)*)\.\s+\S`)
	matches := sectionNumPattern.FindStringSubmatch(line)
	if len(matches) < 2 {
		return false
	}

	sectionNum := matches[1]
	depth := strings.Count(sectionNum, ".") + 1

	// If same depth or shallower, it's a new section
	if depth <= currentDepth {
		// Make sure it's not a subsection of current
		if !strings.HasPrefix(sectionNum+".", currentPrefix) {
			return true
		}
	}

	return false
}

// truncateWithContext truncates content while preserving context
func truncateWithContext(content string, maxChars int) string {
	if len(content) <= maxChars {
		return content
	}

	// Find a good break point (end of paragraph or sentence)
	truncated := content[:maxChars]

	// Calculate safe break thresholds (ensure they're not negative)
	paraThreshold := maxChars - 500
	if paraThreshold < 0 {
		paraThreshold = 0
	}
	lineThreshold := maxChars - 200
	if lineThreshold < 0 {
		lineThreshold = 0
	}
	sentThreshold := maxChars - 100
	if sentThreshold < 0 {
		sentThreshold = 0
	}

	// Try to break at paragraph
	if lastPara := strings.LastIndex(truncated, "\n\n"); lastPara > paraThreshold {
		truncated = truncated[:lastPara]
	} else if lastNewline := strings.LastIndex(truncated, "\n"); lastNewline > lineThreshold {
		// Break at line
		truncated = truncated[:lastNewline]
	} else if lastPeriod := strings.LastIndex(truncated, ". "); lastPeriod > sentThreshold {
		// Break at sentence
		truncated = truncated[:lastPeriod+1]
	}

	return truncated + "\n\n... [内容已截断，共 " + fmt.Sprintf("%d", len(content)) + " 字符]"
}

// htmlToMarkdown converts HTML to markdown-like plain text
func htmlToMarkdown(html string) string {
	// Remove script and style tags with content
	scriptPattern := regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	html = scriptPattern.ReplaceAllString(html, "")

	stylePattern := regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	html = stylePattern.ReplaceAllString(html, "")

	// Remove HTML comments
	commentPattern := regexp.MustCompile(`(?s)<!--.*?-->`)
	html = commentPattern.ReplaceAllString(html, "")

	// Convert headers
	for i := 6; i >= 1; i-- {
		headerPattern := regexp.MustCompile(fmt.Sprintf(`(?is)<h%d[^>]*>(.*?)</h%d>`, i, i))
		prefix := strings.Repeat("#", i) + " "
		html = headerPattern.ReplaceAllStringFunc(html, func(match string) string {
			inner := headerPattern.FindStringSubmatch(match)
			if len(inner) > 1 {
				return "\n" + prefix + stripTags(inner[1]) + "\n"
			}
			return match
		})
	}

	// Convert paragraphs
	pPattern := regexp.MustCompile(`(?is)<p[^>]*>(.*?)</p>`)
	html = pPattern.ReplaceAllStringFunc(html, func(match string) string {
		inner := pPattern.FindStringSubmatch(match)
		if len(inner) > 1 {
			return "\n" + stripTags(inner[1]) + "\n"
		}
		return match
	})

	// Convert line breaks
	brPattern := regexp.MustCompile(`(?i)<br\s*/?>`)
	html = brPattern.ReplaceAllString(html, "\n")

	// Convert links: <a href="url">text</a> -> [text](url)
	linkPattern := regexp.MustCompile(`(?is)<a[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>`)
	html = linkPattern.ReplaceAllStringFunc(html, func(match string) string {
		matches := linkPattern.FindStringSubmatch(match)
		if len(matches) > 2 {
			text := stripTags(matches[2])
			url := matches[1]
			if text != "" {
				return fmt.Sprintf("[%s](%s)", text, url)
			}
		}
		return match
	})

	// Convert code blocks
	prePattern := regexp.MustCompile(`(?is)<pre[^>]*>(.*?)</pre>`)
	html = prePattern.ReplaceAllStringFunc(html, func(match string) string {
		inner := prePattern.FindStringSubmatch(match)
		if len(inner) > 1 {
			return "\n```\n" + stripTags(inner[1]) + "\n```\n"
		}
		return match
	})

	// Convert inline code
	codePattern := regexp.MustCompile(`(?is)<code[^>]*>(.*?)</code>`)
	html = codePattern.ReplaceAllStringFunc(html, func(match string) string {
		inner := codePattern.FindStringSubmatch(match)
		if len(inner) > 1 {
			return "`" + stripTags(inner[1]) + "`"
		}
		return match
	})

	// Convert list items
	liPattern := regexp.MustCompile(`(?is)<li[^>]*>(.*?)</li>`)
	html = liPattern.ReplaceAllStringFunc(html, func(match string) string {
		inner := liPattern.FindStringSubmatch(match)
		if len(inner) > 1 {
			return "- " + stripTags(inner[1]) + "\n"
		}
		return match
	})

	// Convert blockquotes
	bqPattern := regexp.MustCompile(`(?is)<blockquote[^>]*>(.*?)</blockquote>`)
	html = bqPattern.ReplaceAllStringFunc(html, func(match string) string {
		inner := bqPattern.FindStringSubmatch(match)
		if len(inner) > 1 {
			lines := strings.Split(stripTags(inner[1]), "\n")
			var result []string
			for _, line := range lines {
				result = append(result, "> "+strings.TrimSpace(line))
			}
			return strings.Join(result, "\n") + "\n"
		}
		return match
	})

	// Convert bold and strong
	boldPattern := regexp.MustCompile(`(?is)<(b|strong)[^>]*>(.*?)</(b|strong)>`)
	html = boldPattern.ReplaceAllStringFunc(html, func(match string) string {
		inner := boldPattern.FindStringSubmatch(match)
		if len(inner) > 2 {
			return "**" + stripTags(inner[2]) + "**"
		}
		return match
	})

	// Convert italic and em
	italicPattern := regexp.MustCompile(`(?is)<(i|em)[^>]*>(.*?)</(i|em)>`)
	html = italicPattern.ReplaceAllStringFunc(html, func(match string) string {
		inner := italicPattern.FindStringSubmatch(match)
		if len(inner) > 2 {
			return "*" + stripTags(inner[2]) + "*"
		}
		return match
	})

	// Remove remaining tags
	html = stripTags(html)

	// Decode common HTML entities
	html = decodeHTMLEntities(html)

	// Clean up whitespace
	// Multiple spaces to single space
	multiSpace := regexp.MustCompile(`[ \t]+`)
	html = multiSpace.ReplaceAllString(html, " ")

	// Multiple newlines to double newline
	multiNewline := regexp.MustCompile(`\n{3,}`)
	html = multiNewline.ReplaceAllString(html, "\n\n")

	// Trim lines
	lines := strings.Split(html, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	html = strings.Join(lines, "\n")

	return strings.TrimSpace(html)
}

// stripTags removes all HTML tags from a string
func stripTags(html string) string {
	tagPattern := regexp.MustCompile(`<[^>]*>`)
	return tagPattern.ReplaceAllString(html, "")
}

// decodeHTMLEntities decodes common HTML entities
func decodeHTMLEntities(s string) string {
	entities := map[string]string{
		"&nbsp;":   " ",
		"&amp;":    "&",
		"&lt;":     "<",
		"&gt;":     ">",
		"&quot;":   "\"",
		"&apos;":   "'",
		"&#39;":    "'",
		"&ndash;":  "–",
		"&mdash;":  "—",
		"&lsquo;":  "'",
		"&rsquo;":  "'",
		"&ldquo;":  "\u201c",
		"&rdquo;":  "\u201d",
		"&bull;":   "•",
		"&hellip;": "...",
		"&copy;":   "©",
		"&reg;":    "®",
		"&trade;":  "™",
	}

	for entity, replacement := range entities {
		s = strings.ReplaceAll(s, entity, replacement)
	}

	// Decode numeric entities like &#123;
	numericPattern := regexp.MustCompile(`&#(\d+);`)
	s = numericPattern.ReplaceAllStringFunc(s, func(match string) string {
		matches := numericPattern.FindStringSubmatch(match)
		if len(matches) > 1 {
			var num int
			fmt.Sscanf(matches[1], "%d", &num)
			if num > 0 && num < 65536 {
				return string(rune(num))
			}
		}
		return match
	})

	return s
}
