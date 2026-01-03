// Package claude provides Anthropic Claude API client
package claude

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Zerofisher/pktanalyzer/agent/llm"
)

const (
	DefaultBaseURL = "https://api.anthropic.com/v1"
	DefaultModel   = "claude-sonnet-4-20250514"
	APIVersion     = "2023-06-01"
)

// Client implements llm.Client for Anthropic Claude
type Client struct {
	config     *llm.Config
	httpClient *http.Client
}

// New creates a new Claude client
func New(cfg *llm.Config) (*Client, error) {
	if cfg == nil {
		cfg = llm.DefaultConfig()
	}

	// Get API key from config or environment
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}
	cfg.APIKey = apiKey

	// Set defaults
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.Model == "" {
		cfg.Model = os.Getenv("AI_MODEL")
		if cfg.Model == "" {
			cfg.Model = DefaultModel
		}
	}

	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}, nil
}

func (c *Client) Provider() llm.Provider {
	return llm.ProviderClaude
}

func (c *Client) ModelID() string {
	return c.config.Model
}

func (c *Client) Chat(ctx context.Context, req *llm.ChatRequest) (*llm.ChatResponse, error) {
	// Convert to Claude format
	claudeReq := c.buildRequest(req)

	body, err := json.Marshal(claudeReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.config.BaseURL+"/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.config.APIKey)
	httpReq.Header.Set("anthropic-version", APIVersion)

	// Add extra headers
	for k, v := range c.config.ExtraHeader {
		httpReq.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var claudeResp claudeResponse
	if err := json.Unmarshal(respBody, &claudeResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return c.parseResponse(&claudeResp), nil
}

// ChatStream implements streaming chat with Claude API
func (c *Client) ChatStream(ctx context.Context, req *llm.ChatRequest) (<-chan llm.StreamEvent, error) {
	// Convert to Claude format with stream enabled
	claudeReq := c.buildRequest(req)

	// Build streaming request body
	streamReq := struct {
		*claudeRequest
		Stream bool `json:"stream"`
	}{
		claudeRequest: claudeReq,
		Stream:        true,
	}

	body, err := json.Marshal(streamReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.config.BaseURL+"/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.config.APIKey)
	httpReq.Header.Set("anthropic-version", APIVersion)

	// Add extra headers
	for k, v := range c.config.ExtraHeader {
		httpReq.Header.Set(k, v)
	}

	// Don't use the default client with timeout for streaming
	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	eventChan := make(chan llm.StreamEvent, 100)

	go c.processSSEStream(ctx, resp.Body, eventChan)

	return eventChan, nil
}

// processSSEStream processes Server-Sent Events from Claude API
func (c *Client) processSSEStream(ctx context.Context, body io.ReadCloser, eventChan chan<- llm.StreamEvent) {
	defer close(eventChan)
	defer body.Close()

	scanner := bufio.NewScanner(body)
	// Increase buffer size for large events
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var currentEvent string
	var currentData strings.Builder

	// Track tool call state
	toolCalls := make(map[int]*llm.ToolCall)
	toolInputBuilders := make(map[int]*strings.Builder)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			eventChan <- llm.StreamEvent{Type: llm.StreamEventError, Error: ctx.Err()}
			return
		default:
		}

		line := scanner.Text()

		// SSE format: "event: <type>\ndata: <json>\n\n"
		if strings.HasPrefix(line, "event: ") {
			currentEvent = strings.TrimPrefix(line, "event: ")
			continue
		}

		if strings.HasPrefix(line, "data: ") {
			currentData.WriteString(strings.TrimPrefix(line, "data: "))
			continue
		}

		// Empty line means end of event
		if line == "" && currentData.Len() > 0 {
			c.handleSSEEvent(currentEvent, currentData.String(), eventChan, toolCalls, toolInputBuilders)
			currentEvent = ""
			currentData.Reset()
		}
	}

	if err := scanner.Err(); err != nil {
		eventChan <- llm.StreamEvent{Type: llm.StreamEventError, Error: err}
	}
}

// handleSSEEvent processes a single SSE event
func (c *Client) handleSSEEvent(eventType, data string, eventChan chan<- llm.StreamEvent,
	toolCalls map[int]*llm.ToolCall, toolInputBuilders map[int]*strings.Builder) {

	switch eventType {
	case "message_start":
		eventChan <- llm.StreamEvent{Type: llm.StreamEventStart}

	case "content_block_start":
		var event struct {
			Index        int `json:"index"`
			ContentBlock struct {
				Type  string `json:"type"`
				ID    string `json:"id,omitempty"`
				Name  string `json:"name,omitempty"`
				Input any    `json:"input,omitempty"`
			} `json:"content_block"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return
		}

		if event.ContentBlock.Type == "tool_use" {
			tc := &llm.ToolCall{
				ID:        event.ContentBlock.ID,
				Name:      event.ContentBlock.Name,
				Arguments: make(map[string]any),
			}
			toolCalls[event.Index] = tc
			toolInputBuilders[event.Index] = &strings.Builder{}

			eventChan <- llm.StreamEvent{
				Type:      llm.StreamEventToolStart,
				ToolCall:  tc,
				ToolIndex: event.Index,
			}
		}

	case "content_block_delta":
		var event struct {
			Index int `json:"index"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text,omitempty"`
				PartialJSON string `json:"partial_json,omitempty"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return
		}

		if event.Delta.Type == "text_delta" && event.Delta.Text != "" {
			eventChan <- llm.StreamEvent{
				Type:  llm.StreamEventDelta,
				Delta: event.Delta.Text,
			}
		} else if event.Delta.Type == "input_json_delta" && event.Delta.PartialJSON != "" {
			// Accumulate partial JSON for tool input
			if builder, ok := toolInputBuilders[event.Index]; ok {
				builder.WriteString(event.Delta.PartialJSON)
				eventChan <- llm.StreamEvent{
					Type:      llm.StreamEventToolDelta,
					Delta:     event.Delta.PartialJSON,
					ToolIndex: event.Index,
				}
			}
		}

	case "content_block_stop":
		var event struct {
			Index int `json:"index"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return
		}

		// Parse complete tool input JSON
		if tc, ok := toolCalls[event.Index]; ok {
			if builder, ok := toolInputBuilders[event.Index]; ok {
				jsonStr := builder.String()
				if jsonStr != "" {
					var args map[string]any
					if err := json.Unmarshal([]byte(jsonStr), &args); err == nil {
						tc.Arguments = args
					}
				}
			}
			eventChan <- llm.StreamEvent{
				Type:      llm.StreamEventToolEnd,
				ToolCall:  tc,
				ToolIndex: event.Index,
			}
		}

	case "message_delta":
		var event struct {
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return
		}
		// Don't send end event here, wait for message_stop

	case "message_stop":
		eventChan <- llm.StreamEvent{Type: llm.StreamEventEnd}

	case "error":
		var event struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			eventChan <- llm.StreamEvent{
				Type:  llm.StreamEventError,
				Error: fmt.Errorf("API error: %s", data),
			}
			return
		}
		eventChan <- llm.StreamEvent{
			Type:  llm.StreamEventError,
			Error: fmt.Errorf("%s: %s", event.Error.Type, event.Error.Message),
		}
	}
}

// Claude API types
type claudeRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	System    string          `json:"system,omitempty"`
	Messages  []claudeMessage `json:"messages"`
	Tools     []claudeTool    `json:"tools,omitempty"`
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // string or []claudeContentBlock
}

type claudeContentBlock struct {
	Type      string         `json:"type"`
	Text      string         `json:"text,omitempty"`
	ID        string         `json:"id,omitempty"`
	Name      string         `json:"name,omitempty"`
	Input     map[string]any `json:"input,omitempty"`
	ToolUseID string         `json:"tool_use_id,omitempty"`
	Content   string         `json:"content,omitempty"`
}

type claudeTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

type claudeResponse struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Role    string `json:"role"`
	Content []struct {
		Type  string         `json:"type"`
		Text  string         `json:"text,omitempty"`
		ID    string         `json:"id,omitempty"`
		Name  string         `json:"name,omitempty"`
		Input map[string]any `json:"input,omitempty"`
	} `json:"content"`
	Model        string `json:"model"`
	StopReason   string `json:"stop_reason"`
	StopSequence string `json:"stop_sequence"`
	Usage        struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func (c *Client) buildRequest(req *llm.ChatRequest) *claudeRequest {
	model := req.Model
	if model == "" {
		model = c.config.Model
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	claudeReq := &claudeRequest{
		Model:     model,
		MaxTokens: maxTokens,
	}

	// Extract system message and convert messages
	for _, msg := range req.Messages {
		if msg.Role == llm.RoleSystem {
			claudeReq.System = msg.Content
			continue
		}

		cm := claudeMessage{Role: string(msg.Role)}

		if msg.Role == llm.RoleTool && msg.ToolResult != nil {
			// Tool result message
			cm.Role = "user" // Claude expects tool results from user role
			cm.Content = []claudeContentBlock{
				{
					Type:      "tool_result",
					ToolUseID: msg.ToolResult.ToolCallID,
					Content:   msg.ToolResult.Content,
				},
			}
		} else if len(msg.ToolCalls) > 0 {
			// Assistant message with tool calls
			blocks := []claudeContentBlock{}
			if msg.Content != "" {
				blocks = append(blocks, claudeContentBlock{
					Type: "text",
					Text: msg.Content,
				})
			}
			for _, tc := range msg.ToolCalls {
				blocks = append(blocks, claudeContentBlock{
					Type:  "tool_use",
					ID:    tc.ID,
					Name:  tc.Name,
					Input: tc.Arguments,
				})
			}
			cm.Content = blocks
		} else {
			cm.Content = msg.Content
		}

		claudeReq.Messages = append(claudeReq.Messages, cm)
	}

	// Convert tools
	for _, t := range req.Tools {
		claudeReq.Tools = append(claudeReq.Tools, claudeTool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.Parameters,
		})
	}

	return claudeReq
}

func (c *Client) parseResponse(resp *claudeResponse) *llm.ChatResponse {
	result := &llm.ChatResponse{
		StopReason: resp.StopReason,
		Usage: &llm.Usage{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.InputTokens + resp.Usage.OutputTokens,
		},
	}

	var textParts []string
	for _, content := range resp.Content {
		switch content.Type {
		case "text":
			textParts = append(textParts, content.Text)
		case "tool_use":
			result.ToolCalls = append(result.ToolCalls, llm.ToolCall{
				ID:        content.ID,
				Name:      content.Name,
				Arguments: content.Input,
			})
		}
	}
	result.Content = strings.Join(textParts, "\n")

	return result
}
