// Package openai provides OpenAI API client (also used as base for compatible APIs)
package openai

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
	DefaultBaseURL = "https://api.openai.com/v1"
	DefaultModel   = "gpt-4.1-mini"
)

// Client implements llm.Client for OpenAI and compatible APIs
type Client struct {
	config     *llm.Config
	httpClient *http.Client
	provider   llm.Provider
}

// New creates a new OpenAI client
func New(cfg *llm.Config) (*Client, error) {
	if cfg == nil {
		cfg = llm.DefaultConfig()
	}

	// Get API key from config or environment
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("OPENAI_API_KEY not set")
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
		provider: llm.ProviderOpenAI,
	}, nil
}

// NewWithProvider creates a client with custom provider type (for OpenRouter, Ollama, etc.)
func NewWithProvider(cfg *llm.Config, provider llm.Provider) (*Client, error) {
	client, err := newClientInternal(cfg)
	if err != nil {
		return nil, err
	}
	client.provider = provider
	return client, nil
}

func newClientInternal(cfg *llm.Config) (*Client, error) {
	if cfg == nil {
		cfg = llm.DefaultConfig()
	}

	if cfg.APIKey == "" {
		return nil, fmt.Errorf("API key not set")
	}

	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}

	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}, nil
}

func (c *Client) Provider() llm.Provider {
	return c.provider
}

func (c *Client) ModelID() string {
	return c.config.Model
}

func (c *Client) Chat(ctx context.Context, req *llm.ChatRequest) (*llm.ChatResponse, error) {
	// Convert to OpenAI format
	openaiReq := c.buildRequest(req)

	body, err := json.Marshal(openaiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.config.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.config.APIKey)

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

	var openaiResp openaiResponse
	if err := json.Unmarshal(respBody, &openaiResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return c.parseResponse(&openaiResp)
}

// ChatStream implements streaming chat with OpenAI API
func (c *Client) ChatStream(ctx context.Context, req *llm.ChatRequest) (<-chan llm.StreamEvent, error) {
	// Convert to OpenAI format with stream enabled
	openaiReq := c.buildRequest(req)

	// Build streaming request body
	streamReq := struct {
		*openaiRequest
		Stream bool `json:"stream"`
	}{
		openaiRequest: openaiReq,
		Stream:        true,
	}

	body, err := json.Marshal(streamReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.config.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.config.APIKey)

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

// openaiStreamChunk represents a streaming response chunk from OpenAI
type openaiStreamChunk struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Role      string           `json:"role,omitempty"`
			Content   string           `json:"content,omitempty"`
			ToolCalls []openaiToolCall `json:"tool_calls,omitempty"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason,omitempty"`
	} `json:"choices"`
}

// processSSEStream processes Server-Sent Events from OpenAI API
func (c *Client) processSSEStream(ctx context.Context, body io.ReadCloser, eventChan chan<- llm.StreamEvent) {
	defer close(eventChan)
	defer body.Close()

	scanner := bufio.NewScanner(body)
	// Increase buffer size for large events
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	// Track tool call state (OpenAI sends incremental updates)
	toolCalls := make(map[int]*llm.ToolCall)
	toolArgsBuilders := make(map[int]*strings.Builder)
	var lastFinishReason string

	eventChan <- llm.StreamEvent{Type: llm.StreamEventStart}

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			eventChan <- llm.StreamEvent{Type: llm.StreamEventError, Error: ctx.Err()}
			return
		default:
		}

		line := scanner.Text()

		// OpenAI SSE format: "data: <json>" or "data: [DONE]"
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			// Finalize any pending tool calls
			for idx, tc := range toolCalls {
				if builder, ok := toolArgsBuilders[idx]; ok {
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
					ToolIndex: idx,
				}
			}
			eventChan <- llm.StreamEvent{
				Type:       llm.StreamEventEnd,
				StopReason: lastFinishReason,
			}
			return
		}

		var chunk openaiStreamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue // Skip malformed chunks
		}

		if len(chunk.Choices) == 0 {
			continue
		}

		choice := chunk.Choices[0]

		// Handle content delta
		if choice.Delta.Content != "" {
			eventChan <- llm.StreamEvent{
				Type:  llm.StreamEventDelta,
				Delta: choice.Delta.Content,
			}
		}

		// Handle tool calls (OpenAI sends them incrementally)
		for _, tc := range choice.Delta.ToolCalls {
			idx := tc.Index

			// Check if this is a new tool call
			if _, exists := toolCalls[idx]; !exists {
				toolCalls[idx] = &llm.ToolCall{
					ID:        tc.ID,
					Name:      tc.Function.Name,
					Arguments: make(map[string]any),
				}
				toolArgsBuilders[idx] = &strings.Builder{}

				// Send tool start event
				eventChan <- llm.StreamEvent{
					Type:      llm.StreamEventToolStart,
					ToolCall:  toolCalls[idx],
					ToolIndex: idx,
				}
			}

			// Update tool call ID and name if provided
			if tc.ID != "" {
				toolCalls[idx].ID = tc.ID
			}
			if tc.Function.Name != "" {
				toolCalls[idx].Name = tc.Function.Name
			}

			// Accumulate arguments
			if tc.Function.Arguments != "" {
				toolArgsBuilders[idx].WriteString(tc.Function.Arguments)
				eventChan <- llm.StreamEvent{
					Type:      llm.StreamEventToolDelta,
					Delta:     tc.Function.Arguments,
					ToolIndex: idx,
				}
			}
		}

		// Record finish reason (don't send end event yet, wait for [DONE])
		if choice.FinishReason != "" {
			lastFinishReason = choice.FinishReason
		}
	}

	// If we exit the loop without [DONE], still send end event
	if err := scanner.Err(); err != nil {
		eventChan <- llm.StreamEvent{Type: llm.StreamEventError, Error: err}
	} else {
		// Stream ended without [DONE] - this can happen with some providers
		// Finalize any pending tool calls
		for idx, tc := range toolCalls {
			if builder, ok := toolArgsBuilders[idx]; ok {
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
				ToolIndex: idx,
			}
		}
		eventChan <- llm.StreamEvent{
			Type:       llm.StreamEventEnd,
			StopReason: lastFinishReason,
		}
	}
}

// OpenAI API types
type openaiRequest struct {
	Model       string          `json:"model"`
	Messages    []openaiMessage `json:"messages"`
	Tools       []openaiTool    `json:"tools,omitempty"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature float64         `json:"temperature,omitempty"`
}

type openaiMessage struct {
	Role       string           `json:"role"`
	Content    string           `json:"content,omitempty"`
	ToolCalls  []openaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openaiTool struct {
	Type     string         `json:"type"`
	Function openaiFunction `json:"function"`
}

type openaiFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type openaiToolCall struct {
	Index    int    `json:"index,omitempty"` // Used in streaming responses
	ID       string `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`
	Function struct {
		Name      string `json:"name,omitempty"`
		Arguments string `json:"arguments,omitempty"`
	} `json:"function"`
}

type openaiResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role      string           `json:"role"`
			Content   string           `json:"content"`
			ToolCalls []openaiToolCall `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

func (c *Client) buildRequest(req *llm.ChatRequest) *openaiRequest {
	model := req.Model
	if model == "" {
		model = c.config.Model
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	openaiReq := &openaiRequest{
		Model:     model,
		MaxTokens: maxTokens,
	}

	if req.Temperature > 0 {
		openaiReq.Temperature = req.Temperature
	}

	// Convert messages
	for _, msg := range req.Messages {
		om := openaiMessage{Role: string(msg.Role)}

		if msg.Role == llm.RoleTool && msg.ToolResult != nil {
			// Tool result message
			om.Role = "tool"
			om.Content = msg.ToolResult.Content
			om.ToolCallID = msg.ToolResult.ToolCallID
		} else if len(msg.ToolCalls) > 0 {
			// Assistant message with tool calls
			om.Content = msg.Content
			for _, tc := range msg.ToolCalls {
				argsJSON, _ := json.Marshal(tc.Arguments)
				om.ToolCalls = append(om.ToolCalls, openaiToolCall{
					ID:   tc.ID,
					Type: "function",
					Function: struct {
						Name      string `json:"name,omitempty"`
						Arguments string `json:"arguments,omitempty"`
					}{
						Name:      tc.Name,
						Arguments: string(argsJSON),
					},
				})
			}
		} else {
			om.Content = msg.Content
		}

		openaiReq.Messages = append(openaiReq.Messages, om)
	}

	// Convert tools
	for _, t := range req.Tools {
		openaiReq.Tools = append(openaiReq.Tools, openaiTool{
			Type: "function",
			Function: openaiFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Parameters,
			},
		})
	}

	return openaiReq
}

func (c *Client) parseResponse(resp *openaiResponse) (*llm.ChatResponse, error) {
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	choice := resp.Choices[0]
	result := &llm.ChatResponse{
		Content:    choice.Message.Content,
		StopReason: choice.FinishReason,
		Usage: &llm.Usage{
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		},
	}

	// Parse tool calls
	for _, tc := range choice.Message.ToolCalls {
		var args map[string]any
		json.Unmarshal([]byte(tc.Function.Arguments), &args)
		result.ToolCalls = append(result.ToolCalls, llm.ToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: args,
		})
	}

	return result, nil
}
