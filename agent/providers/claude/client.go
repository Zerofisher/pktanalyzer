// Package claude provides Anthropic Claude API client using the official SDK
package claude

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/packages/ssestream"

	"github.com/Zerofisher/pktanalyzer/agent/llm"
)

const (
	DefaultBaseURL = "https://api.anthropic.com"
	DefaultModel   = "claude-sonnet-4-20250514"
)

// Client implements llm.Client for Anthropic Claude
type Client struct {
	config *llm.Config
	sdk    anthropic.Client
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

	// Build SDK options
	opts := []option.RequestOption{
		option.WithAPIKey(apiKey),
	}

	// Add custom base URL if not default
	if cfg.BaseURL != DefaultBaseURL {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}

	// Add extra headers
	for k, v := range cfg.ExtraHeader {
		opts = append(opts, option.WithHeader(k, v))
	}

	sdk := anthropic.NewClient(opts...)

	return &Client{
		config: cfg,
		sdk:    sdk,
	}, nil
}

func (c *Client) Provider() llm.Provider {
	return llm.ProviderClaude
}

func (c *Client) ModelID() string {
	return c.config.Model
}

func (c *Client) Chat(ctx context.Context, req *llm.ChatRequest) (*llm.ChatResponse, error) {
	params := c.buildParams(req)

	message, err := c.sdk.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("chat message failed: %w", err)
	}

	return c.parseResponse(message), nil
}

// ChatStream implements streaming chat with Claude API
func (c *Client) ChatStream(ctx context.Context, req *llm.ChatRequest) (<-chan llm.StreamEvent, error) {
	params := c.buildParams(req)

	stream := c.sdk.Messages.NewStreaming(ctx, params)

	eventChan := make(chan llm.StreamEvent, 100)

	go c.processStream(ctx, stream, eventChan)

	return eventChan, nil
}

func (c *Client) buildParams(req *llm.ChatRequest) anthropic.MessageNewParams {
	model := req.Model
	if model == "" {
		model = c.config.Model
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: int64(maxTokens),
	}

	// Convert messages
	var systemContent string
	for _, msg := range req.Messages {
		if msg.Role == llm.RoleSystem {
			systemContent = msg.Content
			continue
		}
		params.Messages = append(params.Messages, c.convertMessage(msg))
	}

	// Set system message if present
	if systemContent != "" {
		params.System = []anthropic.TextBlockParam{
			{Text: systemContent},
		}
	}

	// Convert tools
	for _, t := range req.Tools {
		// Convert map[string]any to ToolInputSchemaParam
		inputSchema := anthropic.ToolInputSchemaParam{
			Properties: t.Parameters["properties"],
		}
		if required, ok := t.Parameters["required"].([]any); ok {
			for _, r := range required {
				if s, ok := r.(string); ok {
					inputSchema.Required = append(inputSchema.Required, s)
				}
			}
		}

		params.Tools = append(params.Tools, anthropic.ToolUnionParam{
			OfTool: &anthropic.ToolParam{
				Name:        t.Name,
				Description: anthropic.String(t.Description),
				InputSchema: inputSchema,
			},
		})
	}

	return params
}

func (c *Client) convertMessage(msg llm.Message) anthropic.MessageParam {
	switch msg.Role {
	case llm.RoleUser:
		return anthropic.NewUserMessage(anthropic.NewTextBlock(msg.Content))

	case llm.RoleAssistant:
		if len(msg.ToolCalls) > 0 {
			// Assistant message with tool calls
			var blocks []anthropic.ContentBlockParamUnion
			if msg.Content != "" {
				blocks = append(blocks, anthropic.ContentBlockParamUnion{
					OfText: &anthropic.TextBlockParam{Text: msg.Content},
				})
			}
			for _, tc := range msg.ToolCalls {
				blocks = append(blocks, anthropic.ContentBlockParamUnion{
					OfToolUse: &anthropic.ToolUseBlockParam{
						ID:    tc.ID,
						Name:  tc.Name,
						Input: tc.Arguments,
					},
				})
			}
			return anthropic.MessageParam{
				Role:    anthropic.MessageParamRoleAssistant,
				Content: blocks,
			}
		}
		return anthropic.NewAssistantMessage(anthropic.NewTextBlock(msg.Content))

	case llm.RoleTool:
		if msg.ToolResult != nil {
			return anthropic.NewUserMessage(
				anthropic.NewToolResultBlock(msg.ToolResult.ToolCallID, msg.ToolResult.Content, msg.ToolResult.IsError),
			)
		}
		return anthropic.NewUserMessage(anthropic.NewTextBlock(msg.Content))

	default:
		return anthropic.NewUserMessage(anthropic.NewTextBlock(msg.Content))
	}
}

func (c *Client) parseResponse(msg *anthropic.Message) *llm.ChatResponse {
	result := &llm.ChatResponse{
		StopReason: string(msg.StopReason),
		Usage: &llm.Usage{
			PromptTokens:     int(msg.Usage.InputTokens),
			CompletionTokens: int(msg.Usage.OutputTokens),
			TotalTokens:      int(msg.Usage.InputTokens + msg.Usage.OutputTokens),
		},
	}

	var textParts []string
	for _, block := range msg.Content {
		switch v := block.AsAny().(type) {
		case anthropic.TextBlock:
			textParts = append(textParts, v.Text)
		case anthropic.ToolUseBlock:
			// Convert Input to map[string]any
			var args map[string]any
			if inputBytes, err := json.Marshal(v.Input); err == nil {
				json.Unmarshal(inputBytes, &args)
			}
			result.ToolCalls = append(result.ToolCalls, llm.ToolCall{
				ID:        v.ID,
				Name:      v.Name,
				Arguments: args,
			})
		}
	}

	if len(textParts) > 0 {
		result.Content = textParts[0]
		for i := 1; i < len(textParts); i++ {
			result.Content += "\n" + textParts[i]
		}
	}

	return result
}

func (c *Client) processStream(ctx context.Context, stream *ssestream.Stream[anthropic.MessageStreamEventUnion], eventChan chan<- llm.StreamEvent) {
	defer close(eventChan)

	acc := anthropic.Message{}

	// Track tool call state
	toolCalls := make(map[int]*llm.ToolCall)
	toolInputBuilders := make(map[int]string)

	for stream.Next() {
		select {
		case <-ctx.Done():
			eventChan <- llm.StreamEvent{Type: llm.StreamEventError, Error: ctx.Err()}
			return
		default:
		}

		event := stream.Current()
		if err := acc.Accumulate(event); err != nil {
			eventChan <- llm.StreamEvent{Type: llm.StreamEventError, Error: err}
			return
		}

		switch ev := event.AsAny().(type) {
		case anthropic.MessageStartEvent:
			eventChan <- llm.StreamEvent{Type: llm.StreamEventStart}

		case anthropic.ContentBlockStartEvent:
			if ev.ContentBlock.Type == "tool_use" {
				// Extract tool use info from content block
				if toolUse, ok := ev.ContentBlock.AsAny().(anthropic.ToolUseBlock); ok {
					idx := int(ev.Index)
					tc := &llm.ToolCall{
						ID:        toolUse.ID,
						Name:      toolUse.Name,
						Arguments: make(map[string]any),
					}
					toolCalls[idx] = tc
					toolInputBuilders[idx] = ""

					eventChan <- llm.StreamEvent{
						Type:      llm.StreamEventToolStart,
						ToolCall:  tc,
						ToolIndex: idx,
					}
				}
			}

		case anthropic.ContentBlockDeltaEvent:
			switch delta := ev.Delta.AsAny().(type) {
			case anthropic.TextDelta:
				if delta.Text != "" {
					eventChan <- llm.StreamEvent{
						Type:  llm.StreamEventDelta,
						Delta: delta.Text,
					}
				}
			case anthropic.InputJSONDelta:
				idx := int(ev.Index)
				if delta.PartialJSON != "" {
					toolInputBuilders[idx] += delta.PartialJSON
					eventChan <- llm.StreamEvent{
						Type:      llm.StreamEventToolDelta,
						Delta:     delta.PartialJSON,
						ToolIndex: idx,
					}
				}
			}

		case anthropic.ContentBlockStopEvent:
			idx := int(ev.Index)
			if tc, ok := toolCalls[idx]; ok {
				// Parse complete tool input JSON
				if jsonStr, ok := toolInputBuilders[idx]; ok && jsonStr != "" {
					var args map[string]any
					if err := json.Unmarshal([]byte(jsonStr), &args); err == nil {
						tc.Arguments = args
					}
				}
				eventChan <- llm.StreamEvent{
					Type:      llm.StreamEventToolEnd,
					ToolCall:  tc,
					ToolIndex: idx,
				}
			}

		case anthropic.MessageStopEvent:
			stopReason := ""
			if acc.StopReason != "" {
				stopReason = string(acc.StopReason)
			}
			eventChan <- llm.StreamEvent{
				Type:       llm.StreamEventEnd,
				StopReason: stopReason,
			}
		}
	}

	if err := stream.Err(); err != nil {
		eventChan <- llm.StreamEvent{Type: llm.StreamEventError, Error: err}
	}
}
