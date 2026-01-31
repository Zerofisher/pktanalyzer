// Package openai provides OpenAI API client using the official SDK
package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/packages/ssestream"

	"github.com/Zerofisher/pktanalyzer/agent/llm"
)

const (
	DefaultBaseURL = "https://api.openai.com/v1"
	DefaultModel   = "gpt-5.1"
)

// Client implements llm.Client for OpenAI and compatible APIs
type Client struct {
	config   *llm.Config
	sdk      openai.Client
	provider llm.Provider
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

	sdk := openai.NewClient(opts...)

	return &Client{
		config:   cfg,
		sdk:      sdk,
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

	// Build SDK options
	opts := []option.RequestOption{
		option.WithAPIKey(cfg.APIKey),
	}

	if cfg.BaseURL != DefaultBaseURL {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}

	for k, v := range cfg.ExtraHeader {
		opts = append(opts, option.WithHeader(k, v))
	}

	sdk := openai.NewClient(opts...)

	return &Client{
		config: cfg,
		sdk:    sdk,
	}, nil
}

func (c *Client) Provider() llm.Provider {
	return c.provider
}

func (c *Client) ModelID() string {
	return c.config.Model
}

func (c *Client) Chat(ctx context.Context, req *llm.ChatRequest) (*llm.ChatResponse, error) {
	params := c.buildParams(req)

	completion, err := c.sdk.Chat.Completions.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("chat completion failed: %w", err)
	}

	return c.parseResponse(completion)
}

// ChatStream implements streaming chat with OpenAI API
func (c *Client) ChatStream(ctx context.Context, req *llm.ChatRequest) (<-chan llm.StreamEvent, error) {
	params := c.buildParams(req)

	stream := c.sdk.Chat.Completions.NewStreaming(ctx, params)

	eventChan := make(chan llm.StreamEvent, 100)

	go c.processStream(ctx, stream, eventChan)

	return eventChan, nil
}

func (c *Client) buildParams(req *llm.ChatRequest) openai.ChatCompletionNewParams {
	model := req.Model
	if model == "" {
		model = c.config.Model
	}

	params := openai.ChatCompletionNewParams{
		Model: model,
	}

	// Set max tokens (SDK handles max_tokens vs max_completion_tokens automatically)
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}
	params.MaxCompletionTokens = openai.Int(int64(maxTokens))

	if req.Temperature > 0 {
		params.Temperature = openai.Float(req.Temperature)
	}

	// Convert messages
	for _, msg := range req.Messages {
		params.Messages = append(params.Messages, c.convertMessage(msg))
	}

	// Convert tools
	for _, t := range req.Tools {
		params.Tools = append(params.Tools, openai.ChatCompletionToolUnionParam{
			OfFunction: &openai.ChatCompletionFunctionToolParam{
				Function: openai.FunctionDefinitionParam{
					Name:        t.Name,
					Description: openai.String(t.Description),
					Parameters:  openai.FunctionParameters(t.Parameters),
				},
			},
		})
	}

	return params
}

func (c *Client) convertMessage(msg llm.Message) openai.ChatCompletionMessageParamUnion {
	switch msg.Role {
	case llm.RoleSystem:
		return openai.SystemMessage(msg.Content)
	case llm.RoleUser:
		return openai.UserMessage(msg.Content)
	case llm.RoleAssistant:
		if len(msg.ToolCalls) > 0 {
			// Assistant message with tool calls
			var toolCalls []openai.ChatCompletionMessageToolCallUnionParam
			for _, tc := range msg.ToolCalls {
				argsJSON, _ := json.Marshal(tc.Arguments)
				toolCalls = append(toolCalls, openai.ChatCompletionMessageToolCallUnionParam{
					OfFunction: &openai.ChatCompletionMessageFunctionToolCallParam{
						ID: tc.ID,
						Function: openai.ChatCompletionMessageFunctionToolCallFunctionParam{
							Name:      tc.Name,
							Arguments: string(argsJSON),
						},
					},
				})
			}
			return openai.ChatCompletionMessageParamUnion{
				OfAssistant: &openai.ChatCompletionAssistantMessageParam{
					Content:   openai.ChatCompletionAssistantMessageParamContentUnion{OfString: openai.String(msg.Content)},
					ToolCalls: toolCalls,
				},
			}
		}
		return openai.AssistantMessage(msg.Content)
	case llm.RoleTool:
		if msg.ToolResult != nil {
			return openai.ToolMessage(msg.ToolResult.Content, msg.ToolResult.ToolCallID)
		}
		return openai.ToolMessage(msg.Content, "")
	default:
		return openai.UserMessage(msg.Content)
	}
}

func (c *Client) parseResponse(resp *openai.ChatCompletion) (*llm.ChatResponse, error) {
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	choice := resp.Choices[0]
	result := &llm.ChatResponse{
		Content:    choice.Message.Content,
		StopReason: string(choice.FinishReason),
		Usage: &llm.Usage{
			PromptTokens:     int(resp.Usage.PromptTokens),
			CompletionTokens: int(resp.Usage.CompletionTokens),
			TotalTokens:      int(resp.Usage.TotalTokens),
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

func (c *Client) processStream(ctx context.Context, stream *ssestream.Stream[openai.ChatCompletionChunk], eventChan chan<- llm.StreamEvent) {
	defer close(eventChan)

	acc := openai.ChatCompletionAccumulator{}
	eventChan <- llm.StreamEvent{Type: llm.StreamEventStart}

	toolCallsSent := make(map[int]bool)

	for stream.Next() {
		select {
		case <-ctx.Done():
			eventChan <- llm.StreamEvent{Type: llm.StreamEventError, Error: ctx.Err()}
			return
		default:
		}

		chunk := stream.Current()
		acc.AddChunk(chunk)

		// Handle content delta
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			eventChan <- llm.StreamEvent{
				Type:  llm.StreamEventDelta,
				Delta: chunk.Choices[0].Delta.Content,
			}
		}

		// Handle tool calls
		if len(chunk.Choices) > 0 {
			for _, tc := range chunk.Choices[0].Delta.ToolCalls {
				idx := int(tc.Index)

				// Send tool start event if this is a new tool call
				if !toolCallsSent[idx] && tc.Function.Name != "" {
					toolCallsSent[idx] = true
					eventChan <- llm.StreamEvent{
						Type: llm.StreamEventToolStart,
						ToolCall: &llm.ToolCall{
							ID:   tc.ID,
							Name: tc.Function.Name,
						},
						ToolIndex: idx,
					}
				}

				// Send tool delta for arguments
				if tc.Function.Arguments != "" {
					eventChan <- llm.StreamEvent{
						Type:      llm.StreamEventToolDelta,
						Delta:     tc.Function.Arguments,
						ToolIndex: idx,
					}
				}
			}
		}

		// Detect finished tool calls using accumulator
		if tool, ok := acc.JustFinishedToolCall(); ok {
			var args map[string]any
			json.Unmarshal([]byte(tool.Arguments), &args)
			eventChan <- llm.StreamEvent{
				Type: llm.StreamEventToolEnd,
				ToolCall: &llm.ToolCall{
					ID:        tool.ID,
					Name:      tool.Name,
					Arguments: args,
				},
				ToolIndex: int(tool.Index),
			}
		}
	}

	if err := stream.Err(); err != nil {
		eventChan <- llm.StreamEvent{Type: llm.StreamEventError, Error: err}
		return
	}

	// Send end event with stop reason
	stopReason := ""
	if len(acc.Choices) > 0 {
		stopReason = string(acc.Choices[0].FinishReason)
	}
	eventChan <- llm.StreamEvent{
		Type:       llm.StreamEventEnd,
		StopReason: stopReason,
	}
}
