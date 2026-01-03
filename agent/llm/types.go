// Package llm provides unified abstractions for LLM providers
package llm

import (
	"context"
	"time"
)

// Provider represents different LLM providers
type Provider string

const (
	ProviderClaude     Provider = "claude"
	ProviderOpenAI     Provider = "openai"
	ProviderOpenRouter Provider = "openrouter"
	ProviderOllama     Provider = "ollama"
)

// Message represents a unified chat message
type Message struct {
	Role       Role        // system/user/assistant/tool
	Content    string      // text content
	ToolCalls  []ToolCall  // assistant -> tool calls (when Role=assistant)
	ToolResult *ToolResult // tool execution result (when Role=tool)
}

// Role represents message roles
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

// Tool represents a tool/function definition
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"` // JSON Schema
}

// ToolCall represents a tool invocation request from the model
type ToolCall struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// ToolResult represents the result of a tool execution
type ToolResult struct {
	ToolCallID string `json:"tool_call_id"`
	Content    string `json:"content"`
	IsError    bool   `json:"is_error,omitempty"`
}

// ChatRequest represents a unified chat request
type ChatRequest struct {
	Model       string    // model identifier
	Messages    []Message // conversation history
	Tools       []Tool    // available tools
	MaxTokens   int       // max tokens to generate
	Temperature float64   // sampling temperature (0-1)
}

// ChatResponse represents a unified chat response
type ChatResponse struct {
	Content    string     // text content from assistant
	ToolCalls  []ToolCall // tool calls requested by assistant
	StopReason string     // why the model stopped (end_turn, tool_use, max_tokens, etc.)
	Usage      *Usage     // token usage (optional)
}

// Usage represents token usage statistics
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
}

// StreamEventType represents the type of streaming event
type StreamEventType string

const (
	StreamEventStart     StreamEventType = "start"      // Stream started
	StreamEventDelta     StreamEventType = "delta"      // Content delta (text chunk)
	StreamEventToolStart StreamEventType = "tool_start" // Tool call started
	StreamEventToolDelta StreamEventType = "tool_delta" // Tool call arguments delta
	StreamEventToolEnd   StreamEventType = "tool_end"   // Tool call completed
	StreamEventEnd       StreamEventType = "end"        // Stream ended
	StreamEventError     StreamEventType = "error"      // Error occurred
)

// StreamEvent represents a streaming event from the LLM
type StreamEvent struct {
	Type       StreamEventType // Event type
	Delta      string          // Text delta (for delta events)
	ToolCall   *ToolCall       // Tool call info (for tool events)
	ToolIndex  int             // Index of tool call being updated
	StopReason string          // Stop reason (for end events)
	Error      error           // Error (for error events)
}

// Client is the unified interface for all LLM providers
type Client interface {
	// Chat sends a chat request and returns the response
	Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error)

	// ChatStream sends a chat request and returns a stream of events
	ChatStream(ctx context.Context, req *ChatRequest) (<-chan StreamEvent, error)

	// Provider returns the provider type
	Provider() Provider

	// ModelID returns the current model identifier
	ModelID() string
}

// Config holds common configuration for LLM clients
type Config struct {
	APIKey      string            // API key for authentication
	BaseURL     string            // Base URL for API requests
	Model       string            // Model identifier
	Timeout     time.Duration     // Request timeout
	MaxRetries  int               // Max retry attempts
	ExtraHeader map[string]string // Extra HTTP headers
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		Timeout:    120 * time.Second,
		MaxRetries: 2,
	}
}
