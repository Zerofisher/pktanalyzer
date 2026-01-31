package agent

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"sync"

	"github.com/Zerofisher/pktanalyzer/agent/llm"
	"github.com/Zerofisher/pktanalyzer/agent/providers/claude"
	"github.com/Zerofisher/pktanalyzer/agent/providers/ollama"
	"github.com/Zerofisher/pktanalyzer/agent/providers/openai"
	"github.com/Zerofisher/pktanalyzer/agent/providers/openrouter"
	"github.com/Zerofisher/pktanalyzer/agent/react"
	"github.com/Zerofisher/pktanalyzer/agent/tracing"
	"github.com/Zerofisher/pktanalyzer/capture"
)

//go:embed prompts/system.md
var systemPrompt string

// Agent is the AI agent that can interact with users and execute tools
type Agent struct {
	reactAgent   *react.Agent
	llmClient    llm.Client
	toolExecutor *ToolExecutor
	isProcessing bool
	processingMu sync.Mutex
}

// NewAgent creates a new AI agent
func NewAgent(provider llm.Provider) (*Agent, error) {
	// Initialize tracing (runtime detection of LANGFUSE_* env vars)
	if err := tracing.Init(context.Background()); err != nil {
		// Log warning but don't block startup
		log.Printf("Warning: tracing init failed: %v", err)
	}

	client, err := NewLLMClient(provider)
	if err != nil {
		return nil, err
	}

	// Wrap client with tracing (noop if not enabled)
	client = tracing.WrapClient(client)

	toolExecutor := NewToolExecutor()

	// Convert tools to llm.Tool format
	tools := GetTools()

	// Create ReAct agent with traced tool executor
	policy := react.DefaultPolicy()
	executor := tracing.WrapToolExecutor(&toolExecutorAdapter{toolExecutor})
	reactAgent := react.NewAgent(client, tools, executor, policy)

	// Set system prompt
	reactAgent.SetSystemPrompt(getSystemPrompt())

	return &Agent{
		reactAgent:   reactAgent,
		llmClient:    client,
		toolExecutor: toolExecutor,
	}, nil
}

// SetCapturer sets the packet capturer for the agent
func (a *Agent) SetCapturer(c *capture.Capturer) {
	a.toolExecutor.SetCapturer(c)
}

// SetPacketReader sets the packet data source for the agent.
// This should be called after creating the agent to provide packet access.
func (a *Agent) SetPacketReader(reader PacketReader) {
	a.toolExecutor.SetPacketReader(reader)
}

// GetPacketCount returns the number of packets available
func (a *Agent) GetPacketCount() int {
	return a.toolExecutor.GetPacketCount()
}

// Chat sends a message to the AI and returns the response
func (a *Agent) Chat(userMessage string) (string, error) {
	a.processingMu.Lock()
	a.isProcessing = true
	a.processingMu.Unlock()

	defer func() {
		a.processingMu.Lock()
		a.isProcessing = false
		a.processingMu.Unlock()
	}()

	// P0-2: Store user input for raw data authorization checks
	a.toolExecutor.SetLastUserInput(userMessage)

	ctx := context.Background()
	return a.reactAgent.Chat(ctx, userMessage)
}

// StreamEvent re-exports react.StreamEvent for external use
type StreamEvent = react.StreamEvent

// ChatStream sends a message and returns a stream of response events
func (a *Agent) ChatStream(userMessage string) (<-chan StreamEvent, error) {
	a.processingMu.Lock()
	a.isProcessing = true
	a.processingMu.Unlock()

	// P0-2: Store user input for raw data authorization checks
	a.toolExecutor.SetLastUserInput(userMessage)

	ctx := context.Background()
	eventChan, err := a.reactAgent.ChatStream(ctx, userMessage)
	if err != nil {
		a.processingMu.Lock()
		a.isProcessing = false
		a.processingMu.Unlock()
		return nil, err
	}

	// Wrap channel to handle completion
	wrappedChan := make(chan StreamEvent, 100)
	go func() {
		defer close(wrappedChan)
		defer func() {
			a.processingMu.Lock()
			a.isProcessing = false
			a.processingMu.Unlock()
		}()

		for event := range eventChan {
			wrappedChan <- event
		}
	}()

	return wrappedChan, nil
}

// IsProcessing returns whether the agent is currently processing
func (a *Agent) IsProcessing() bool {
	a.processingMu.Lock()
	defer a.processingMu.Unlock()
	return a.isProcessing
}

// GetMessages returns the conversation history
func (a *Agent) GetMessages() []llm.Message {
	return a.reactAgent.GetMessages()
}

// ClearHistory clears the conversation history
func (a *Agent) ClearHistory() {
	a.reactAgent.ClearHistory()
}

// GetProvider returns the LLM provider being used
func (a *Agent) GetProvider() llm.Provider {
	return a.reactAgent.Provider()
}

// Close gracefully shuts down the agent, flushing any pending traces.
// Should be called before application exit.
func (a *Agent) Close() error {
	return tracing.Shutdown(context.Background())
}

// --- Authorization methods for TUI interaction ---

// HasPendingConfirmation returns true if there's a pending confirmation request
func (a *Agent) HasPendingConfirmation() bool {
	return a.toolExecutor.HasPendingConfirmation()
}

// GetPendingConfirmation returns the current pending confirmation request
func (a *Agent) GetPendingConfirmation() *ConfirmationRequest {
	return a.toolExecutor.GetPendingConfirmation()
}

// GrantAuthorization grants the pending authorization
// forSession: if true, remember this grant for the entire session
func (a *Agent) GrantAuthorization(forSession bool) {
	a.toolExecutor.GrantRawDataAuthorization(forSession)
}

// DenyAuthorization denies the pending authorization
func (a *Agent) DenyAuthorization() {
	a.toolExecutor.DenyRawDataAuthorization()
}

// ClearPendingAuthorization clears the pending authorization without responding
func (a *Agent) ClearPendingAuthorization() {
	a.toolExecutor.ClearPendingAuthorization()
}

// RetryLastToolCall retries the last tool call that required confirmation
// Returns the result of the retried tool call
func (a *Agent) RetryLastToolCall() (string, error) {
	req := a.toolExecutor.GetPendingConfirmation()
	if req == nil || !req.Responded || !req.Granted {
		return "", fmt.Errorf("no granted authorization to retry")
	}

	// Get the original tool input from context
	toolInput, ok := req.Context["tool_input"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid tool input in authorization context")
	}

	// Clear the pending request before retrying
	a.toolExecutor.ClearPendingAuthorization()

	// Execute the tool again
	return a.toolExecutor.ExecuteTool(req.ToolName, toolInput)
}

// NewLLMClient creates a new LLM client for the specified provider
func NewLLMClient(provider llm.Provider) (llm.Client, error) {
	cfg := llm.ConfigFromEnv(provider)

	switch provider {
	case llm.ProviderClaude:
		return claude.New(cfg)
	case llm.ProviderOpenAI:
		return openai.New(cfg)
	case llm.ProviderOpenRouter:
		return openrouter.New(cfg)
	case llm.ProviderOllama:
		return ollama.New(cfg)
	default:
		// Auto-detect
		detected := llm.DetectProvider()
		if detected == "" {
			return nil, fmt.Errorf("no LLM provider configured. Set one of: ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, or OLLAMA_BASE_URL")
		}
		return NewLLMClient(detected)
	}
}

// DetectProvider detects available LLM provider from environment
func DetectProvider() llm.Provider {
	return llm.DetectProvider()
}

// toolExecutorAdapter adapts ToolExecutor to react.ToolExecutor interface
type toolExecutorAdapter struct {
	executor *ToolExecutor
}

func (a *toolExecutorAdapter) Execute(ctx context.Context, name string, args map[string]any) (string, error) {
	return a.executor.ExecuteTool(name, args)
}

// getSystemPrompt returns the system prompt for the agent.
// The prompt is loaded from agent/prompts/system.md via go:embed.
func getSystemPrompt() string {
	return systemPrompt
}
