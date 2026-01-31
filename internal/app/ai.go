package app

import (
	"fmt"
	"os"

	"github.com/Zerofisher/pktanalyzer/agent"
	"github.com/Zerofisher/pktanalyzer/agent/llm"
	"github.com/Zerofisher/pktanalyzer/capture"
	uiadapter "github.com/Zerofisher/pktanalyzer/ui/adapter"
)

// AIConfig holds AI agent configuration.
type AIConfig struct {
	Capturer     *capture.Capturer  // Optional: set for live/non-indexed mode
	PacketReader agent.PacketReader // Required: packet reader for queries
}

// SetupAI initializes the AI agent.
// Returns nil (without error) if no API key is found or initialization fails.
// Prints warnings to stderr in those cases.
func SetupAI(cfg AIConfig) uiadapter.AIAssistant {
	provider := llm.DetectProvider()
	if provider == "" {
		fmt.Fprintf(os.Stderr, "Warning: AI enabled but no API key found.\n")
		fmt.Fprintf(os.Stderr, "Set ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, or OLLAMA_BASE_URL.\n")
		return nil
	}

	aiAgent, err := agent.NewAgent(provider)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to initialize AI agent: %v\n", err)
		return nil
	}

	fmt.Printf("AI assistant enabled (using %s). Press 'a' to chat.\n", provider)

	if cfg.Capturer != nil {
		aiAgent.SetCapturer(cfg.Capturer)
	}
	aiAgent.SetPacketReader(cfg.PacketReader)

	return NewAgentAdapter(aiAgent)
}

// AgentAdapter adapts *agent.Agent to uiadapter.AIAssistant interface.
type AgentAdapter struct {
	agent *agent.Agent
}

// NewAgentAdapter creates a new AgentAdapter.
func NewAgentAdapter(a *agent.Agent) *AgentAdapter {
	return &AgentAdapter{agent: a}
}

// ChatStream sends a message and returns a stream of events.
func (a *AgentAdapter) ChatStream(message string) (<-chan uiadapter.StreamEvent, error) {
	eventChan, err := a.agent.ChatStream(message)
	if err != nil {
		return nil, err
	}

	resultChan := make(chan uiadapter.StreamEvent, 100)
	go func() {
		defer close(resultChan)
		for event := range eventChan {
			resultChan <- uiadapter.StreamEvent{
				Type:          string(event.Type),
				Delta:         event.Delta,
				ToolName:      event.ToolName,
				ToolExecuting: event.ToolExecuting,
				Error:         event.Error,
			}
		}
	}()

	return resultChan, nil
}

// IsProcessing returns whether the agent is currently processing.
func (a *AgentAdapter) IsProcessing() bool {
	return a.agent.IsProcessing()
}

// HasPendingConfirmation returns true if there's a pending confirmation request.
func (a *AgentAdapter) HasPendingConfirmation() bool {
	return a.agent.HasPendingConfirmation()
}

// GetPendingConfirmation returns the current pending confirmation request.
func (a *AgentAdapter) GetPendingConfirmation() *uiadapter.ConfirmationRequest {
	req := a.agent.GetPendingConfirmation()
	if req == nil {
		return nil
	}
	return &uiadapter.ConfirmationRequest{
		ToolName:    req.ToolName,
		Description: req.Description,
		Reason:      "",
		Context:     req.Context,
		Responded:   req.Responded,
		Granted:     req.Granted,
	}
}

// GrantAuthorization grants the pending authorization.
func (a *AgentAdapter) GrantAuthorization(forSession bool) {
	a.agent.GrantAuthorization(forSession)
}

// DenyAuthorization denies the pending authorization.
func (a *AgentAdapter) DenyAuthorization() {
	a.agent.DenyAuthorization()
}

// ClearPendingAuthorization clears the pending authorization without responding.
func (a *AgentAdapter) ClearPendingAuthorization() {
	a.agent.ClearPendingAuthorization()
}

// RetryLastToolCall retries the last tool call that required confirmation.
func (a *AgentAdapter) RetryLastToolCall() (string, error) {
	return a.agent.RetryLastToolCall()
}
