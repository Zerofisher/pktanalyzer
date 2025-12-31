// Package react implements ReAct (Reasoning and Acting) agent loop
package react

import (
	"context"
	"fmt"
	"github.com/Zerofisher/pktanalyzer/agent/llm"
	"time"
)

// Policy defines the behavior of the ReAct loop
type Policy struct {
	MaxIterations     int           // Maximum tool call iterations (default 10)
	MaxToolsPerTurn   int           // Maximum tools per single turn (default 5)
	ToolTimeout       time.Duration // Timeout for each tool execution (default 30s)
	ContinueOnError   bool          // Whether to continue if a tool fails (default true)
	TrimOldMessages   bool          // Whether to trim old messages to save context (default false)
	MaxMessagesKept   int           // Max messages to keep when trimming (default 50)
}

// DefaultPolicy returns a sensible default policy
func DefaultPolicy() *Policy {
	return &Policy{
		MaxIterations:   10,
		MaxToolsPerTurn: 5,
		ToolTimeout:     30 * time.Second,
		ContinueOnError: true,
		TrimOldMessages: false,
		MaxMessagesKept: 50,
	}
}

// ToolExecutor executes tools and returns results
type ToolExecutor interface {
	Execute(ctx context.Context, name string, args map[string]any) (string, error)
}

// Agent implements the ReAct loop
type Agent struct {
	client   llm.Client
	tools    []llm.Tool
	executor ToolExecutor
	policy   *Policy
	messages []llm.Message
}

// NewAgent creates a new ReAct agent
func NewAgent(client llm.Client, tools []llm.Tool, executor ToolExecutor, policy *Policy) *Agent {
	if policy == nil {
		policy = DefaultPolicy()
	}
	return &Agent{
		client:   client,
		tools:    tools,
		executor: executor,
		policy:   policy,
		messages: make([]llm.Message, 0),
	}
}

// SetSystemPrompt sets the system prompt
func (a *Agent) SetSystemPrompt(prompt string) {
	// Check if we already have a system message
	if len(a.messages) > 0 && a.messages[0].Role == llm.RoleSystem {
		a.messages[0].Content = prompt
	} else {
		// Insert at beginning
		a.messages = append([]llm.Message{{Role: llm.RoleSystem, Content: prompt}}, a.messages...)
	}
}

// Chat processes a user message and returns the final response
func (a *Agent) Chat(ctx context.Context, userMessage string) (string, error) {
	// Add user message
	a.messages = append(a.messages, llm.Message{
		Role:    llm.RoleUser,
		Content: userMessage,
	})

	// ReAct loop
	for iteration := 0; iteration < a.policy.MaxIterations; iteration++ {
		// Prepare request
		req := &llm.ChatRequest{
			Messages: a.messages,
			Tools:    a.tools,
		}

		// Call LLM
		resp, err := a.client.Chat(ctx, req)
		if err != nil {
			return "", fmt.Errorf("LLM error at iteration %d: %w", iteration, err)
		}

		// No tool calls - we have our final answer
		if len(resp.ToolCalls) == 0 {
			// Add assistant response
			a.messages = append(a.messages, llm.Message{
				Role:    llm.RoleAssistant,
				Content: resp.Content,
			})
			return resp.Content, nil
		}

		// Limit tool calls per turn
		toolCalls := resp.ToolCalls
		if len(toolCalls) > a.policy.MaxToolsPerTurn {
			toolCalls = toolCalls[:a.policy.MaxToolsPerTurn]
		}

		// Add assistant message with tool calls
		a.messages = append(a.messages, llm.Message{
			Role:      llm.RoleAssistant,
			Content:   resp.Content,
			ToolCalls: toolCalls,
		})

		// Execute tools and collect results
		for _, tc := range toolCalls {
			result, err := a.executeToolWithTimeout(ctx, tc)

			isError := err != nil
			content := result
			if isError {
				content = fmt.Sprintf("Error: %v", err)
				if !a.policy.ContinueOnError {
					return "", fmt.Errorf("tool %s failed: %w", tc.Name, err)
				}
			}

			// Add tool result message
			a.messages = append(a.messages, llm.Message{
				Role: llm.RoleTool,
				ToolResult: &llm.ToolResult{
					ToolCallID: tc.ID,
					Content:    content,
					IsError:    isError,
				},
			})
		}

		// Optionally trim old messages
		if a.policy.TrimOldMessages && len(a.messages) > a.policy.MaxMessagesKept {
			a.trimMessages()
		}
	}

	return "", fmt.Errorf("max iterations (%d) reached without final response", a.policy.MaxIterations)
}

func (a *Agent) executeToolWithTimeout(ctx context.Context, tc llm.ToolCall) (string, error) {
	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, a.policy.ToolTimeout)
	defer cancel()

	// Execute in goroutine
	type result struct {
		output string
		err    error
	}
	ch := make(chan result, 1)

	go func() {
		output, err := a.executor.Execute(timeoutCtx, tc.Name, tc.Arguments)
		ch <- result{output, err}
	}()

	select {
	case r := <-ch:
		return r.output, r.err
	case <-timeoutCtx.Done():
		return "", fmt.Errorf("tool execution timed out after %v", a.policy.ToolTimeout)
	}
}

func (a *Agent) trimMessages() {
	// Keep system message + most recent messages
	keep := a.policy.MaxMessagesKept

	if len(a.messages) <= keep {
		return
	}

	// Find system message
	hasSystem := len(a.messages) > 0 && a.messages[0].Role == llm.RoleSystem
	if hasSystem {
		keep-- // Reserve spot for system message
	}

	// Keep recent messages
	startIdx := len(a.messages) - keep
	if hasSystem {
		newMessages := make([]llm.Message, 0, keep+1)
		newMessages = append(newMessages, a.messages[0]) // Keep system
		newMessages = append(newMessages, a.messages[startIdx:]...)
		a.messages = newMessages
	} else {
		a.messages = a.messages[startIdx:]
	}
}

// GetMessages returns the conversation history
func (a *Agent) GetMessages() []llm.Message {
	result := make([]llm.Message, len(a.messages))
	copy(result, a.messages)
	return result
}

// ClearHistory clears conversation history (keeps system prompt if present)
func (a *Agent) ClearHistory() {
	if len(a.messages) > 0 && a.messages[0].Role == llm.RoleSystem {
		a.messages = a.messages[:1] // Keep only system message
	} else {
		a.messages = make([]llm.Message, 0)
	}
}

// Provider returns the underlying LLM provider
func (a *Agent) Provider() llm.Provider {
	return a.client.Provider()
}

// ModelID returns the current model ID
func (a *Agent) ModelID() string {
	return a.client.ModelID()
}

// StreamEvent extends llm.StreamEvent with agent-specific info
type StreamEvent struct {
	llm.StreamEvent
	ToolExecuting bool   // True when a tool is being executed
	ToolName      string // Name of the tool being executed
	Iteration     int    // Current ReAct iteration
}

// ChatStream processes a user message and streams the response
func (a *Agent) ChatStream(ctx context.Context, userMessage string) (<-chan StreamEvent, error) {
	// Add user message
	a.messages = append(a.messages, llm.Message{
		Role:    llm.RoleUser,
		Content: userMessage,
	})

	eventChan := make(chan StreamEvent, 100)

	go a.runStreamLoop(ctx, eventChan)

	return eventChan, nil
}

func (a *Agent) runStreamLoop(ctx context.Context, eventChan chan<- StreamEvent) {
	defer close(eventChan)

	for iteration := 0; iteration < a.policy.MaxIterations; iteration++ {
		// Prepare request
		req := &llm.ChatRequest{
			Messages: a.messages,
			Tools:    a.tools,
		}

		// Call LLM with streaming
		llmEventChan, err := a.client.ChatStream(ctx, req)
		if err != nil {
			eventChan <- StreamEvent{
				StreamEvent: llm.StreamEvent{
					Type:  llm.StreamEventError,
					Error: fmt.Errorf("LLM error at iteration %d: %w", iteration, err),
				},
				Iteration: iteration,
			}
			return
		}

		// Collect response while streaming
		var content string
		var toolCalls []llm.ToolCall
		toolCallMap := make(map[int]*llm.ToolCall)

		for llmEvent := range llmEventChan {
			select {
			case <-ctx.Done():
				eventChan <- StreamEvent{
					StreamEvent: llm.StreamEvent{Type: llm.StreamEventError, Error: ctx.Err()},
					Iteration:   iteration,
				}
				return
			default:
			}

			// Forward event to caller
			eventChan <- StreamEvent{
				StreamEvent: llmEvent,
				Iteration:   iteration,
			}

			// Accumulate response
			switch llmEvent.Type {
			case llm.StreamEventDelta:
				content += llmEvent.Delta

			case llm.StreamEventToolStart:
				if llmEvent.ToolCall != nil {
					tc := *llmEvent.ToolCall
					toolCallMap[llmEvent.ToolIndex] = &tc
				}

			case llm.StreamEventToolEnd:
				if tc, ok := toolCallMap[llmEvent.ToolIndex]; ok {
					// Update with final arguments
					if llmEvent.ToolCall != nil {
						tc.Arguments = llmEvent.ToolCall.Arguments
					}
					toolCalls = append(toolCalls, *tc)
				}

			case llm.StreamEventError:
				return
			}
		}

		// No tool calls - we have our final answer
		if len(toolCalls) == 0 {
			a.messages = append(a.messages, llm.Message{
				Role:    llm.RoleAssistant,
				Content: content,
			})
			return
		}

		// Limit tool calls per turn
		if len(toolCalls) > a.policy.MaxToolsPerTurn {
			toolCalls = toolCalls[:a.policy.MaxToolsPerTurn]
		}

		// Add assistant message with tool calls
		a.messages = append(a.messages, llm.Message{
			Role:      llm.RoleAssistant,
			Content:   content,
			ToolCalls: toolCalls,
		})

		// Execute tools and collect results
		for _, tc := range toolCalls {
			// Notify tool execution start
			eventChan <- StreamEvent{
				StreamEvent: llm.StreamEvent{
					Type:     llm.StreamEventToolStart,
					ToolCall: &tc,
				},
				ToolExecuting: true,
				ToolName:      tc.Name,
				Iteration:     iteration,
			}

			result, err := a.executeToolWithTimeout(ctx, tc)

			isError := err != nil
			resultContent := result
			if isError {
				resultContent = fmt.Sprintf("Error: %v", err)
				if !a.policy.ContinueOnError {
					eventChan <- StreamEvent{
						StreamEvent: llm.StreamEvent{
							Type:  llm.StreamEventError,
							Error: fmt.Errorf("tool %s failed: %w", tc.Name, err),
						},
						Iteration: iteration,
					}
					return
				}
			}

			// Add tool result message
			a.messages = append(a.messages, llm.Message{
				Role: llm.RoleTool,
				ToolResult: &llm.ToolResult{
					ToolCallID: tc.ID,
					Content:    resultContent,
					IsError:    isError,
				},
			})

			// Notify tool execution end with result preview
			eventChan <- StreamEvent{
				StreamEvent: llm.StreamEvent{
					Type:  llm.StreamEventDelta,
					Delta: fmt.Sprintf("\n[Tool %s executed]\n", tc.Name),
				},
				ToolExecuting: false,
				ToolName:      tc.Name,
				Iteration:     iteration,
			}
		}

		// Optionally trim old messages
		if a.policy.TrimOldMessages && len(a.messages) > a.policy.MaxMessagesKept {
			a.trimMessages()
		}
	}

	eventChan <- StreamEvent{
		StreamEvent: llm.StreamEvent{
			Type:  llm.StreamEventError,
			Error: fmt.Errorf("max iterations (%d) reached without final response", a.policy.MaxIterations),
		},
	}
}
