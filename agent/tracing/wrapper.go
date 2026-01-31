package tracing

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/Zerofisher/pktanalyzer/agent/llm"
)

// TracedClient wraps an llm.Client to add OpenTelemetry tracing.
// It creates spans for Chat and ChatStream operations with GenAI semantic conventions.
type TracedClient struct {
	client llm.Client
}

// WrapClient wraps an LLM client with tracing.
// If tracing is not enabled, returns the original client unchanged.
func WrapClient(client llm.Client) llm.Client {
	if !isEnabled {
		return client
	}
	return &TracedClient{client: client}
}

// Chat implements llm.Client.Chat with tracing.
func (c *TracedClient) Chat(ctx context.Context, req *llm.ChatRequest) (*llm.ChatResponse, error) {
	ctx, span := Tracer().Start(ctx, "llm.chat",
		trace.WithSpanKind(trace.SpanKindClient),
	)
	defer span.End()

	// Set GenAI semantic convention attributes
	span.SetAttributes(
		attribute.String("gen_ai.system", string(c.client.Provider())),
		attribute.String("gen_ai.request.model", c.client.ModelID()),
		attribute.String("gen_ai.operation.name", "chat"),
		attribute.Int("gen_ai.request.message_count", len(req.Messages)),
	)

	// Set input preview (sanitized) - find last user message for Langfuse compatibility
	var inputPreview string
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == llm.RoleUser && req.Messages[i].Content != "" {
			inputPreview = Truncate(req.Messages[i].Content, 500)
			break
		}
	}
	if inputPreview != "" {
		span.SetAttributes(
			attribute.String("gen_ai.prompt", inputPreview),
			attribute.String("input", inputPreview),
		)
	}

	// Execute request
	resp, err := c.client.Chat(ctx, req)

	if err != nil {
		span.RecordError(sanitizedError(err))
		span.SetStatus(codes.Error, SanitizeUTF8(err.Error()))
		return nil, err
	}

	// Set output and token usage - use gen_ai.completion for Langfuse compatibility
	outputPreview := Truncate(resp.Content, 500)
	span.SetAttributes(
		attribute.String("gen_ai.completion", outputPreview),
		attribute.String("output", outputPreview), // Langfuse fallback
		attribute.Int("gen_ai.response.tool_calls", len(resp.ToolCalls)),
	)

	if resp.Usage != nil {
		span.SetAttributes(
			attribute.Int("gen_ai.usage.input_tokens", resp.Usage.PromptTokens),
			attribute.Int("gen_ai.usage.output_tokens", resp.Usage.CompletionTokens),
		)
	}

	span.SetStatus(codes.Ok, "")
	return resp, nil
}

// ChatStream implements llm.Client.ChatStream with tracing.
func (c *TracedClient) ChatStream(ctx context.Context, req *llm.ChatRequest) (<-chan llm.StreamEvent, error) {
	ctx, span := Tracer().Start(ctx, "llm.chat_stream",
		trace.WithSpanKind(trace.SpanKindClient),
	)

	span.SetAttributes(
		attribute.String("gen_ai.system", string(c.client.Provider())),
		attribute.String("gen_ai.request.model", c.client.ModelID()),
		attribute.String("gen_ai.operation.name", "chat_stream"),
		attribute.Int("gen_ai.request.message_count", len(req.Messages)),
	)

	// Set input preview for Langfuse compatibility - find last user message
	var inputPreview string
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == llm.RoleUser && req.Messages[i].Content != "" {
			inputPreview = Truncate(req.Messages[i].Content, 500)
			break
		}
	}
	if inputPreview != "" {
		span.SetAttributes(
			attribute.String("gen_ai.prompt", inputPreview),
			attribute.String("input", inputPreview),
		)
	}

	eventChan, err := c.client.ChatStream(ctx, req)
	if err != nil {
		span.RecordError(sanitizedError(err))
		span.SetStatus(codes.Error, SanitizeUTF8(err.Error()))
		span.End()
		return nil, err
	}

	// Wrap channel to end span when streaming completes
	wrappedChan := make(chan llm.StreamEvent, 100)
	go func() {
		defer close(wrappedChan)

		var contentBuilder strings.Builder
		var toolCalls []string

		for event := range eventChan {
			wrappedChan <- event

			switch event.Type {
			case llm.StreamEventDelta:
				contentBuilder.WriteString(event.Delta)
			case llm.StreamEventToolStart, llm.StreamEventToolEnd:
				if event.ToolCall != nil {
					toolCalls = append(toolCalls, event.ToolCall.Name)
				}
			case llm.StreamEventError:
				if event.Error != nil {
					span.RecordError(sanitizedError(event.Error))
					span.SetStatus(codes.Error, SanitizeUTF8(event.Error.Error()))
				}
			}
		}

		// Build output preview - include both text content and tool calls
		var outputPreview string
		textContent := contentBuilder.String()
		if textContent != "" {
			outputPreview = Truncate(textContent, 500)
		} else if len(toolCalls) > 0 {
			outputPreview = fmt.Sprintf("[Tool calls: %s]", strings.Join(toolCalls, ", "))
		}

		if outputPreview != "" {
			span.SetAttributes(
				attribute.String("gen_ai.completion", outputPreview),
				attribute.String("output", outputPreview),
			)
		}

		span.SetStatus(codes.Ok, "")
		span.End()
	}()

	return wrappedChan, nil
}

// Provider implements llm.Client.Provider.
func (c *TracedClient) Provider() llm.Provider {
	return c.client.Provider()
}

// ModelID implements llm.Client.ModelID.
func (c *TracedClient) ModelID() string {
	return c.client.ModelID()
}

// ToolExecutor is the interface for executing tools.
type ToolExecutor interface {
	Execute(ctx context.Context, name string, args map[string]any) (string, error)
}

// TracedToolExecutor wraps a ToolExecutor to add OpenTelemetry tracing.
type TracedToolExecutor struct {
	executor ToolExecutor
}

// WrapToolExecutor wraps a tool executor with tracing.
// If tracing is not enabled, returns the original executor unchanged.
func WrapToolExecutor(executor ToolExecutor) ToolExecutor {
	if !isEnabled {
		return executor
	}
	return &TracedToolExecutor{executor: executor}
}

// Execute implements ToolExecutor.Execute with tracing.
func (e *TracedToolExecutor) Execute(ctx context.Context, name string, args map[string]any) (string, error) {
	ctx, span := Tracer().Start(ctx, "tool."+name,
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	defer span.End()

	span.SetAttributes(
		attribute.String("gen_ai.tool.name", name),
	)

	// Record input parameters (sanitized) and create input summary
	var inputParts []string
	for k, v := range args {
		if str, ok := v.(string); ok {
			truncated := Truncate(str, 100)
			span.SetAttributes(attribute.String("tool.input."+k, truncated))
			inputParts = append(inputParts, k+"="+truncated)
		} else if num, ok := v.(float64); ok {
			span.SetAttributes(attribute.Float64("tool.input."+k, num))
			inputParts = append(inputParts, fmt.Sprintf("%s=%v", k, num))
		} else if b, ok := v.(bool); ok {
			span.SetAttributes(attribute.Bool("tool.input."+k, b))
			inputParts = append(inputParts, fmt.Sprintf("%s=%v", k, b))
		}
	}
	// Set combined input for Langfuse visibility
	if len(inputParts) > 0 {
		span.SetAttributes(attribute.String("input", strings.Join(inputParts, ", ")))
	}

	result, err := e.executor.Execute(ctx, name, args)

	if err != nil {
		span.RecordError(sanitizedError(err))
		span.SetStatus(codes.Error, SanitizeUTF8(err.Error()))
		return "", err
	}

	outputPreview := Truncate(result, 500)
	span.SetAttributes(
		attribute.String("tool.output_preview", outputPreview),
		attribute.String("output", outputPreview), // Langfuse visibility
		attribute.Int("tool.output_length", len(result)),
	)
	span.SetStatus(codes.Ok, "")

	return result, nil
}

// sanitizedError wraps an error with a sanitized UTF-8 message.
// This ensures RecordError doesn't fail on invalid UTF-8 in error messages.
type sanitizedErr struct {
	original error
	message  string
}

func (e *sanitizedErr) Error() string {
	return e.message
}

func (e *sanitizedErr) Unwrap() error {
	return e.original
}

func sanitizedError(err error) error {
	if err == nil {
		return nil
	}
	return &sanitizedErr{
		original: err,
		message:  SanitizeUTF8(fmt.Sprintf("%v", err)),
	}
}
